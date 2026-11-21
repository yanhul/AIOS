from tests.provider_keys import sign_observation, signed_not_applied_proof
# AIOS-CONTRACT: durable external-effect retry authority
# AIOS-REGRESSION: Prevent ambiguous UNKNOWN effects from retrying without governed authority
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Covers bounded UNKNOWN retry, authority binding, and duplicate-effect prevention
# AIOS-BASELINE: Existing M6 effect/runtime regression suite extended for explicit retry authority

import pytest

from tests.retry_issuers import signed_retry_auth

from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.policy_registry import persist_policy

from core.effect_authority import create_effect, dispatch, issue_retry_authorization, observe, retry_dispatch, unknown
from core.evidence import EvidenceRecord
from core.mutation import TransitionError


def _effect(tmp_path):
    registry = CapabilityRegistry()
    registry.register(Capability("provider-1", "1", "test-fixture", "external_effect", status="ACTIVE"))
    registry.persist(str(tmp_path), "test-fixture")
    policy = persist_policy(str(tmp_path), {"policy_type":"GOVERNING_POLICY","name":"effect-authority-test"})
    contract = {
        "contract_type":"EXECUTION_CONTRACT","task_id":"effect-test","scope":"test",
        "actor":"agent-1","capabilities":["provider-1@1"],"input_digest":"input",
        "allowed_effects":["external_effect"],"evidence_required":["provider_receipt"],
        "max_attempts":2,"terminal_states":["OBSERVED_SUCCESS","OBSERVED_FAILURE","UNKNOWN"],
        "policy_digest":policy,
    }
    persist_contract(str(tmp_path), contract)
    permit = persist_permit(str(tmp_path), contract, "agent-1")
    return create_effect(str(tmp_path), contract_identity(contract), "op-1", "agent-1", permit["permit_id"], "external_effect")

def _evidence(provider="provider-1", run_id="run-1"):
    return EvidenceRecord(
        evidence_id="EV-1",
        level="OBSERVED",
        source_ref="provider://receipt/1",
        claim="provider completed operation",
        run_id=run_id,
        provider=provider,
    ).as_record()


def _observation(effect_id, provider="provider-1", attempt=1):
    return {
        "effect_id": effect_id,
        "attempt_id": f"{effect_id}:attempt:{attempt}",
        "provider": provider,
        "provider_operation_id": "op-1",
        "observation": {"status": "ok"},
    }


def test_effect_transition_is_atomic_and_audited(tmp_path):
    effect = _effect(tmp_path)
    assert effect["state"] == "PLANNED"
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    retry_dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:2", "provider-1", 2, signed_retry_auth(str(tmp_path), effect["effect_id"], "agent-1", 2, "operator:test", "test retry"), not_applied_proof=signed_not_applied_proof(str(tmp_path), effect["effect_id"], "provider-1"))
    done = observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS",
                   sign_observation(effect, _observation(effect["effect_id"], attempt=2)))
    assert done["state"] == "OBSERVED_SUCCESS"
    assert (tmp_path / "events" / ("effect-" + effect["effect_id"] + "-OBSERVED_SUCCESS.json")).exists()


def test_unknown_cannot_return_to_dispatch(tmp_path):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "timeout")
    with pytest.raises(TransitionError):
        dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:2", "provider-1")


def test_terminal_state_requires_verified_attempt_bound_evidence(tmp_path):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1")
    with pytest.raises(ValueError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {})

    with pytest.raises(TransitionError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {
            **_observation(effect["effect_id"]), "attempt_id": "forged-attempt"
        })


def test_observation_provider_must_match_effect(tmp_path):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1")
    with pytest.raises(TransitionError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", _observation(effect["effect_id"], "provider-2"))


def test_tampered_evidence_digest_is_rejected(tmp_path):
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1")
    evidence = _evidence()
    evidence["claim"] = "tampered"
    with pytest.raises(ValueError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {
            **_observation(effect["effect_id"]), "evidence": evidence,
        })


def test_terminal_provider_receipt_is_persisted_immutably(tmp_path):
    import json
    effect = _effect(tmp_path)
    attempt_id = f"{effect['effect_id']}:attempt:1"
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", attempt_id, "provider-1")
    supplied = sign_observation(effect, _observation(effect["effect_id"]))
    done = observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", supplied)
    receipt_id = supplied["authentication"]["receipt_id"]
    receipt_path = tmp_path / "provider_receipts" / (receipt_id + ".json")
    assert receipt_path.is_file()
    persisted = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert persisted["record_type"] == "AIOS_TERMINAL_PROVIDER_RECEIPT"
    assert persisted["effect_id"] == done["effect_id"]
    assert persisted["attempt_id"] == attempt_id
    assert persisted["outcome"] == "OBSERVED_SUCCESS"
    assert persisted["authentication"] == supplied["authentication"]
    assert persisted["evidence"] == done["provider_observation"]["evidence"]



def test_production_dispatch_requires_and_persists_contract_bound_lineage(tmp_path, monkeypatch):
    import json
    effect = _effect(tmp_path)
    monkeypatch.setenv("AIOS_REQUIRE_EXECUTION_LINEAGE", "true")
    attempt_id = f"{effect['effect_id']}:attempt:1"
    with pytest.raises(TransitionError, match="requires execution-substrate lineage"):
        dispatch(str(tmp_path), effect["effect_id"], "agent-1", attempt_id, "provider-1")
    contract = __import__("core.authority", fromlist=["load_contract"]).load_contract(
        str(tmp_path), effect["contract_id"])
    lineage = {
        "policy_revision": contract["policy_digest"],
        "environment_revision": "deployment:prod:sha256:abc",
        "capability_snapshot": {
            "capabilities": contract["capabilities"],
            "policy_digest": contract["policy_digest"],
        },
        "provider_revision": "1",
        "attempt_id": attempt_id,
        "trajectory_id": "trajectory:prod:001",
    }
    from core.execution_lineage import ExecutionLineage
    lineage["lineage_digest"] = ExecutionLineage(**lineage).digest
    dispatched = dispatch(str(tmp_path), effect["effect_id"], "agent-1", attempt_id,
                          "provider-1", lineage=lineage)
    assert dispatched["execution_lineage"]["contract_id"] == effect["contract_id"]
    assert dispatched["execution_lineage"]["permit_id"] == effect["permit_id"]
    assert dispatched["execution_lineage"]["lineage"]["trajectory_id"] == "trajectory:prod:001"
    assert dispatched["execution_lineage"]["binding_digest"]
    persisted = json.loads((tmp_path / "effects" / (effect["effect_id"] + ".json")).read_text())
    assert persisted["execution_lineage"] == dispatched["execution_lineage"]
    from tests.provider_keys import KEYRING
    done = observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS",
                   sign_observation(dispatched, _observation(effect["effect_id"])), provider_keyring=KEYRING)
    assert done["state"] == "OBSERVED_SUCCESS"
    receipt_id = done["provider_observation"]["provider_authentication"]["receipt_id"]
    receipt = json.loads((tmp_path / "provider_receipts" / (receipt_id + ".json")).read_text())
    assert receipt["execution_lineage"] == dispatched["execution_lineage"]


def test_production_dispatch_rejects_lineage_for_wrong_policy(tmp_path, monkeypatch):
    from core.execution_lineage import ExecutionLineage
    effect = _effect(tmp_path)
    monkeypatch.setenv("AIOS_REQUIRE_EXECUTION_LINEAGE", "true")
    attempt_id = f"{effect['effect_id']}:attempt:1"
    lineage = {
        "policy_revision": "policy:forged",
        "environment_revision": "deployment:prod",
        "capability_snapshot": {"capabilities": ["provider-1@1"], "policy_digest": "policy:forged"},
        "provider_revision": "1",
        "attempt_id": attempt_id,
        "trajectory_id": "trajectory:1",
    }
    lineage["lineage_digest"] = ExecutionLineage(**lineage).digest
    with pytest.raises(TransitionError, match="policy_revision"):
        dispatch(str(tmp_path), effect["effect_id"], "agent-1", attempt_id,
                 "provider-1", lineage=lineage)


def test_production_unknown_retry_fails_closed_until_independent_issuer(tmp_path, monkeypatch):
    from core.effect_authority import issue_retry_authorization, retry_dispatch, unknown

    effect = _effect(tmp_path)
    attempt_id = f"{effect['effect_id']}:attempt:1"
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", attempt_id, "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    monkeypatch.setenv("AIOS_REQUIRE_EXECUTION_LINEAGE", "true")

    with pytest.raises(TransitionError, match="independent Ed25519 issuer"):
        issue_retry_authorization(
            str(tmp_path), effect["effect_id"], "agent-1", 2,
            "operator:test", "production retry must remain blocked",
            issuer_secret="test-operator-secret-0001",
        )
    with pytest.raises(TransitionError, match="independent public-key retry issuer"):
        retry_dispatch(
            str(tmp_path), effect["effect_id"], "agent-1",
            f"{effect['effect_id']}:attempt:2", "provider-1", 2,
            retry_authorization="RA-" + "0" * 32,
        )

    import json
    persisted = json.loads((tmp_path / "effects" / (effect["effect_id"] + ".json")).read_text())
    assert persisted["state"] == "UNKNOWN"
    assert persisted["attempt"] == 1