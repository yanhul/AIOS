# AIOS-CONTRACT: durable external-effect retry authority
# AIOS-REGRESSION: Prevent ambiguous UNKNOWN effects from retrying without governed authority
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Covers bounded UNKNOWN retry, authority binding, and duplicate-effect prevention
# AIOS-BASELINE: Existing M6 effect/runtime regression suite extended for explicit retry authority

import pytest

from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.policy_registry import persist_policy

from core.effect_authority import (
    create_effect, dispatch, observe, retry_dispatch, unknown,
    issue_retry_authorization,
)
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

def _evidence(provider="provider-1"):
    return EvidenceRecord(
        evidence_id="EV-1",
        level="OBSERVED",
        source_ref="provider://receipt/1",
        claim="provider completed operation",
        run_id="run-1",
        provider=provider,
    ).as_record()


def _observation(effect_id, provider="provider-1", attempt=1):
    return {
        "attempt_id": f"{effect_id}:attempt:{attempt}",
        "provider": provider,
        "evidence": _evidence(provider),
    }


def test_effect_transition_is_atomic_and_audited(tmp_path, monkeypatch):
    secret = "test-only-authority-secret"
    monkeypatch.setenv("AIOS_AUTHORITY_SECRET", secret)
    effect = _effect(tmp_path)
    assert effect["state"] == "PLANNED"
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    authorization = issue_retry_authorization(
        str(tmp_path), effect["effect_id"], "agent-1", 2, secret
    )
    retry_dispatch(str(tmp_path), effect["effect_id"], "agent-1",
                   f"{effect['effect_id']}:attempt:2", "provider-1", 2, authorization)
    done = observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", _observation(effect["effect_id"], attempt=2))
    assert done["state"] == "OBSERVED_SUCCESS"
    assert (tmp_path / "events" / ("effect-" + effect["effect_id"] + "-OBSERVED_SUCCESS.json")).exists()


def test_dispatch_rejects_actor_mismatch_without_mutation(tmp_path):
    effect = _effect(tmp_path)
    with pytest.raises(TransitionError, match="dispatch actor"):
        dispatch(str(tmp_path), effect["effect_id"], "attacker",
                 f"{effect['effect_id']}:attempt:1", "provider-1")
    import json
    effect_path = tmp_path / "effects" / (effect["effect_id"] + ".json")
    assert json.loads(effect_path.read_text(encoding="utf-8"))["state"] == "PLANNED"
    assert not list((tmp_path / "events").glob(
        "effect-" + effect["effect_id"] + "-DISPATCHED-attempt-*.json"
    ))


def test_retry_rejects_self_asserted_explicit_dict(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOS_AUTHORITY_SECRET", "test-only-authority-secret")
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1",
             f"{effect['effect_id']}:attempt:1", "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    forged = {"mode": "EXPLICIT", "effect_id": effect["effect_id"], "attempt": 2}
    with pytest.raises(TransitionError, match="retry authorization schema mismatch"):
        retry_dispatch(str(tmp_path), effect["effect_id"], "agent-1",
                       f"{effect['effect_id']}:attempt:2", "provider-1", 2, forged)


def test_retry_rejects_tampered_signature(tmp_path, monkeypatch):
    secret = "test-only-authority-secret"
    monkeypatch.setenv("AIOS_AUTHORITY_SECRET", secret)
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1",
             f"{effect['effect_id']}:attempt:1", "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    authorization = issue_retry_authorization(
        str(tmp_path), effect["effect_id"], "agent-1", 2, secret
    )
    authorization["attempt"] = 1
    with pytest.raises(TransitionError, match="binding mismatch"):
        retry_dispatch(str(tmp_path), effect["effect_id"], "agent-1",
                       f"{effect['effect_id']}:attempt:2", "provider-1", 2, authorization)


def test_retry_fails_closed_without_authority_secret(tmp_path, monkeypatch):
    monkeypatch.delenv("AIOS_AUTHORITY_SECRET", raising=False)
    effect = _effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1",
             f"{effect['effect_id']}:attempt:1", "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    with pytest.raises(TransitionError, match="secret is not configured"):
        retry_dispatch(str(tmp_path), effect["effect_id"], "agent-1",
                       f"{effect['effect_id']}:attempt:2", "provider-1", 2,
                       {"mode": "EXPLICIT"})



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
            "attempt_id": f"{effect['effect_id']}:attempt:1",
            "provider": "provider-1",
            "evidence": evidence,
        })
