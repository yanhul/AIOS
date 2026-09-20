import pytest

from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.policy_registry import persist_policy

from core.effect_authority import create_effect, dispatch, observe, unknown
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


def _observation(effect_id, provider="provider-1"):
    return {
        "attempt_id": f"{effect_id}:attempt:1",
        "provider": provider,
        "evidence": _evidence(provider),
    }


def test_effect_transition_is_atomic_and_audited(tmp_path):
    effect = _effect(tmp_path)
    assert effect["state"] == "PLANNED"
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    done = observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", _observation(effect["effect_id"]))
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
            "attempt_id": f"{effect['effect_id']}:attempt:1",
            "provider": "provider-1",
            "evidence": evidence,
        })
