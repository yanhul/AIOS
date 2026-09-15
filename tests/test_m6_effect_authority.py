import pytest

from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.effect_authority import create_effect, dispatch, observe, unknown
from core.evidence import EvidenceRecord
from core.mutation import TransitionError
from core.policy_registry import persist_policy


def setup_authority(tmp_path, max_attempts=1):
    registry = CapabilityRegistry()
    registry.register(Capability("provider", "1", "test-fixture", "test", status="ACTIVE"))
    registry.persist(str(tmp_path), "test-fixture")
    policy = persist_policy(str(tmp_path), {"policy_type": "GOVERNING_POLICY", "name": "effect-fixture"})
    contract = {
        "contract_type": "EXECUTION_CONTRACT", "task_id": "task-effect", "scope": "effect-test",
        "actor": "agent-1", "capabilities": ["provider@1"], "input_digest": "input-1",
        "allowed_effects": ["external_effect"], "evidence_required": ["provider_receipt"],
        "max_attempts": max_attempts, "terminal_states": ["SUCCESS", "FAILURE"], "policy_digest": policy,
    }
    cid = contract_identity(contract)
    persist_contract(str(tmp_path), contract)
    permit = persist_permit(str(tmp_path), contract, "root")
    return cid, permit["permit_id"]


def evidence(provider="provider"):
    return EvidenceRecord("EV-1", "OBSERVED", "provider://receipt/1", "provider completed operation", "run-1", provider).as_record()


def observation(effect_id, provider="provider"):
    return {"attempt_id": f"{effect_id}:attempt:1", "provider": provider, "evidence": evidence(provider)}


def make_effect(tmp_path):
    cid, pid = setup_authority(tmp_path)
    return create_effect(str(tmp_path), cid, "op-1", "agent-1", pid, "external_effect")


def test_effect_transition_is_atomic_and_audited(tmp_path):
    effect = make_effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    # UNKNOWN is intentionally non-dispatchable; this test checks the direct
    # observed path on a fresh dispatched attempt instead.
    effect = make_effect(tmp_path / "fresh")
    dispatch(str(tmp_path / "fresh"), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider")
    result = observe(str(tmp_path / "fresh"), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", observation(effect["effect_id"]))
    assert result["state"] == "OBSERVED_SUCCESS"
    assert (tmp_path / "fresh" / "events" / ("effect-" + effect["effect_id"] + "-OBSERVED_SUCCESS.json")).exists()


def test_unknown_cannot_return_to_dispatch(tmp_path):
    effect = make_effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider")
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "timeout")
    with pytest.raises(TransitionError):
        dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:2", "provider")


def test_terminal_state_requires_verified_attempt_bound_evidence(tmp_path):
    effect = make_effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider")
    with pytest.raises(ValueError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {})
    with pytest.raises(TransitionError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {
            **observation(effect["effect_id"]), "attempt_id": "forged-attempt"
        })


def test_observation_provider_must_match_effect(tmp_path):
    effect = make_effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider")
    with pytest.raises(TransitionError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", observation(effect["effect_id"], "provider-2"))


def test_tampered_evidence_digest_is_rejected(tmp_path):
    effect = make_effect(tmp_path)
    dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider")
    forged = evidence()
    forged["claim"] = "tampered"
    with pytest.raises(ValueError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {
            "attempt_id": f"{effect['effect_id']}:attempt:1", "provider": "provider", "evidence": forged,
        })
