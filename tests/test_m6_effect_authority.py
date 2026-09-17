import pytest

from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.effect_authority import create_effect, dispatch, observe, unknown
from core.evidence import EvidenceRecord
from core.mutation import TransitionError
from core.policy_registry import persist_policy

BINDING = {
    "target_sha": "sha256:worker-v1",
    "evidence_ref": "EV-1",
    "lineage_ref": "LIN-1",
    "idempotency_key": "idem-1",
    "attempt_fence": 1,
}


def _authorized(tmp_path):
    registry = CapabilityRegistry()
    registry.register(Capability("research_is_validation", "1", "test-fixture", "research", status="ACTIVE"))
    registry.persist(str(tmp_path), "test-fixture")
    policy = persist_policy(str(tmp_path), {"policy_type": "GOVERNING_POLICY", "name": "effect-tests"})
    contract = {
        "contract_type": "EXECUTION_CONTRACT", "task_id": "RESEARCH_TEST", "scope": "research",
        "actor": "agent-1", "capabilities": ["research_is_validation@1"],
        "input_digest": "sha256:input", "allowed_effects": ["process_execution"],
        "evidence_required": ["execution_receipt"], "max_attempts": 2,
        "terminal_states": ["PASS", "BLOCKED", "INCONCLUSIVE"], "policy_digest": policy,
    }
    persist_contract(str(tmp_path), contract)
    permit = persist_permit(str(tmp_path), contract, "AIOS_AUTHORITY")
    return create_effect(str(tmp_path), contract_identity(contract), "op-1", "agent-1", permit["permit_id"], "process_execution")


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


def _dispatch(tmp_path, effect, **overrides):
    binding = dict(BINDING, **overrides)
    return dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:1", "provider-1", **binding)


def test_effect_transition_is_atomic_and_audited(tmp_path):
    effect = _authorized(tmp_path)
    assert effect["state"] == "PLANNED"
    _dispatch(tmp_path, effect)
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    done = observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", _observation(effect["effect_id"]))
    assert done["state"] == "OBSERVED_SUCCESS"
    assert (tmp_path / "events" / ("effect-" + effect["effect_id"] + "-OBSERVED_SUCCESS.json")).exists()


def test_unknown_cannot_return_to_dispatch(tmp_path):
    effect = _authorized(tmp_path)
    _dispatch(tmp_path, effect)
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "timeout")
    with pytest.raises(TransitionError):
        dispatch(str(tmp_path), effect["effect_id"], "agent-1", f"{effect['effect_id']}:attempt:2", "provider-1", **BINDING)


def test_terminal_state_requires_verified_attempt_bound_evidence(tmp_path):
    effect = _authorized(tmp_path)
    _dispatch(tmp_path, effect)
    with pytest.raises(ValueError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {})

    with pytest.raises(TransitionError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {
            **_observation(effect["effect_id"]), "attempt_id": "forged-attempt"
        })


def test_observation_provider_must_match_effect(tmp_path):
    effect = _authorized(tmp_path)
    _dispatch(tmp_path, effect)
    with pytest.raises(TransitionError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", _observation(effect["effect_id"], "provider-2"))


def test_tampered_evidence_digest_is_rejected(tmp_path):
    effect = _authorized(tmp_path)
    _dispatch(tmp_path, effect)
    evidence = _evidence()
    evidence["claim"] = "tampered"
    with pytest.raises(ValueError):
        observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_SUCCESS", {
            "attempt_id": f"{effect['effect_id']}:attempt:1",
            "provider": "provider-1",
            "evidence": evidence,
        })


def test_late_receipt_can_reconcile_unknown_attempt(tmp_path):
    effect = _authorized(tmp_path)
    _dispatch(tmp_path, effect)
    unknown(str(tmp_path), effect["effect_id"], "agent-1", "provider timeout")
    done = observe(str(tmp_path), effect["effect_id"], "agent-1", "OBSERVED_FAILURE", _observation(effect["effect_id"]))
    assert done["state"] == "OBSERVED_FAILURE"
