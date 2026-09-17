import tempfile

import pytest

from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.effect_authority import create_effect, dispatch, observe, retry_dispatch, transition, unknown
from core.evidence import EvidenceRecord
from core.mutation import TransitionError
from core.policy_registry import persist_policy

BINDING = {
    "target_sha": "sha256:worker-v1",
    "evidence_ref": "EV-effect-1",
    "lineage_ref": "LIN-effect-1",
    "idempotency_key": "idem-effect-1",
    "attempt_fence": 1,
}


def make_authorized(td):
    registry = CapabilityRegistry()
    registry.register(Capability("research_is_validation", "1", "test-fixture", "research", status="ACTIVE"))
    registry.persist(td, "test-fixture")
    policy = persist_policy(td, {"policy_type": "GOVERNING_POLICY", "name": "effect-hardening"})
    contract = {
        "contract_type": "EXECUTION_CONTRACT", "task_id": "RESEARCH_BC7", "scope": "research",
        "actor": "bc-controller", "capabilities": ["research_is_validation@1"],
        "input_digest": "sha256:input", "allowed_effects": ["process_execution"],
        "evidence_required": ["execution_receipt"], "max_attempts": 2,
        "terminal_states": ["PROMOTED", "REJECTED", "HOLD"], "policy_digest": policy,
    }
    persist_contract(td, contract)
    permit = persist_permit(td, contract, "AIOS_AUTHORITY")
    effect = create_effect(td, contract_identity(contract), "research-oos", "bc-controller", permit["permit_id"], "process_execution")
    return contract, permit, effect


def _dispatch(td, effect, attempt=1, **overrides):
    binding = dict(BINDING, **overrides)
    return dispatch(td, effect["effect_id"], "bc-controller", f"{effect['effect_id']}:attempt:{attempt}", "provider-a", **binding)


def _observation(effect_id):
    evidence = EvidenceRecord(evidence_id="EV-effect-1", level="OBSERVED", source_ref="runtime/provider-a",
                              claim="execution completed", run_id="run-1", provider="provider-a").as_record()
    return {
        "attempt_id": f"{effect_id}:attempt:1", "provider": "provider-a",
        **BINDING, "evidence": evidence,
    }


def test_effect_creation_requires_bound_permit_and_allowed_effect():
    with tempfile.TemporaryDirectory() as td:
        with pytest.raises((ValueError, KeyError, TransitionError)):
            create_effect(td, "fake-contract", "op", "bc-controller", "fake-permit", "process_execution")
        contract, permit, _ = make_authorized(td)
        with pytest.raises(TransitionError):
            create_effect(td, contract_identity(contract), "other", "bc-controller", permit["permit_id"], "forbidden")


def test_initial_dispatch_is_bound_to_effect_attempt_identity():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        with pytest.raises(ValueError):
            dispatch(td, effect["effect_id"], "bc-controller", "arbitrary-attempt", "provider-a", **BINDING)
        updated = _dispatch(td, effect)
        assert updated["state"] == "DISPATCHED" and updated["attempt"] == 1


def test_public_transition_cannot_mutate_identity_or_authority_fields():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        with pytest.raises(TransitionError):
            transition(td, effect["effect_id"], "DISPATCHED", "bc-controller", contract_id="forged-contract", attempt=1,
                       attempt_id=f"{effect['effect_id']}:attempt:1", provider="provider-a")


def test_unknown_can_only_return_to_dispatch_through_bounded_retry():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        first = _dispatch(td, effect)
        unknown(td, effect["effect_id"], "bc-controller", "provider timeout")
        with pytest.raises(TransitionError):
            dispatch(td, effect["effect_id"], "bc-controller", f"{effect['effect_id']}:attempt:2", "provider-a", **BINDING)
        retried = retry_dispatch(td, effect["effect_id"], "bc-controller", f"{effect['effect_id']}:attempt:2", "provider-a", 2,
                                 target_sha=BINDING["target_sha"], attempt_fence=2)
        assert retried["state"] == "DISPATCHED" and retried["attempt"] == 2
        assert first["state"] == "DISPATCHED"
        with pytest.raises(TransitionError):
            retry_dispatch(td, effect["effect_id"], "bc-controller", f"{effect['effect_id']}:attempt:3", "provider-a", 3,
                           target_sha=BINDING["target_sha"], attempt_fence=3)


def test_retry_rejects_equal_or_lower_attempt_fence():
    for candidate in (1, 0):
        with tempfile.TemporaryDirectory() as td:
            _contract, _permit, effect = make_authorized(td)
            _dispatch(td, effect)
            unknown(td, effect["effect_id"], "bc-controller", "provider timeout")
            with pytest.raises(TransitionError, match="increase monotonically"):
                retry_dispatch(td, effect["effect_id"], "bc-controller", f"{effect['effect_id']}:attempt:2", "provider-a", 2,
                               target_sha=BINDING["target_sha"], attempt_fence=candidate)


def test_retry_accepts_higher_attempt_fence():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        _dispatch(td, effect)
        unknown(td, effect["effect_id"], "bc-controller", "provider timeout")
        retried = retry_dispatch(td, effect["effect_id"], "bc-controller", f"{effect['effect_id']}:attempt:2", "provider-a", 2,
                                 target_sha=BINDING["target_sha"], attempt_fence=2)
        assert retried["attempt_fence"] == 2


def test_observation_requires_current_attempt_and_valid_aios_evidence():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        attempt_id = f"{effect['effect_id']}:attempt:1"
        _dispatch(td, effect)
        observed = observe(td, effect["effect_id"], "bc-controller", "OBSERVED_SUCCESS", _observation(effect["effect_id"]))
        assert observed["state"] == "OBSERVED_SUCCESS"
        with pytest.raises(TransitionError):
            observe(td, effect["effect_id"], "bc-controller", "OBSERVED_SUCCESS", _observation(effect["effect_id"]))


def test_tampered_persisted_authority_blocks_future_transition():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        _dispatch(td, effect)
        path = f"{td}/effects/{effect['effect_id']}.json"
        import json
        with open(path, "r", encoding="utf-8") as fh:
            rec = json.load(fh)
        rec["policy_digest"] = "tampered-policy"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rec, fh)
        with pytest.raises(TransitionError):
            unknown(td, effect["effect_id"], "bc-controller", "should be blocked")
