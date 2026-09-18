import tempfile

import pytest

from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.effect_authority import (
    create_effect,
    dispatch,
    observe,
    retry_dispatch,
    transition,
    unknown,
)
from core.evidence import EvidenceRecord
from core.mutation import TransitionError
from core.policy_registry import persist_policy


def make_authorized(td):
    registry = CapabilityRegistry()
    registry.register(Capability("research_is_validation", "1", "test-fixture", "research", status="ACTIVE"))
    registry.persist(td, "test-fixture")
    policy = persist_policy(td, {"policy_type": "GOVERNING_POLICY", "name": "effect-hardening"})
    contract = {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": "RESEARCH_BC7",
        "scope": "research",
        "actor": "bc-controller",
        "capabilities": ["research_is_validation@1"],
        "input_digest": "sha256:input",
        "allowed_effects": ["external_effect"],
        "evidence_required": ["execution_receipt"],
        "max_attempts": 2,
        "terminal_states": ["PROMOTED", "REJECTED", "HOLD"],
        "policy_digest": policy,
    }
    persist_contract(td, contract)
    permit = persist_permit(td, contract, "AIOS_AUTHORITY")
    effect = create_effect(
        td,
        contract_identity(contract),
        "research-oos",
        "bc-controller",
        permit["permit_id"],
        "process_execution",
    )
    return contract, permit, effect


def test_effect_creation_requires_bound_permit_and_allowed_effect():
    with tempfile.TemporaryDirectory() as td:
        with pytest.raises((ValueError, KeyError, FileNotFoundError, TransitionError)):
            create_effect(td, "fake-contract", "op", "bc-controller", "fake-permit", "process_execution")
        contract, permit, _ = make_authorized(td)
        with pytest.raises(TransitionError):
            create_effect(td, contract_identity(contract), "other", "bc-controller", permit["permit_id"], "forbidden")


def test_initial_dispatch_is_bound_to_effect_attempt_identity():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        with pytest.raises(ValueError):
            dispatch(td, effect["effect_id"], "bc-controller", "arbitrary-attempt", "research_is_validation")
        updated = dispatch(td, effect["effect_id"], "bc-controller", f"{effect['effect_id']}:attempt:1", "research_is_validation")
        assert updated["state"] == "DISPATCHED"
        assert updated["attempt"] == 1


def test_public_transition_cannot_mutate_identity_or_authority_fields():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        with pytest.raises(TransitionError):
            transition(td, effect["effect_id"], "DISPATCHED", "bc-controller",
                       contract_id="forged-contract", attempt=1,
                       attempt_id=f"{effect['effect_id']}:attempt:1", provider="provider-a")


def test_unknown_can_only_return_to_dispatch_through_bounded_retry():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        dispatch(td, effect["effect_id"], "bc-controller", f"{effect['effect_id']}:attempt:1", "research_is_validation")
        unknown(td, effect["effect_id"], "bc-controller", "provider timeout")
        with pytest.raises(TransitionError):
            dispatch(td, effect["effect_id"], "bc-controller", f"{effect['effect_id']}:attempt:2", "research_is_validation")
        retried = retry_dispatch(td, effect["effect_id"], "bc-controller", f"{effect['effect_id']}:attempt:2", "research_is_validation", 2)
        assert retried["state"] == "DISPATCHED"
        with pytest.raises(TransitionError):
            retry_dispatch(td, effect["effect_id"], "bc-controller", f"{effect['effect_id']}:attempt:3", "research_is_validation", 3)


def test_retry_public_boundary_self_authorizes_provider_and_preserves_history():
    with tempfile.TemporaryDirectory() as td:
        contract, _permit, effect = make_authorized(td)
        attempt1 = f"{effect['effect_id']}:attempt:1"
        dispatch(td, effect["effect_id"], "bc-controller", attempt1, "provider-a")
        unknown(td, effect["effect_id"], "bc-controller", "provider timeout")

        with pytest.raises(TransitionError):
            retry_dispatch(td, effect["effect_id"], "bc-controller",
                           f"{effect['effect_id']}:attempt:2", "provider-a", 2)

        path = f"{td}/effects/{effect['effect_id']}.json"
        with open(path, "r", encoding="utf-8") as fh:
            current = __import__("json").load(fh)
        assert current["state"] == "UNKNOWN"
        assert current["attempt"] == 1
        # The initial DISPATCHED event remains intact; a retry event is only
        # created after the canonical retry transition is authorized.
        initial_event = f"{td}/events/effect-{effect['effect_id']}-DISPATCHED.json"
        retry_event = f"{td}/events/effect-{effect['effect_id']}-DISPATCHED-attempt-2.json"
        assert __import__("os").path.exists(initial_event)
        assert not __import__("os").path.exists(retry_event)


def test_retry_transition_requires_explicit_retry_gate():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        attempt1 = f"{effect['effect_id']}:attempt:1"
        dispatch(td, effect["effect_id"], "bc-controller", attempt1, "research_is_validation")
        unknown(td, effect["effect_id"], "bc-controller", "timeout")

        with pytest.raises(TransitionError):
            transition(td, effect["effect_id"], "DISPATCHED", "bc-controller",
                       attempt=2, attempt_id=f"{effect['effect_id']}:attempt:2",
                       provider="research_is_validation")


def test_observation_requires_current_attempt_and_valid_aios_evidence():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        attempt_id = f"{effect['effect_id']}:attempt:1"
        dispatch(td, effect["effect_id"], "bc-controller", attempt_id, "research_is_validation")
        evidence = EvidenceRecord(
            evidence_id="EV-effect-1",
            level="OBSERVED",
            source_ref="runtime/provider-a",
            claim="execution completed",
            run_id="run-1",
            provider="research_is_validation",
        ).as_record()
        observed = observe(
            td,
            effect["effect_id"],
            "bc-controller",
            "OBSERVED_SUCCESS",
            {"attempt_id": attempt_id, "provider": "research_is_validation", "evidence": evidence},
        )
        assert observed["state"] == "OBSERVED_SUCCESS"
        with pytest.raises(TransitionError):
            observe(td, effect["effect_id"], "bc-controller", "OBSERVED_SUCCESS",
                    {"attempt_id": attempt_id, "provider": "research_is_validation", "evidence": evidence})


def test_tampered_persisted_authority_blocks_future_transition():
    with tempfile.TemporaryDirectory() as td:
        contract, _permit, effect = make_authorized(td)
        dispatch(td, effect["effect_id"], "bc-controller", f"{effect['effect_id']}:attempt:1", "research_is_validation")
        path = f"{td}/effects/{effect['effect_id']}.json"
        import json
        with open(path, "r", encoding="utf-8") as fh:
            rec = json.load(fh)
        rec["policy_digest"] = "tampered-policy"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rec, fh)
        with pytest.raises(TransitionError):
            unknown(td, effect["effect_id"], "bc-controller", "should be blocked")
