"""Concurrency regression tests for effect identity and one-shot dispatch.

The tests use independent worker threads against one durable AIOS state
directory. Exactly one state transition may win a contested attempt.
"""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import json
import tempfile

from core.effect_authority import create_effect, dispatch, retry_dispatch, unknown
from core.mutation import TransitionError
from tests.retry_issuers import signed_retry_auth
from tests.test_effect_authority_hardening import make_authorized


def _race_two(fn):
    barrier = Barrier(2)

    def run():
        barrier.wait(timeout=5)
        try:
            return ("ok", fn())
        except Exception as exc:
            return ("error", exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        return list(pool.map(lambda _: run(), range(2)))


def test_concurrent_create_same_logical_operation_returns_one_identity():
    with tempfile.TemporaryDirectory() as td:
        from core.capabilities import Capability, CapabilityRegistry
        from core.authority import persist_contract, persist_permit
        from core.contract import contract_identity
        from core.policy_registry import persist_policy

        registry = CapabilityRegistry()
        registry.register(Capability("research_is_validation", "1", "test-fixture", "research", status="ACTIVE"))
        registry.register(Capability("provider-a", "1", "test-fixture", "process_execution", status="ACTIVE"))
        registry.persist(td, "test-fixture")
        policy = persist_policy(td, {"policy_type": "GOVERNING_POLICY", "name": "effect-race"})
        contract = {
            "contract_type": "EXECUTION_CONTRACT", "task_id": "RACE", "scope": "research",
            "actor": "bc-controller", "capabilities": ["research_is_validation@1", "provider-a@1"],
            "input_digest": "sha256:input", "allowed_effects": ["process_execution"],
            "evidence_required": ["execution_receipt"], "max_attempts": 2,
            "terminal_states": ["PROMOTED", "REJECTED", "HOLD"], "policy_digest": policy,
        }
        persist_contract(td, contract)
        permit = persist_permit(td, contract, "AIOS_AUTHORITY")
        args = (td, contract_identity(contract), "same-logical-operation", "bc-controller",
                permit["permit_id"], "process_execution")
        outcomes = _race_two(lambda: create_effect(*args))
        assert all(kind == "ok" for kind, _ in outcomes)
        effects = [value for _, value in outcomes]
        assert effects[0]["effect_id"] == effects[1]["effect_id"]
        assert effects[0]["state"] == effects[1]["state"] == "PLANNED"
        import os
        effect_files = [p for p in os.listdir(os.path.join(td, "effects")) if p.endswith(".json")]
        assert len(effect_files) == 1


def test_concurrent_initial_dispatch_has_exactly_one_winner():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        attempt_id = f"{effect['effect_id']}:attempt:1"
        outcomes = _race_two(lambda: dispatch(
            td, effect["effect_id"], "bc-controller", attempt_id, "provider-a"
        ))
        assert sum(kind == "ok" for kind, _ in outcomes) == 1
        assert sum(kind == "error" for kind, _ in outcomes) == 1
        assert all(isinstance(value, TransitionError) for kind, value in outcomes if kind == "error")
        from core.effect_authority import _path
        with open(_path(td, effect["effect_id"]), encoding="utf-8") as fh:
            persisted = json.load(fh)
        assert persisted["state"] == "DISPATCHED"
        assert persisted["attempt"] == 1
        assert persisted["attempt_id"] == attempt_id


def test_retry_authorization_is_consumed_once_under_concurrent_workers():
    with tempfile.TemporaryDirectory() as td:
        _contract, _permit, effect = make_authorized(td)
        first_attempt = f"{effect['effect_id']}:attempt:1"
        dispatch(td, effect["effect_id"], "bc-controller", first_attempt, "provider-a")
        unknown(td, effect["effect_id"], "bc-controller", "provider timeout")
        retry_attempt = f"{effect['effect_id']}:attempt:2"
        authorization = signed_retry_auth(
            td, effect["effect_id"], "bc-controller", 2, "operator:test", "one-shot race"
        )
        outcomes = _race_two(lambda: retry_dispatch(
            td, effect["effect_id"], "bc-controller", retry_attempt, "provider-a", 2,
            authorization,
        ))
        assert sum(kind == "ok" for kind, _ in outcomes) == 1
        assert sum(kind == "error" for kind, _ in outcomes) == 1
        assert all(isinstance(value, TransitionError) for kind, value in outcomes if kind == "error")
        from core.effect_authority import _path, _retry_consumption_rel
        authorization_id = authorization["authorization_id"]
        with open(_path(td, effect["effect_id"]), encoding="utf-8") as fh:
            persisted = json.load(fh)
        assert persisted["state"] == "DISPATCHED"
        assert persisted["attempt"] == 2
        assert persisted["consumed_retry_authorizations"] == [authorization_id]
        assert __import__("os").path.exists(os.path.join(td, _retry_consumption_rel(authorization_id)))
