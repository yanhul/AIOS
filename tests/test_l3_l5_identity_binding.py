# AIOS-CONTRACT: L3 owns logical operation identity; restart reconciles against the L5 ledger and never dispatches.
# AIOS-REGRESSION: B-1 Decision A (random attempt IDs, replay after crash, legacy intent promotion).
# AIOS-OWNER: AIOS control-plane durable execution (L3/L5)
# AIOS-COVERAGE-GAP: Crash at every L3/L5 boundary, tampered intent identity, legacy random IDs.
# AIOS-BASELINE: Extends tests/test_m6_runtime.py and tests/test_durable_loop_crash_recovery.py.
"""Phase 4 / B-1 Decision A: L3 owns logical operation identity; restart reconciles against L5.

Real L5 (journaled effect ledger) and L6 (Ed25519-attested permit) are used; process
death is simulated with a BaseException that no AIOS code catches.
"""
import json
from pathlib import Path

import pytest

import core.runtime as runtime
from core.durable_loop import LoopPolicy, MemoryStateStore
from core.effect_authority import _effect_rel, _load, _path
from core.effect_identity import effect_identity, operation_identity
from core.orchestrator import GovernedRuntimeExecutor, run_governed_execution
from tests.test_m6_runtime import BrokenAdapter, GoodAdapter, setup_authority

ACTOR = "agent:test"


class Crash(BaseException):
    pass


class CountingAdapter:
    def __init__(self, inner, crash=False):
        self.inner, self.crash, self.calls, self.name = inner, crash, 0, inner.name

    def execute(self, **kw):
        self.calls += 1
        if self.crash:
            raise Crash()
        return self.inner.execute(**kw)


def _verifier(crash_first=None):
    def verify(result, state):
        if crash_first is not None and crash_first["armed"]:
            crash_first["armed"] = False
            raise Crash()  # receipt already committed in L5; L3 checkpoint not yet written
        observed = str(result.get("state", "")).startswith("OBSERVED")
        return {"receipt": {"effect_id": result["effect_id"], "attempt_id": result["attempt_id"],
                            "status": "OBSERVED" if observed else "UNKNOWN",
                            "evidence": result.get("evidence") or {"effect_state": result.get("state")}}}
    return verify


def _setup(tmp_path, op="op-1", adapter=None, verifier=None, max_attempts=1):
    c, cid, pid = setup_authority(tmp_path, max_attempts=max_attempts)
    aios = str(tmp_path)

    def receipt_validator(receipt, state):  # binds every receipt to the L5 ledger
        effect = _load(_path(aios, receipt["effect_id"]))
        if effect.get("attempt_id") != receipt["attempt_id"]:
            raise ValueError("receipt attempt not in L5 ledger")
        if receipt["status"] == "OBSERVED" and not effect["state"].startswith("OBSERVED"):
            raise ValueError("receipt claims OBSERVED but L5 does not")

    policy = LoopPolicy(max_steps=1, terminal_evaluator=lambda v, s: "SUCCESS" if v["receipt"]["status"] == "OBSERVED" else None,
                        action_authorizer=lambda d, s: None, policy_digest=c["policy_digest"],
                        terminal_states=frozenset(c["terminal_states"]), failure_state="FAILURE",
                        budget_exhaustion_state="FAILURE", require_execution_receipt=True,
                        execution_receipt_validator=receipt_validator, state_patch_validator=lambda p, r, s: None,
                        operation_identity=lambda d, s: {})  # replaced by the orchestrator (authority-bound)
    adapter = adapter or CountingAdapter(GoodAdapter())
    executor = GovernedRuntimeExecutor(aios_dir=aios, contract_id=cid, permit_id=pid, actor=ACTOR, adapter=adapter,
                                       observer=lambda s: {}, decider=lambda o, s: {"logical_operation_id": op},
                                       verifier=verifier or _verifier())
    return executor, policy, cid, adapter


def _run(executor, policy, store):
    return run_governed_execution(executor=executor, store=store, policy=policy)


def _crash_run(executor, policy, store):
    with pytest.raises(Crash):
        _run(executor, policy, store)


def _effects(tmp_path):
    return sorted(p.stem for p in (Path(tmp_path) / "effects").glob("*.json"))


def _classification(state):
    return state.get("reconciliation", {}).get("classification")


def _patch_crash(monkeypatch, name):
    original = getattr(runtime, name)

    def boom(*a, **kw):
        raise Crash()
    monkeypatch.setattr(runtime, name, boom)
    return lambda: monkeypatch.setattr(runtime, name, original)


# ------------------------------------------------------------------ identity

def test_intent_identity_is_canonical_and_equals_l5_identity(tmp_path):
    executor, policy, cid, adapter = _setup(tmp_path)
    store = MemoryStateStore()
    result = _run(executor, policy, store)
    assert result["status"] == "SUCCESS" and adapter.calls == 1
    expected = operation_identity(cid, "op-1", ACTOR)
    receipt = result["history"][0]["verification"]["receipt"]
    assert (receipt["effect_id"], receipt["attempt_id"]) == (expected["effect_id"], expected["attempt_id"])
    assert _effects(tmp_path) == [expected["effect_id"]]


def test_two_logical_operations_never_share_an_effect(tmp_path):
    a, policy, cid, _ = _setup(tmp_path, op="op-A")
    _run(a, policy, MemoryStateStore())
    b, policy_b, _, _ = _setup(tmp_path, op="op-B")
    _run(b, policy_b, MemoryStateStore())
    assert _effects(tmp_path) == sorted([effect_identity(cid, "op-A", ACTOR), effect_identity(cid, "op-B", ACTOR)])
    assert effect_identity(cid, "op-A", ACTOR) != effect_identity(cid, "op-A", "other-actor")


def test_replaying_same_operation_creates_no_new_effect_and_no_provider_call(tmp_path):
    executor, policy, _, adapter = _setup(tmp_path)
    assert _run(executor, policy, MemoryStateStore())["status"] == "SUCCESS"
    replay = _run(executor, policy, MemoryStateStore())  # fresh L3 state, same logical operation
    assert replay["status"] == "FAILURE" and adapter.calls == 1 and len(_effects(tmp_path)) == 1


# ------------------------------------------------------------------ crash matrix

def test_crash_after_intent_before_l5_create(tmp_path, monkeypatch):
    executor, policy, _, adapter = _setup(tmp_path)
    store = MemoryStateStore()
    restore = _patch_crash(monkeypatch, "create_effect")
    _crash_run(executor, policy, store)
    restore()
    assert store.load()["in_flight_attempt"]["status"] == "PREPARED"
    resumed = _run(executor, policy, store)
    assert _classification(resumed) == "LEDGER_MISSING_EFFECT" and resumed["status"] == "FAILURE"
    assert adapter.calls == 0 and _effects(tmp_path) == []  # nothing inferred, nothing created


def test_crash_after_l5_create_before_dispatch(tmp_path, monkeypatch):
    executor, policy, _, adapter = _setup(tmp_path)
    store = MemoryStateStore()
    restore = _patch_crash(monkeypatch, "dispatch")
    _crash_run(executor, policy, store)
    restore()
    resumed = _run(executor, policy, store)
    assert _classification(resumed) == "LEDGER_PLANNED" and adapter.calls == 0


def test_crash_after_dispatched_commit_before_provider_call(tmp_path, monkeypatch):
    executor, policy, _, adapter = _setup(tmp_path)
    store = MemoryStateStore()
    restore = _patch_crash(monkeypatch, "execute_attempt")
    _crash_run(executor, policy, store)
    restore()
    for _ in range(3):  # repeated restarts
        resumed = _run(executor, policy, store)
        assert _classification(resumed) == "LEDGER_DISPATCHED"
    assert adapter.calls == 0


def test_crash_inside_provider_call(tmp_path):
    adapter = CountingAdapter(GoodAdapter(), crash=True)
    executor, policy, _, _ = _setup(tmp_path, adapter=adapter)
    store = MemoryStateStore()
    _crash_run(executor, policy, store)
    adapter.crash = False
    for _ in range(3):
        resumed = _run(executor, policy, store)
        assert _classification(resumed) == "LEDGER_DISPATCHED" and resumed["status"] == "FAILURE"
    assert adapter.calls == 1 and len(_effects(tmp_path)) == 1


def test_crash_after_receipt_commit_before_l3_checkpoint_reconciles_without_replay(tmp_path):
    armed = {"armed": True}
    executor, policy, cid, adapter = _setup(tmp_path, verifier=_verifier(armed))
    store = MemoryStateStore()
    _crash_run(executor, policy, store)
    eid = effect_identity(cid, "op-1", ACTOR)
    assert json.loads((Path(tmp_path) / _effect_rel(eid)).read_text())["state"] == "OBSERVED_SUCCESS"
    assert store.load()["in_flight_attempt"]["effect_id"] == eid  # L3 never checkpointed the result
    resumed = _run(executor, policy, store)
    assert resumed["status"] == "SUCCESS" and adapter.calls == 1
    assert "in_flight_attempt" not in resumed
    assert resumed["history"][-1]["verification"]["receipt"]["effect_id"] == eid
    again = _run(executor, policy, store)  # further restarts are no-ops
    assert again["status"] == "SUCCESS" and adapter.calls == 1 and len(again["history"]) == 1


def test_unknown_is_never_redispatched_or_promoted(tmp_path):
    adapter = CountingAdapter(BrokenAdapter())
    executor, policy, _, _ = _setup(tmp_path, adapter=adapter)
    store = MemoryStateStore()
    first = _run(executor, policy, store)
    assert first["status"] == "FAILURE" and "in_flight_attempt" in first
    for _ in range(3):
        resumed = _run(executor, policy, store)
        assert _classification(resumed) == "LEDGER_UNKNOWN"
    assert adapter.calls == 1


def test_ledger_inconsistency_fails_closed(tmp_path):
    armed = {"armed": True}
    executor, policy, cid, adapter = _setup(tmp_path, verifier=_verifier(armed))
    store = MemoryStateStore()
    _crash_run(executor, policy, store)
    eid = effect_identity(cid, "op-1", ACTOR)
    (Path(tmp_path) / "events" / f"effect-{eid}-a1-dispatch-DISPATCHED.json").unlink()
    resumed = _run(executor, policy, store)
    assert _classification(resumed) == "LEDGER_INCONSISTENT" and resumed["status"] == "FAILURE"


# ------------------------------------------------------------------ tamper / legacy

@pytest.mark.parametrize("field", ["contract_id", "actor", "logical_operation_id", "effect_id", "attempt_id"])
def test_tampered_intent_identity_blocks(tmp_path, field):
    armed = {"armed": True}
    executor, policy, _, adapter = _setup(tmp_path, verifier=_verifier(armed))
    store = MemoryStateStore()
    _crash_run(executor, policy, store)  # an OBSERVED effect is available to (wrongly) adopt
    state = store.load()
    state["in_flight_attempt"][field] = "tampered-" + field
    store.save(state)
    resumed = _run(executor, policy, store)
    assert resumed["status"] == "FAILURE" and "in_flight_attempt" in resumed
    assert _classification(resumed) in ("IDENTITY_INVALID", "IDENTITY_MISMATCH")
    assert adapter.calls == 1


@pytest.mark.parametrize("field", ["contract_id", "logical_operation_id"])
def test_consistently_rederived_tamper_still_blocks(tmp_path, field):
    """Attacker recomputes effect/attempt IDs so derivation checks pass; context binding still rejects."""
    armed = {"armed": True}
    executor, policy, cid, adapter = _setup(tmp_path, verifier=_verifier(armed))
    store = MemoryStateStore()
    _crash_run(executor, policy, store)
    state = store.load()
    intent = state["in_flight_attempt"]
    values = {"contract_id": intent["contract_id"], "logical_operation_id": intent["logical_operation_id"]}
    values[field] = "other-" + field
    intent.update(operation_identity(values["contract_id"], values["logical_operation_id"], ACTOR))
    store.save(state)
    resumed = _run(executor, policy, store)
    assert _classification(resumed) == "IDENTITY_MISMATCH" and adapter.calls == 1


def test_legacy_random_id_intent_is_never_promoted(tmp_path):
    armed = {"armed": True}
    executor, policy, cid, adapter = _setup(tmp_path, verifier=_verifier(armed))
    store = MemoryStateStore()
    _crash_run(executor, policy, store)  # L5 holds an OBSERVED_SUCCESS effect for op-1
    state = store.load()
    legacy = {k: v for k, v in state["in_flight_attempt"].items()
              if k in ("decision", "observation", "status")}
    legacy.update({"effect_id": "effect-0123456789abcdef", "attempt_id": "attempt-0123456789abcdef"})
    state["in_flight_attempt"] = legacy
    store.save(state)
    for _ in range(2):
        resumed = _run(executor, policy, store)
        assert _classification(resumed) == "LEGACY_UNRECONCILED" and resumed["status"] == "FAILURE"
        assert resumed["in_flight_attempt"] == legacy  # not backfilled or rewritten
    assert adapter.calls == 1


def test_receipt_mode_without_identity_is_rejected():
    with pytest.raises(ValueError, match="operation_identity"):
        LoopPolicy(max_steps=1, terminal_evaluator=lambda v, s: None, action_authorizer=lambda d, s: None,
                   require_execution_receipt=True, execution_receipt_validator=lambda r, s: None,
                   state_patch_validator=lambda p, r, s: None)


def test_operator_retry_outcome_on_other_attempt_is_not_adopted(tmp_path):
    """L5 OBSERVED at attempt 2 (explicit operator retry) must not close the L3 attempt-1 intent."""
    from core.runtime import execute_retry_attempt
    from tests.retry_issuers import signed_retry_auth
    adapter = CountingAdapter(BrokenAdapter())
    executor, policy, cid, _ = _setup(tmp_path, adapter=adapter, max_attempts=2)
    store = MemoryStateStore()
    assert _run(executor, policy, store)["status"] == "FAILURE"  # attempt 1 -> UNKNOWN
    eid = effect_identity(cid, "op-1", ACTOR)
    effect = json.loads((Path(tmp_path) / _effect_rel(eid)).read_text())
    effect["retry_authorization"] = signed_retry_auth(str(tmp_path), eid, ACTOR, 2, "operator:test", "explicit retry")
    retried = execute_retry_attempt(str(tmp_path), cid, executor.permit_id, effect, ACTOR, GoodAdapter(),
                                    f"{eid}:attempt:2", 2)
    assert retried["state"] == "OBSERVED_SUCCESS" and retried["attempt"] == 2
    resumed = _run(executor, policy, store)
    assert _classification(resumed) == "ATTEMPT_MISMATCH" and resumed["status"] == "FAILURE"
    assert adapter.calls == 1
