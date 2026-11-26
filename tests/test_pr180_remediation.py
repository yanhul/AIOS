# AIOS-CONTRACT: restart recovery reuses the normal verification contract; receipt, verification, state patch
#   and action result are one digest-bound record; ledger folding recomputes canonical identity;
#   verify_effect_ledger is read-only; blocking persists a projection consistent with canonical state.
# AIOS-REGRESSION: PR #180 audit P1-A (recovery discarded recomputed verification/state patch), P1-B (ledger
#   fold trusted event identity fields), P2-A (verification mutated journals), P2-B (_block left stale projection).
# AIOS-OWNER: AIOS control-plane durable execution (L3/L5)
# AIOS-COVERAGE-GAP: Crash matrix, recovery-record tamper, identity forgery, filesystem immutability, blocked restart.
# AIOS-BASELINE: Extends tests/test_l3_l5_identity_binding.py and tests/test_l5_journal_hardening.py.
"""PR #180 P1/P2 remediation: adversarial crash, tamper, identity and read-only tests.

P1-A recovery verification/state patch binding   (core/durable_loop.py, core/orchestrator.py)
P1-B canonical attempt identity in ledger folding (core/effect_authority.py)
P2-A read-only verify_effect_ledger              (core/effect_authority.py, core/mutation.py)
P2-B blocked state keeps durable projection      (core/orchestrator.py::_block)
"""
import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

import core.durable_loop as durable_loop
import core.effect_authority as ea
import core.mutation as mutation
from core.continue_contract import build_continue_contract
from core.durable_loop import MemoryStateStore, _recovery_binding
from core.effect_identity import effect_identity
from tests.test_l3_l5_identity_binding import (ACTOR, BrokenAdapter, CountingAdapter, Crash, _classification,
                                               _run, _setup)


class CrashStore:
    """MemoryStateStore that simulates process death on the first save matching ``when``."""

    def __init__(self, when=None):
        self.inner, self.when = MemoryStateStore(), when

    def load(self):
        return self.inner.load()

    def save(self, state):
        if self.when is not None and self.when(state):
            self.when = None
            raise Crash()
        self.inner.save(state)

    @property
    def raw(self):
        return self.inner.state


def _patch_verifier(armed=None):
    """Verifier whose verification carries a state patch bound to the observed attempt."""
    def verify(result, state):
        if armed is not None and armed["armed"]:
            armed["armed"] = False
            raise Crash()
        observed = str(result.get("state", "")).startswith("OBSERVED")
        receipt = {"effect_id": result["effect_id"], "attempt_id": result["attempt_id"],
                   "status": "OBSERVED" if observed else "UNKNOWN",
                   "evidence": result.get("evidence") or {"effect_state": result.get("state")}}
        out = {"receipt": receipt}
        if observed:
            out["state_patch"] = {"artifact": f"built:{result['attempt_id']}"}
        return out
    return verify


def _validated(state):
    intent = state.get("in_flight_attempt") or {}
    return intent.get("status") == "RECEIPT_VALIDATED"


def _crash_before_patch(monkeypatch):
    original = durable_loop._apply_state_patch
    calls = {"n": 0}

    def boom(state, patch):
        calls["n"] += 1
        if calls["n"] == 1:
            raise Crash()
        return original(state, patch)
    monkeypatch.setattr(durable_loop, "_apply_state_patch", boom)


def _leave_receipt_validated(tmp_path, monkeypatch):
    executor, policy, cid, adapter = _setup(tmp_path, verifier=_patch_verifier())
    store = CrashStore()
    _crash_before_patch(monkeypatch)
    with pytest.raises(Crash):
        _run(executor, policy, store)
    assert _validated(store.raw) and "artifact" not in store.raw
    return executor, policy, cid, adapter, store


# ============================================================ P1-A crash matrix

def _assert_recovered(resumed, adapter, eid):
    assert resumed["status"] == "SUCCESS" and adapter.calls == 1
    assert "in_flight_attempt" not in resumed
    assert resumed["artifact"] == f"built:{eid}:attempt:1"  # state patch is never lost
    assert resumed["history"][-1]["verification"]["receipt"]["effect_id"] == eid
    assert len(resumed["history"]) == 1


def test_crash_before_receipt_persistence_recovers_state_patch(tmp_path):
    """Pre-fix bug: recovery recomputed verification but discarded its state_patch."""
    armed = {"armed": True}
    executor, policy, cid, adapter = _setup(tmp_path, verifier=_patch_verifier(armed))
    store = CrashStore()
    with pytest.raises(Crash):
        _run(executor, policy, store)
    assert store.raw["in_flight_attempt"]["status"] == "PREPARED"
    _assert_recovered(_run(executor, policy, store), adapter, effect_identity(cid, "op-1", ACTOR))


def test_crash_during_receipt_validated_save_recovers_from_l5(tmp_path):
    executor, policy, cid, adapter = _setup(tmp_path, verifier=_patch_verifier())
    store = CrashStore(when=_validated)
    with pytest.raises(Crash):
        _run(executor, policy, store)
    assert store.raw["in_flight_attempt"]["status"] == "PREPARED"
    _assert_recovered(_run(executor, policy, store), adapter, effect_identity(cid, "op-1", ACTOR))


def test_crash_after_validation_before_state_patch(tmp_path, monkeypatch):
    executor, policy, cid, adapter, store = _leave_receipt_validated(tmp_path, monkeypatch)
    assert store.raw["in_flight_attempt"]["recovery_binding"].startswith("sha256:")
    _assert_recovered(_run(executor, policy, store), adapter, effect_identity(cid, "op-1", ACTOR))


def test_crash_after_state_patch_before_checkpoint(tmp_path):
    executor, policy, cid, adapter = _setup(tmp_path, verifier=_patch_verifier())
    store = CrashStore(when=lambda s: "in_flight_attempt" not in s and "artifact" in s)
    with pytest.raises(Crash):
        _run(executor, policy, store)
    assert _validated(store.raw)  # the checkpoint never landed; durable record is RECEIPT_VALIDATED
    _assert_recovered(_run(executor, policy, store), adapter, effect_identity(cid, "op-1", ACTOR))


def test_repeated_recovery_is_idempotent(tmp_path, monkeypatch):
    executor, policy, cid, adapter, store = _leave_receipt_validated(tmp_path, monkeypatch)
    first = _run(executor, policy, store)
    for _ in range(3):
        again = _run(executor, policy, store)
        assert again == first and adapter.calls == 1


def test_recomputed_action_result_must_match_durable_recovery_record(tmp_path, monkeypatch):
    executor, policy, cid, adapter, store = _leave_receipt_validated(tmp_path, monkeypatch)
    intent = store.raw["in_flight_attempt"]
    before = json.loads(json.dumps(store.raw))
    with pytest.raises(ValueError, match="recomputed action result differs"):
        durable_loop.reconcile_in_flight_attempt(
            store, policy, intent["validated_receipt"],
            authorizer=lambda pending, receipt: None,
            verification=intent["validated_verification"],
            action_result={"forged": "different-action"},
        )
    assert store.raw == before
    assert adapter.calls == 1


def _rebind(intent):
    intent["recovery_binding"] = _recovery_binding(
        intent, intent["validated_receipt"], intent["validated_state_patch"],
        intent["validated_verification"], intent["validated_action_result"])


def _tamper_verification(i):
    i["validated_verification"]["forged"] = True


def _tamper_patch(i):
    i["validated_state_patch"]["artifact"] = "forged"


def _tamper_patch_consistently_and_rebind(i):
    i["validated_state_patch"]["artifact"] = "forged"
    i["validated_verification"]["state_patch"] = {"artifact": "forged"}
    _rebind(i)


def _tamper_receipt_attempt(i):
    i["validated_receipt"]["attempt_id"] = i["effect_id"] + ":attempt:2"
    i["validated_verification"]["receipt"]["attempt_id"] = i["effect_id"] + ":attempt:2"
    _rebind(i)


def _tamper_action(i):
    i["validated_action_result"] = {"forged": True}


TAMPERS = {
    "verification": _tamper_verification,
    "state_patch": _tamper_patch,
    "state_patch_rebound": _tamper_patch_consistently_and_rebind,
    "receipt_attempt_mismatch": _tamper_receipt_attempt,
    "action_result": _tamper_action,
    "missing_binding": lambda i: i.pop("recovery_binding"),
    "missing_action": lambda i: i.pop("validated_action_result"),
    "malformed_verification": lambda i: i.__setitem__("validated_verification", "x"),
    "malformed_patch": lambda i: i.__setitem__("validated_state_patch", ["artifact"]),
    "binding_garbage": lambda i: i.__setitem__("recovery_binding", "sha256:00"),
}


@pytest.mark.parametrize("name", sorted(TAMPERS))
def test_tampered_or_partial_recovery_record_is_rejected(tmp_path, monkeypatch, name):
    executor, policy, cid, adapter, store = _leave_receipt_validated(tmp_path, monkeypatch)
    TAMPERS[name](store.raw["in_flight_attempt"])
    for _ in range(2):  # stays rejected across restarts
        resumed = _run(executor, policy, store)
        assert resumed["status"] == "FAILURE" and _classification(resumed) == "RECONCILIATION_REJECTED"
        assert "in_flight_attempt" in resumed and "artifact" not in resumed
        assert adapter.calls == 1  # never replays the provider to rebuild evidence


# ============================================================ P1-B canonical identity

def _success(tmp_path):
    executor, policy, cid, adapter = _setup(tmp_path)
    assert _run(executor, policy, MemoryStateStore())["status"] == "SUCCESS"
    return str(tmp_path), effect_identity(cid, "op-1", ACTOR)


def _ev(aios, eid, suffix):
    return Path(aios) / "events" / f"effect-{eid}-{suffix}.json"


def _edit(path, fn):
    data = json.loads(path.read_text())
    fn(data)
    path.write_text(json.dumps(data))


def test_fresh_ledger_is_verified(tmp_path):
    aios, eid = _success(tmp_path)
    assert ea.inspect_effect_ledger(aios, eid)["verdict"] == "VERIFIED"


def _forge_attempt(aios, eid):
    forged = "EF-" + "0" * 64 + ":attempt:1"
    _edit(Path(aios) / "effects" / f"{eid}.json", lambda d: d.__setitem__("attempt_id", forged))
    _edit(_ev(aios, eid, "a1-dispatch-DISPATCHED"), lambda d: d.__setitem__("attempt_id", forged))


def _write_event(aios, eid, attempt, action, to_state, **fields):
    rel, ev = ea._ledger_event(eid, attempt, action, to_state, **fields)
    (Path(aios) / rel).write_text(json.dumps(ev))


IDENTITY_ATTACKS = {
    "forged_attempt_id": _forge_attempt,
    "forged_effect_id_projection": lambda a, e: _edit(Path(a) / "effects" / f"{e}.json",
                                                      lambda d: d.__setitem__("effect_id", "EF-" + "1" * 64)),
    "forged_effect_id_event": lambda a, e: _edit(_ev(a, e, "a1-dispatch-DISPATCHED"),
                                                 lambda d: d.__setitem__("effect_id", "EF-" + "1" * 64)),
    "cross_contract": lambda a, e: _edit(_ev(a, e, "a0-create-PLANNED"),
                                         lambda d: d.__setitem__("contract_id", "CT-other")),
    "cross_actor": lambda a, e: _edit(_ev(a, e, "a0-create-PLANNED"),
                                      lambda d: d.__setitem__("actor", "agent:evil")),
    "altered_logical_operation": lambda a, e: [
        _edit(Path(a) / "effects" / f"{e}.json", lambda d: d.__setitem__("logical_operation_id", "op-2")),
        _edit(_ev(a, e, "a0-create-PLANNED"), lambda d: d.__setitem__("logical_operation_id", "op-2"))],
    "create_event_logical_operation_only": lambda a, e: _edit(
        _ev(a, e, "a0-create-PLANNED"), lambda d: d.__setitem__("logical_operation_id", "op-2")),
    "observe_attempt_substitution": lambda a, e: _edit(
        _ev(a, e, "a1-transition-OBSERVED_SUCCESS"), lambda d: d.__setitem__("attempt_id", e + ":attempt:9")),
    "ordering_extra_dispatch": lambda a, e: _write_event(a, e, 2, "dispatch", "DISPATCHED",
                                                         attempt_id=e + ":attempt:2"),
    "conflicting_outcome": lambda a, e: _write_event(a, e, 1, "transition", "OBSERVED_FAILURE"),
    "mixed_legacy_version": lambda a, e: _ev(a, e, "a9-legacy").write_text(json.dumps({"event_version": 1})),
}


@pytest.mark.parametrize("name", sorted(IDENTITY_ATTACKS))
def test_identity_attacks_are_conflict(tmp_path, name):
    aios, eid = _success(tmp_path)
    IDENTITY_ATTACKS[name](aios, eid)
    result = ea.inspect_effect_ledger(aios, eid)
    assert result["verdict"] == "CONFLICT", result
    with pytest.raises(ea.TransitionError):
        ea.verify_effect_ledger(aios, eid)


def test_legacy_ledger_without_create_is_unknown_never_verified(tmp_path):
    aios, eid = _success(tmp_path)
    _ev(aios, eid, "a0-create-PLANNED").unlink()
    result = ea.verify_effect_ledger(aios, eid)
    assert result["verdict"] == "UNKNOWN" and result["status"] == "LEGACY_UNVERIFIABLE"


def test_pre_fix_create_event_is_verified_separately_not_backfilled(tmp_path):
    aios, eid = _success(tmp_path)
    path = _ev(aios, eid, "a0-create-PLANNED")
    _edit(path, lambda d: d.pop("logical_operation_id"))
    before = path.read_bytes()
    assert ea.inspect_effect_ledger(aios, eid)["verdict"] == "VERIFIED_SEPARATE"
    assert path.read_bytes() == before  # never repaired or backfilled


def test_orchestrator_blocks_recovery_on_forged_ledger_identity(tmp_path):
    armed = {"armed": True}
    executor, policy, cid, adapter = _setup(tmp_path, verifier=_patch_verifier(armed))
    store = CrashStore()
    with pytest.raises(Crash):
        _run(executor, policy, store)
    eid = effect_identity(cid, "op-1", ACTOR)
    _edit(_ev(str(tmp_path), eid, "a0-create-PLANNED"), lambda d: d.__setitem__("actor", "agent:evil"))
    resumed = _run(executor, policy, store)
    assert resumed["status"] == "FAILURE" and _classification(resumed) == "LEDGER_INCONSISTENT"
    assert adapter.calls == 1 and "artifact" not in resumed


# ============================================================ P2-A read-only verification

def _snapshot(root):
    snap = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            st = os.stat(path)
            digest = None
            if os.path.isfile(path):
                with open(path, "rb") as fh:
                    digest = hashlib.sha256(fh.read()).hexdigest()
            snap[os.path.relpath(path, root)] = (st.st_size if digest else None, digest, st.st_mtime_ns)
    return snap


def _forbid_mutation(monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("verification invoked a mutating recovery path")
    for target, name in ((ea, "recover_pending"), (mutation, "_recover_pending_unlocked"),
                         (mutation, "_quarantine"), (mutation, "recover_pending")):
        monkeypatch.setattr(target, name, forbidden)


def test_verification_is_byte_identical_and_deterministic(tmp_path, monkeypatch):
    aios, eid = _success(tmp_path)
    _forbid_mutation(monkeypatch)
    before = _snapshot(aios)
    results = [ea.verify_effect_ledger(aios, eid) for _ in range(3)]
    assert all(r == results[0] for r in results) and results[0]["verdict"] == "VERIFIED"
    assert _snapshot(aios) == before


@pytest.mark.parametrize("content", ["{garbage", json.dumps({"format": "x", "ops": []}), None])
def test_corrupt_or_pending_journal_untouched_by_verification(tmp_path, monkeypatch, content):
    aios, eid = _success(tmp_path)
    batch = Path(aios) / ".staging" / "batch-adversarial"
    batch.mkdir(parents=True)
    if content is not None:
        (batch / "journal.v2.json").write_text(content)
    with monkeypatch.context() as m:
        _forbid_mutation(m)
        before = _snapshot(aios)
        for _ in range(2):
            result = ea.verify_effect_ledger(aios, eid)
            assert result["verdict"] == "UNKNOWN" and result["status"] == "PENDING_RECOVERY"
        assert _snapshot(aios) == before and batch.is_dir()
    # Recovery happens only through the explicit recovery API.
    if content is None:
        ea.recover_pending(aios)
        assert not batch.exists()
        assert ea.verify_effect_ledger(aios, eid)["verdict"] == "VERIFIED"
    else:
        with pytest.raises(mutation.LedgerBlockedError):
            ea.recover_pending(aios)
        assert (Path(aios) / mutation.QUARANTINE_DIR / "batch-adversarial").is_dir()
        assert ea.verify_effect_ledger(aios, eid)["verdict"] == "UNKNOWN"


def test_unresolved_quarantine_is_unknown_not_verified(tmp_path):
    aios, eid = _success(tmp_path)
    (Path(aios) / mutation.QUARANTINE_DIR / "batch-q").mkdir(parents=True)
    before = _snapshot(aios)
    assert ea.inspect_effect_ledger(aios, eid)["verdict"] == "UNKNOWN"
    assert _snapshot(aios) == before


# ============================================================ P2-B blocked state / projection

_CC = {"authority": "AIOS_CONTROL_PLANE", "project": "pr180", "design": "blocked-projection",
       "pipeline": {"exec": "PENDING"}, "active_phase": "exec", "active_commit": "c0",
       "latest_run": "r0", "active_blockers": [], "next_legal_actions": [], "forbidden_actions": []}


def _builder(fail_on_block=False):
    def build(state):
        if fail_on_block and "reconciliation" in state:
            raise ValueError("projection unavailable")
        # The projection depends on the block reason, so a stale projection is detectable.
        return build_continue_contract({**_CC, **state, "latest_receipt": str(state.get("block_reason") or "none")})
    return build


def _blocked_setup(tmp_path, fail_on_block=False):
    adapter = CountingAdapter(BrokenAdapter())
    executor, policy, _, _ = _setup(tmp_path, adapter=adapter)
    return executor, replace(policy, continue_contract_builder=_builder(fail_on_block)), adapter


def _projection_consistent(state, builder):
    source = {k: v for k, v in state.items() if k != "continue_contract"}
    return state.get("continue_contract") == builder(source)


def test_block_persists_projection_consistent_with_canonical_state(tmp_path):
    executor, policy, adapter = _blocked_setup(tmp_path)
    store = CrashStore()
    _run(executor, policy, store)
    seen = []
    for _ in range(3):
        resumed = _run(executor, policy, store)
        persisted = store.load()
        assert persisted["status"] == "FAILURE" and _classification(persisted) == "LEDGER_UNKNOWN"
        assert _projection_consistent(persisted, policy.continue_contract_builder)
        seen.append((persisted["block_reason"], persisted["continue_contract"]))
        assert resumed["status"] != "RUNNING"
    assert len(set(json.dumps(s, sort_keys=True) for s in seen)) == 1
    assert adapter.calls == 1  # blocked execution never dispatches again


def test_crash_during_block_leaves_no_contradiction(tmp_path):
    executor, policy, adapter = _blocked_setup(tmp_path)
    store = CrashStore()
    _run(executor, policy, store)
    prior = store.load()
    store.when = lambda s: "reconciliation" in s
    with pytest.raises(Crash):
        _run(executor, policy, store)
    assert store.load() == prior  # nothing half-written
    resumed = _run(executor, policy, store)
    assert resumed["status"] == "FAILURE" and _projection_consistent(store.load(), policy.continue_contract_builder)
    assert adapter.calls == 1


def test_block_with_unbuildable_projection_drops_it_and_fails_closed(tmp_path):
    executor, policy, adapter = _blocked_setup(tmp_path, fail_on_block=True)
    store = CrashStore()
    _run(executor, policy, store)
    resumed = _run(executor, policy, store)
    persisted = store.load()
    assert persisted["status"] == "FAILURE" and "continue_contract" not in persisted
    assert "projection_error" in persisted and resumed["status"] != "RUNNING"
    try:
        again = _run(executor, policy, store)
        assert again["status"] != "RUNNING"
    except ValueError:
        pass  # fail-closed resume integrity error is also acceptable
    assert adapter.calls == 1
