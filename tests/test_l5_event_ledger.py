"""Phase 3 — L5 durable event ledger: fault injection, restart/recovery, duplicate/replay.

Maps to docs/L5_EVENT_LEDGER.md (contract 3.x, failure matrix F1..F6).
"""
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import core.mutation as mutation
from core.effect_authority import _effect_rel, verify_effect_ledger
from core.mutation import StateConflictError, TransitionError, commit_batch, recover_pending
from core.runtime import execute
from tests.test_m6_runtime import BrokenAdapter, GoodAdapter, setup_authority

ROOT = Path(__file__).resolve().parents[1]


class Crash(BaseException):
    """Simulated process death: not an Exception, so nothing in AIOS catches it."""


def _crash_on_replace(monkeypatch, n):
    real = mutation._replace
    calls = {"n": 0}

    def fake(src, dst):
        calls["n"] += 1
        if calls["n"] == n:
            raise Crash()
        return real(src, dst)
    monkeypatch.setattr(mutation, "_replace", fake)
    return lambda: monkeypatch.setattr(mutation, "_replace", real)


def _read(d, rel):
    with open(os.path.join(d, rel), encoding="utf-8") as fh:
        return json.load(fh)


class CountingAdapter:
    def __init__(self, inner, crash=False):
        self.inner, self.crash, self.calls = inner, crash, 0
        self.name = inner.name

    def execute(self, **kw):
        self.calls += 1
        if self.crash:
            raise Crash()  # process dies inside the provider call (after DISPATCHED commit)
        return self.inner.execute(**kw)


# ---------------------------------------------------------------- commit engine

@pytest.mark.parametrize("crash_at", [1, 2, 3])
def test_update_batch_is_all_or_nothing_at_every_crash_point(tmp_path, monkeypatch, crash_at):
    """D-L5-1: crash at journal publish (1), between replaces (2), before last replace (3)."""
    d = str(tmp_path)
    commit_batch(d, [("effects/A.json", {"v": 1})])
    restore = _crash_on_replace(monkeypatch, crash_at)
    with pytest.raises(Crash):
        commit_batch(d, [("effects/A.json", {"v": 2}), ("events/A-2.json", {"e": 2})])
    restore()
    recover_pending(d)
    a, ev = _read(d, "effects/A.json"), os.path.exists(os.path.join(d, "events/A-2.json"))
    if crash_at == 1:
        assert (a, ev) == ({"v": 1}, False)  # before commit point: discarded
    else:
        assert (a, ev) == ({"v": 2}, True)   # after commit point: rolled forward
    assert not os.listdir(os.path.join(d, ".staging"))


def test_torn_legacy_journal_is_discarded_not_wedged(tmp_path):
    """D-L5-2."""
    d = str(tmp_path)
    commit_batch(d, [("effects/A.json", {"v": 1})])
    torn = os.path.join(d, ".staging", "batch-legacy")
    os.makedirs(torn)
    Path(torn, "journal.json").write_text('{"batch_id": "x", "ops": [{"tm', encoding="utf-8")
    recover_pending(d)
    assert _read(d, "effects/A.json") == {"v": 1} and not os.path.exists(torn)


def test_commit_recovers_pending_batch_before_precondition(tmp_path, monkeypatch):
    """D-L5-3: a precondition never observes a half-applied batch."""
    d = str(tmp_path)
    commit_batch(d, [("effects/A.json", {"v": 1})])
    restore = _crash_on_replace(monkeypatch, 2)
    with pytest.raises(Crash):
        commit_batch(d, [("effects/A.json", {"v": 2}), ("events/A-2.json", {"e": 2})])
    restore()
    seen = {}
    commit_batch(d, [("effects/B.json", {})], precondition=lambda root: seen.update(
        a=_read(root, "effects/A.json"), ev=os.path.exists(os.path.join(root, "events/A-2.json"))))
    assert seen == {"a": {"v": 2}, "ev": True}


def test_corrupted_staged_file_fails_closed(tmp_path, monkeypatch):
    d = str(tmp_path)
    commit_batch(d, [("effects/A.json", {"v": 1})])
    restore = _crash_on_replace(monkeypatch, 2)
    with pytest.raises(Crash):
        commit_batch(d, [("effects/A.json", {"v": 2})])
    restore()
    (batch,) = os.listdir(os.path.join(d, ".staging"))
    journal = _read(d, os.path.join(".staging", batch, "journal.json"))
    Path(journal["ops"][0]["tmp"]).write_bytes(b'{"v": 666}\n')
    with pytest.raises(StateConflictError, match="staged file diverges"):
        recover_pending(d)
    assert _read(d, "effects/A.json") == {"v": 1}  # never applied unverified content


@pytest.mark.parametrize("crash_at", [1, 2, 3])
def test_real_process_death_mid_commit_then_restart(tmp_path, crash_at):
    """Genuine crash: child process calls os._exit inside the commit; parent restarts/recovers."""
    d = str(tmp_path / "aios")
    commit_batch(d, [("effects/A.json", {"v": 1})])
    child = textwrap.dedent(f"""
        import os, core.mutation as m
        real, n = m._replace, {{"n": 0}}
        def fake(s, t):
            n["n"] += 1
            if n["n"] == {crash_at}: os._exit(9)
            real(s, t)
        m._replace = fake
        m.commit_batch({d!r}, [("effects/A.json", {{"v": 2}}), ("events/A-2.json", {{"e": 2}})])
    """)
    proc = subprocess.run([sys.executable, "-c", child], cwd=str(ROOT), env={**os.environ, "PYTHONPATH": str(ROOT)})
    assert proc.returncode == 9
    recover_pending(d)
    expected = {"v": 1} if crash_at == 1 else {"v": 2}
    assert _read(d, "effects/A.json") == expected
    assert os.path.exists(os.path.join(d, "events/A-2.json")) == (crash_at != 1)


# ---------------------------------------------------------------- effect ledger

def test_ledger_consistent_and_append_only(tmp_path):
    c, cid, pid = setup_authority(tmp_path)
    result = execute(str(tmp_path), cid, pid, "op-1", "agent:test", GoodAdapter())
    eid = result["effect_id"]
    assert verify_effect_ledger(str(tmp_path), eid) == {
        "status": "CONSISTENT", "effect_id": eid, "state": "OBSERVED_SUCCESS", "attempt": 1, "events": 3}
    # Replaying the same commit (duplicate event) is rejected, never an overwrite.
    from core.effect_authority import _ledger_event, _expect_unchanged
    rel, ev = _ledger_event(eid, 1, "transition", "OBSERVED_SUCCESS")
    before = (tmp_path / rel).read_bytes()
    with pytest.raises(TransitionError):
        commit_batch(str(tmp_path), [(rel, ev)], precondition=_expect_unchanged(rel, None))
    assert (tmp_path / rel).read_bytes() == before


@pytest.mark.parametrize("tamper", ["projection_state", "delete_dispatch", "projection_attempt_id", "forged_event"])
def test_ledger_detects_tampering(tmp_path, tamper):
    c, cid, pid = setup_authority(tmp_path)
    eid = execute(str(tmp_path), cid, pid, "op-1", "agent:test", BrokenAdapter())["effect_id"]
    rec_path = tmp_path / _effect_rel(eid)
    rec = json.loads(rec_path.read_text())
    events = tmp_path / "events"
    if tamper == "projection_state":
        rec["state"] = "OBSERVED_SUCCESS"; rec_path.write_text(json.dumps(rec))  # UNKNOWN silently -> SUCCESS
    elif tamper == "projection_attempt_id":
        rec["attempt_id"] = "other"; rec_path.write_text(json.dumps(rec))
    elif tamper == "delete_dispatch":
        (events / f"effect-{eid}-a1-dispatch-DISPATCHED.json").unlink()
    else:
        (events / f"effect-{eid}-a1-transition-OBSERVED_SUCCESS.json").write_text(json.dumps(
            {"kind": "external_effect", "event_version": 2, "event_id": "forged", "action": "transition",
             "effect_id": eid, "attempt": 1, "to_state": "OBSERVED_SUCCESS"}))
    with pytest.raises(TransitionError):
        verify_effect_ledger(str(tmp_path), eid)


def test_legacy_effect_is_never_reported_consistent(tmp_path):
    c, cid, pid = setup_authority(tmp_path)
    eid = execute(str(tmp_path), cid, pid, "op-1", "agent:test", GoodAdapter())["effect_id"]
    for f in (tmp_path / "events").glob(f"effect-{eid}-a*.json"):
        f.unlink()  # simulate a store written by the pre-v2 engine
    assert verify_effect_ledger(str(tmp_path), eid)["status"] == "LEGACY_UNVERIFIABLE"


# ---------------------------------------------------------------- failure matrix (runtime)

def _effect(tmp_path, eid):
    return json.loads((tmp_path / _effect_rel(eid)).read_text())


def _only_effect_id(tmp_path):
    (path,) = list((tmp_path / "effects").glob("*.json"))
    return path.stem


def test_F1_crash_before_dispatch_commit_point_dispatches_once_on_restart(tmp_path, monkeypatch):
    c, cid, pid = setup_authority(tmp_path)
    adapter = CountingAdapter(GoodAdapter())
    # create_effect is batch 1 (one replace for its journal + 2 ops); dispatch journal publish is replace #4.
    restore = _crash_on_replace(monkeypatch, 4)
    with pytest.raises(Crash):
        execute(str(tmp_path), cid, pid, "op-1", "agent:test", adapter)
    restore()
    eid = _only_effect_id(tmp_path)
    recover_pending(str(tmp_path))
    assert _effect(tmp_path, eid)["state"] == "PLANNED" and adapter.calls == 0
    assert execute(str(tmp_path), cid, pid, "op-1", "agent:test", adapter)["state"] == "OBSERVED_SUCCESS"
    assert adapter.calls == 1
    assert verify_effect_ledger(str(tmp_path), eid)["status"] == "CONSISTENT"


@pytest.mark.parametrize("crash_at", [5, 6])
def test_F2_crash_during_dispatch_commit_rolls_forward_and_never_redispatches(tmp_path, monkeypatch, crash_at):
    c, cid, pid = setup_authority(tmp_path)
    adapter = CountingAdapter(GoodAdapter())
    restore = _crash_on_replace(monkeypatch, crash_at)
    with pytest.raises(Crash):
        execute(str(tmp_path), cid, pid, "op-1", "agent:test", adapter)
    restore()
    eid = _only_effect_id(tmp_path)
    recover_pending(str(tmp_path))
    assert _effect(tmp_path, eid)["state"] == "DISPATCHED"
    with pytest.raises(Exception):
        execute(str(tmp_path), cid, pid, "op-1", "agent:test", adapter)
    assert adapter.calls == 0 and _effect(tmp_path, eid)["state"] == "DISPATCHED"
    assert verify_effect_ledger(str(tmp_path), eid)["state"] == "DISPATCHED"


def test_F3_crash_inside_provider_call_is_never_replayed_or_promoted(tmp_path):
    c, cid, pid = setup_authority(tmp_path)
    adapter = CountingAdapter(GoodAdapter(), crash=True)
    with pytest.raises(Crash):
        execute(str(tmp_path), cid, pid, "op-1", "agent:test", adapter)
    eid = _only_effect_id(tmp_path)
    adapter.crash = False
    for _ in range(3):  # repeated restarts
        with pytest.raises(Exception):
            execute(str(tmp_path), cid, pid, "op-1", "agent:test", adapter)
    assert adapter.calls == 1
    assert _effect(tmp_path, eid)["state"] == "DISPATCHED"  # ambiguous; not SUCCESS


def test_F6_unknown_is_never_redispatched_or_promoted_on_restart(tmp_path):
    c, cid, pid = setup_authority(tmp_path)
    broken = CountingAdapter(BrokenAdapter())
    assert execute(str(tmp_path), cid, pid, "op-1", "agent:test", broken)["state"] == "UNKNOWN"
    good = CountingAdapter(GoodAdapter())
    for _ in range(3):
        with pytest.raises(Exception):
            execute(str(tmp_path), cid, pid, "op-1", "agent:test", good)
    eid = _only_effect_id(tmp_path)
    assert (broken.calls, good.calls) == (1, 0)
    assert verify_effect_ledger(str(tmp_path), eid)["state"] == "UNKNOWN"


def test_crash_during_observe_commit_keeps_dispatched_or_rolls_forward(tmp_path, monkeypatch):
    """F4 (L5 side): receipt commit is atomic -- either still DISPATCHED or OBSERVED with its event."""
    for crash_at, expected in ((7, "DISPATCHED"), (8, "OBSERVED_SUCCESS")):
        root = tmp_path / str(crash_at)
        root.mkdir()
        c, cid, pid = setup_authority(root)
        restore = _crash_on_replace(monkeypatch, crash_at)
        with pytest.raises(Crash):
            execute(str(root), cid, pid, "op-1", "agent:test", GoodAdapter())
        restore()
        eid = _only_effect_id(root)
        recover_pending(str(root))
        assert verify_effect_ledger(str(root), eid)["state"] == expected


@pytest.mark.parametrize("step", ["create", "dispatch", "unknown"])
def test_existing_event_file_is_never_overwritten(tmp_path, step):
    """Contract 3.6: every effect event is create-only, independent of the projection CAS."""
    from core.effect_authority import _id, create_effect, dispatch, unknown
    c, cid, pid = setup_authority(tmp_path)
    eid = _id(cid, "op-1", "agent:test")
    names = {"create": "a0-create-PLANNED", "dispatch": "a1-dispatch-DISPATCHED", "unknown": "a1-transition-UNKNOWN"}
    planted = tmp_path / "events" / f"effect-{eid}-{names[step]}.json"
    steps = [lambda: create_effect(str(tmp_path), cid, "op-1", "agent:test", pid, "external_effect"),
             lambda: dispatch(str(tmp_path), eid, "agent:test", f"{eid}:attempt:1", "fake-provider"),
             lambda: unknown(str(tmp_path), eid, "agent:test", "timeout")]
    stop = list(names).index(step)
    for run_step in steps[:stop]:
        run_step()
    planted.parent.mkdir(exist_ok=True)
    planted.write_text('{"planted": true}')
    with pytest.raises(TransitionError):
        steps[stop]()
    assert json.loads(planted.read_text()) == {"planted": True}
