# AIOS-CONTRACT: L5 commit state lives in protected .l5/state.json (F-03/F-04 P0). A journal is executed only
#   when its bytes match the digest recorded there; corrupt/legacy/untracked residue is quarantined and blocks.
# AIOS-REGRESSION: Unparseable journals treated as uncommitted (silent loss of committed batches).
# AIOS-OWNER: AIOS control-plane effect ledger (L5)
# AIOS-COVERAGE-GAP: Torn/corrupt v2 and legacy journals, diverging staged files, quarantine resolution.
# AIOS-BASELINE: Extends tests/test_l5_event_ledger.py.
"""Phase 4 part 1: journal commit-state classification, quarantine, fail-closed recovery."""
import json
import os
from pathlib import Path

import pytest

import core.mutation as mutation
from core.mutation import LedgerBlockedError, commit_batch, recover_pending, unresolved_quarantine


class Crash(BaseException):
    pass


def _crash_at(monkeypatch, n):
    real, calls = mutation._replace, {"n": 0}

    def fake(src, dst, **kw):
        calls["n"] += 1
        if calls["n"] == n:
            raise Crash()
        return real(src, dst, **kw)
    monkeypatch.setattr(mutation, "_replace", fake)
    return lambda: monkeypatch.setattr(mutation, "_replace", real)


def _read(d, rel):
    return json.loads(Path(d, rel).read_text(encoding="utf-8"))


def _crashed_update(tmp_path, monkeypatch, crash_at):
    d = str(tmp_path)
    commit_batch(d, [("effects/A.json", {"v": 1}), ("effects/B.json", {"v": 1})])
    restore = _crash_at(monkeypatch, crash_at)
    with pytest.raises(Crash):
        commit_batch(d, [("effects/A.json", {"v": 2}), ("effects/B.json", {"v": 2})])
    restore()
    (batch,) = os.listdir(os.path.join(d, ".staging"))
    return d, Path(d, ".staging", batch)


def _state(d):
    return _read(d, "effects/A.json"), _read(d, "effects/B.json")


def _l5(d):
    return _read(d, ".l5/state.json")


def test_crash_before_commit_point_is_aborted_without_quarantine(tmp_path, monkeypatch):
    """Crash at journal publication (_replace #1): state is PREPARED, no
    destination was written, so recovery aborts the batch."""
    d, batch = _crashed_update(tmp_path, monkeypatch, 1)
    assert _l5(d)["phase"] == "PREPARED"
    (batch / "journal.v3.json.tmp").write_text("{garbage", encoding="utf-8")  # existing 0600 inode
    recover_pending(d)
    assert _state(d) == ({"v": 1}, {"v": 1}) and not batch.exists() and unresolved_quarantine(d) == []
    st = _l5(d)
    assert st["phase"] == "IDLE" and st["next_seq"] == 3 and st["last_finalized_seq"] == 1  # seq 2 burned


@pytest.mark.parametrize("corruption", ["truncate", "flip_digest", "drop_op", "not_json"])
def test_journal_corruption_after_commit_is_quarantined_and_blocks(tmp_path, monkeypatch, corruption):
    d, batch = _crashed_update(tmp_path, monkeypatch, 2)  # committed, nothing replaced yet
    jpath = batch / "journal.v3.json"
    raw = jpath.read_bytes()
    journal = json.loads(raw)
    if corruption == "truncate":
        jpath.write_bytes(raw[: len(raw) // 2])
    elif corruption == "flip_digest":
        journal["ops"][0]["new"] = "0" * 64
        jpath.write_text(mutation.canonical_json(journal), encoding="utf-8")
    elif corruption == "drop_op":
        journal["ops"] = journal["ops"][:1]
        jpath.write_text(mutation.canonical_json(journal), encoding="utf-8")
    else:
        jpath.write_bytes(b"\x00\xff")
    with pytest.raises(LedgerBlockedError, match="COMMITTED_JOURNAL_UNTRUSTED"):
        recover_pending(d)
    qid = _l5(d)["txn"]["quarantine_id"]
    wrapper = Path(d, ".quarantine", qid)
    assert (wrapper / "QUARANTINE.json").exists() and (wrapper / "evidence" / "journal.v3.json").exists()
    assert len([f for f in os.listdir(wrapper / "evidence") if f.endswith(".tmp")]) == 2  # staged evidence kept
    assert _state(d) == ({"v": 1}, {"v": 1})  # nothing guessed
    with pytest.raises(LedgerBlockedError, match="quarantined"):
        commit_batch(d, [("effects/C.json", {})])
    with pytest.raises(LedgerBlockedError):
        recover_pending(d)


def test_operator_resolution_unblocks(tmp_path, monkeypatch):
    d, batch = _crashed_update(tmp_path, monkeypatch, 2)
    (batch / "journal.v3.json").write_text("{", encoding="utf-8")
    with pytest.raises(LedgerBlockedError):
        recover_pending(d)
    qid = _l5(d)["txn"]["quarantine_id"]
    Path(d, ".quarantine", qid, "RESOLVED.json").write_text('{"by": "operator"}', encoding="utf-8")
    commit_batch(d, [("effects/C.json", {"ok": True})])
    assert _read(d, "effects/C.json") == {"ok": True}
    assert _l5(d)["phase"] == "IDLE"


@pytest.mark.parametrize("which", [0, 1])
def test_missing_staged_file_after_commit_is_quarantined(tmp_path, monkeypatch, which):
    d, batch = _crashed_update(tmp_path, monkeypatch, 2)
    journal = json.loads((batch / "journal.v3.json").read_bytes())
    os.unlink(batch / journal["ops"][which]["src"])  # lost staged file; destination still old
    with pytest.raises(LedgerBlockedError, match="ROLL_FORWARD_REJECTED"):
        recover_pending(d)
    assert _state(d) == ({"v": 1}, {"v": 1})  # all-or-nothing: the valid op is NOT applied either


@pytest.mark.parametrize("crash_at", [2, 3])  # replace #1 = journal publish, #2/#3 = ops
def test_crash_between_replaces_rolls_forward_completely(tmp_path, monkeypatch, crash_at):
    d, _ = _crashed_update(tmp_path, monkeypatch, crash_at)
    recover_pending(d)
    assert _state(d) == ({"v": 2}, {"v": 2})


def test_crash_during_recovery_itself_is_idempotent(tmp_path, monkeypatch):
    d, _ = _crashed_update(tmp_path, monkeypatch, 2)
    restore = _crash_at(monkeypatch, 2)  # recovery replaces op 1, dies before op 2
    with pytest.raises(Crash):
        recover_pending(d)
    restore()
    recover_pending(d)
    assert _state(d) == ({"v": 2}, {"v": 2})


def test_legacy_journal_is_never_rolled_forward(tmp_path):
    """Audit F03-2: a legacy (pre-v3, unauthenticated) journal is a downgrade
    vector. It is quarantined as untracked evidence and never executed."""
    d = str(tmp_path)
    commit_batch(d, [("effects/A.json", {"v": 1})])
    batch = Path(d, ".staging", "batch-legacy")
    batch.mkdir(mode=0o700)
    payload = (mutation.canonical_json({"v": 2}) + "\n").encode()
    tmp = batch / "x.tmp"
    tmp.write_bytes(payload)
    (batch / "journal.json").write_text(json.dumps({"batch_id": "legacy", "ops": [
        {"tmp": str(tmp), "dest": str(Path(d, "effects", "A.json")), "digest": mutation._digest_bytes(payload)}]}))
    with pytest.raises(LedgerBlockedError, match="untracked staging entries"):
        recover_pending(d)
    assert _read(d, "effects/A.json") == {"v": 1}
    assert [q for q in unresolved_quarantine(d) if q.startswith("batch-legacy~")]


def test_cas_still_enforced_after_hardening(tmp_path):
    from core.effect_authority import _expect_unchanged
    from core.mutation import TransitionError
    d = str(tmp_path)
    commit_batch(d, [("effects/A.json", {"v": 1})])
    with pytest.raises(TransitionError):
        commit_batch(d, [("effects/A.json", {"v": 3})], precondition=_expect_unchanged("effects/A.json", {"v": 0}))
    assert _read(d, "effects/A.json") == {"v": 1}
