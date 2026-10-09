# AIOS-CONTRACT: WAL-backed state persistence and recovery boundary
# AIOS-REGRESSION: Prevent stale or missing snapshots from losing durable state
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Covers WAL-authoritative recovery and UNKNOWN preservation
# AIOS-BASELINE: Tests target the existing durable state-store baseline

from pathlib import Path

import pytest

from core.durable_wal import DurableWalIntegrityError
from core.wal_state_store import WalStateStore


def test_wal_state_store_recovers_state_when_snapshot_is_missing(tmp_path):
    snapshot = tmp_path / ".aios" / "state.json"
    wal_path = tmp_path / ".aios" / "durable" / "wal.jsonl"
    store = WalStateStore(str(snapshot), str(wal_path))
    state = {"step": 2, "status": "RUNNING", "history": [{"step": 2}]}

    store.save(state)
    snapshot.unlink()

    assert store.load() == state


def test_wal_state_store_uses_latest_wal_commit_over_stale_snapshot(tmp_path):
    snapshot = tmp_path / "state.json"
    wal_path = tmp_path / "wal.jsonl"
    store = WalStateStore(str(snapshot), str(wal_path))

    first = {"step": 1, "status": "RUNNING", "history": []}
    second = {"step": 2, "status": "RUNNING", "history": [{"step": 2}]}
    store.save(first)
    store.save(second)
    snapshot.write_text('{"step":1,"status":"RUNNING","history":[]}\n', encoding="utf-8")

    assert store.load() == second


def test_wal_state_store_fails_closed_on_non_tail_corruption(tmp_path):
    snapshot = tmp_path / "state.json"
    wal_path = tmp_path / "wal.jsonl"
    store = WalStateStore(str(snapshot), str(wal_path))
    store.save({"step": 1, "status": "RUNNING", "history": []})
    store.save({"step": 2, "status": "RUNNING", "history": []})

    lines = wal_path.read_bytes().splitlines(keepends=True)
    lines[0] = b'{"corrupt":true}\n'
    wal_path.write_bytes(b"".join(lines))

    with pytest.raises(DurableWalIntegrityError):
        store.load()


def test_wal_state_store_does_not_turn_wal_into_execution_receipt(tmp_path):
    store = WalStateStore(str(tmp_path / "state.json"), str(tmp_path / "wal.jsonl"))
    store.save({
        "step": 1,
        "status": "RUNNING",
        "receipt": {
            "effect_id": "e1",
            "attempt_id": "A1",
            "status": "UNKNOWN",
            "evidence": {"source": "test"},
        },
    })

    recovered = store.load()
    assert recovered["receipt"]["status"] == "UNKNOWN"

def test_wal_state_store_recovers_after_process_death_between_wal_and_snapshot(tmp_path):
    import os
    import subprocess
    import sys

    snapshot = tmp_path / "state.json"
    wal_path = tmp_path / "wal.jsonl"
    store = WalStateStore(str(snapshot), str(wal_path))
    first = {"step": 1, "status": "RUNNING", "history": []}
    second = {"step": 2, "status": "RUNNING", "history": [{"step": 2}]}
    store.save(first)

    child_code = (
        "import os; "
        "from core.wal_state_store import WalStateStore; "
        f"s=WalStateStore({str(snapshot)!r}, {str(wal_path)!r}); "
        "s._write_snapshot=lambda state: os._exit(77); "
        f"s.save({second!r})"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.getcwd()
    child = subprocess.run([sys.executable, "-c", child_code], env=env)

    assert child.returncode == 77
    assert snapshot.exists()
    assert store.load() == second


def test_snapshot_replace_fsyncs_parent_directory(tmp_path, monkeypatch):
    import core.wal_state_store as state_store

    snapshot = tmp_path / "state.json"
    store = WalStateStore(str(snapshot), str(tmp_path / "wal.jsonl"))
    calls = []
    original = state_store._fsync_parent_dir

    def checked_fsync_parent(path):
        assert snapshot.exists()
        assert snapshot.read_text(encoding="utf-8").strip() == '{"status":"RUNNING"}'
        calls.append(path)
        original(path)

    monkeypatch.setattr(state_store, "_fsync_parent_dir", checked_fsync_parent)
    store._write_snapshot({"status": "RUNNING"})
    assert calls == [snapshot]
