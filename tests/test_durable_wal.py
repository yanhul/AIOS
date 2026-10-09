# AIOS-CONTRACT: durable append-only WAL sequencing, integrity, and tail recovery
# AIOS-REGRESSION: Prevent durable transition corruption from being silently accepted
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Covers WAL replay, truncation, corruption, and receipt boundary
# AIOS-BASELINE: Tests target the existing durable WAL contract baseline

from pathlib import Path

import pytest

from core.durable_wal import DurableTransitionLog, DurableWalIntegrityError


def test_wal_append_is_replayable_and_sequenced(tmp_path):
    wal = DurableTransitionLog(str(tmp_path / ".aios" / "durable" / "wal.jsonl"))
    first = wal.append(transition="ENQUEUED", payload={"workload_id": "w1"})
    second = wal.append(transition="STARTED", payload={"workload_id": "w1", "attempt_id": "A1"})

    replay = wal.replay()
    assert [r["sequence"] for r in replay.records] == [1, 2]
    assert [r["transition"] for r in replay.records] == ["ENQUEUED", "STARTED"]
    assert replay.dropped_tail_records == 0
    assert first["checksum"] != second["checksum"]


def test_wal_discards_only_a_truncated_final_record(tmp_path):
    path = Path(tmp_path / "wal.jsonl")
    wal = DurableTransitionLog(str(path))
    wal.append(transition="ENQUEUED", payload={"id": "w1"})
    with path.open("ab") as fh:
        fh.write(b'{"version":1,"sequence":2,"transition":"STARTED"')
        fh.flush()

    replay = wal.replay()
    assert len(replay.records) == 1
    assert replay.dropped_tail_records == 1

    wal.append(transition="STARTED", payload={"id": "w1"})
    replay = wal.replay()
    assert len(replay.records) == 2
    assert replay.records[-1]["sequence"] == 2
    assert replay.dropped_tail_records == 0


def test_wal_rejects_corruption_before_final_tail(tmp_path):
    path = Path(tmp_path / "wal.jsonl")
    wal = DurableTransitionLog(str(path))
    wal.append(transition="ENQUEUED", payload={"id": "w1"})
    wal.append(transition="STARTED", payload={"id": "w1"})
    lines = path.read_bytes().splitlines(keepends=True)
    lines[0] = b'{"corrupt":true}\n'
    path.write_bytes(b"".join(lines))

    with pytest.raises(DurableWalIntegrityError, match="checksum"):
        wal.replay()


def test_wal_append_once_serializes_duplicate_idempotency_keys(tmp_path):
    wal = DurableTransitionLog(str(tmp_path / "wal.jsonl"))
    first, appended = wal.append_once(
        transition="NAMESPACE_APPENDED",
        payload={"namespace": "memory", "item": {"mutation_id": "M-1", "value": 1}},
        unique_path=("item", "mutation_id"),
        unique_value="M-1",
        scope_path=("namespace",),
        scope_value="memory",
    )
    assert appended is True
    replay, appended = wal.append_once(
        transition="NAMESPACE_APPENDED",
        payload={"namespace": "memory", "item": {"mutation_id": "M-1", "value": 2}},
        unique_path=("item", "mutation_id"),
        unique_value="M-1",
        scope_path=("namespace",),
        scope_value="memory",
    )
    assert appended is False
    assert replay == first
    assert len(wal.replay().records) == 1


def test_wal_is_not_an_execution_receipt(tmp_path):
    wal = DurableTransitionLog(str(tmp_path / "wal.jsonl"))
    record = wal.append(
        transition="STARTED",
        payload={"effect_id": "e1", "attempt_id": "A1"},
    )
    assert record["transition"] == "STARTED"
    assert record["payload"]["effect_id"] == "e1"
    assert "status" not in record
