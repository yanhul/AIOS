import os
import threading
from pathlib import Path

import pytest

from core import mutation


def test_commit_batch_serializes_concurrent_writers(tmp_path):
    aios_dir = str(tmp_path)
    barrier = threading.Barrier(2)
    errors = []

    def writer(i):
        try:
            barrier.wait(timeout=5)
            mutation.commit_batch(
                aios_dir,
                [(os.path.join("events", f"concurrent-{i}.json"), {"i": i})],
            )
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not any(t.is_alive() for t in threads)
    assert errors == []
    assert (Path(aios_dir) / "events" / "concurrent-0.json").exists()
    assert (Path(aios_dir) / "events" / "concurrent-1.json").exists()
    assert not list((Path(aios_dir) / ".staging").glob("batch-*"))


def test_recovery_and_commit_share_serialization_domain(tmp_path, monkeypatch):
    aios_dir = str(tmp_path)
    original_replace = mutation._replace
    calls = {"n": 0}

    def fail_once(src, dst):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("injected mid-commit failure")
        return original_replace(src, dst)

    monkeypatch.setattr(mutation, "_replace", fail_once)
    with pytest.raises(OSError, match="injected"):
        mutation.commit_batch(
            aios_dir,
            [
                ("events/recover-a.json", {"a": 1}),
                ("events/recover-b.json", {"b": 2}),
            ],
        )

    # The journal remains after the injected failure. Recovery is itself
    # serialized by the same mutation lock and must roll the batch forward.
    monkeypatch.setattr(mutation, "_replace", original_replace)
    mutation.recover_pending(aios_dir)

    assert (Path(aios_dir) / "events" / "recover-a.json").exists()
    assert (Path(aios_dir) / "events" / "recover-b.json").exists()
    assert not list((Path(aios_dir) / ".staging").glob("batch-*"))


def _entity(entity_id, statement):
    return {
        "entity_type": "EVIDENCE",
        "entity_id": entity_id,
        "statement": statement,
        "status": "NEW",
        "source_file": "test.md",
        "source_line": 1,
        "source_text": statement,
        "classification": "EVIDENCE",
        "imported_at": "2026-09-18T00:00:00Z",
        "snapshot_id": "snapshot-1",
    }


def test_concurrent_same_entity_mutation_cannot_overwrite(tmp_path):
    aios_dir = str(tmp_path)
    barrier = threading.Barrier(2)
    results = []
    errors = []

    def writer(statement):
        try:
            barrier.wait(timeout=5)
            result = mutation.apply_mutations(
                aios_dir, [_entity("EV-9001", statement)], "race-test"
            )
            results.append(result)
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=writer, args=("first",)),
        threading.Thread(target=writer, args=("second",)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not any(t.is_alive() for t in threads)
    assert len(results) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], mutation.TransitionError)

    path = Path(aios_dir) / "evidence" / "EV-9001.json"
    assert path.exists()
    with path.open("r", encoding="utf-8") as fh:
        persisted = __import__("json").load(fh)
    assert persisted["statement"] in {"first", "second"}
    assert persisted["source_text"] == persisted["statement"]


def test_semantic_mutation_failure_recovers_without_partial_same_entity_state(
    tmp_path, monkeypatch
):
    aios_dir = str(tmp_path)
    original_replace = mutation._replace
    calls = {"n": 0}

    def fail_once(src, dst):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("injected semantic mutation failure")
        return original_replace(src, dst)

    monkeypatch.setattr(mutation, "_replace", fail_once)
    with pytest.raises(OSError, match="injected semantic mutation failure"):
        mutation.apply_mutations(
            aios_dir,
            [_entity("EV-9002", "entity payload")],
            "failure-test",
        )

    # The first rename may have committed before the injected failure; the
    # journal must make the entire durable batch recoverable under the same
    # serialization domain.
    monkeypatch.setattr(mutation, "_replace", original_replace)
    mutation.recover_pending(aios_dir)

    entity_path = Path(aios_dir) / "evidence" / "EV-9002.json"
    event_files = list((Path(aios_dir) / "events").glob("*.json"))
    assert entity_path.exists()
    assert event_files
    assert not list((Path(aios_dir) / ".staging").glob("batch-*"))

    with entity_path.open("r", encoding="utf-8") as fh:
        persisted = __import__("json").load(fh)
    assert persisted["entity_id"] == "EV-9002"
