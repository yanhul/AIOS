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
