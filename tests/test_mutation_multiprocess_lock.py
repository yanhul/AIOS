"""Cross-process serialization and compare-and-swap tests for the mutation boundary."""
import multiprocessing
import os

from core.mutation import TransitionError, commit_batch


def _must_not_exist(aios_dir):
    if os.path.exists(os.path.join(aios_dir, "race", "winner.json")):
        raise TransitionError("another process already committed the winner")


def _competing_writer(aios_dir, barrier, queue, label):
    barrier.wait()
    try:
        commit_batch(
            aios_dir,
            [("race/winner.json", {"writer": label})],
            precondition=_must_not_exist,
        )
        queue.put("committed")
    except TransitionError:
        queue.put("rejected")


def test_os_lock_serializes_competing_processes_and_cas_allows_one_winner(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(2)
    queue = ctx.Queue()
    workers = [
        ctx.Process(target=_competing_writer, args=(str(tmp_path), barrier, queue, f"writer-{i}"))
        for i in range(2)
    ]
    for worker in workers:
        worker.start()
    results = [queue.get(timeout=20) for _ in workers]
    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0
    assert sorted(results) == ["committed", "rejected"]
    import json
    record = json.loads((tmp_path / "race" / "winner.json").read_text(encoding="utf-8"))
    assert record["writer"] in {"writer-0", "writer-1"}
