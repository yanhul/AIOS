import multiprocessing
import time

from core.mutation import _MutationLock


def _process_writer(state, trace, label, ready, release):
    ready.set()
    if not release.wait(timeout=5):
        raise RuntimeError("test barrier timed out")
    with _MutationLock(state):
        with open(trace, "a", encoding="utf-8") as stream:
            stream.write(label + ":enter\n")
            stream.flush()
        time.sleep(0.1)
        with open(trace, "a", encoding="utf-8") as stream:
            stream.write(label + ":exit\n")
            stream.flush()


def test_mutation_lock_serializes_independent_processes(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    state = str(tmp_path / "aios")
    trace = str(tmp_path / "trace.txt")
    ready_a, ready_b, release = ctx.Event(), ctx.Event(), ctx.Event()
    a = ctx.Process(target=_process_writer, args=(state, trace, "a", ready_a, release))
    b = ctx.Process(target=_process_writer, args=(state, trace, "b", ready_b, release))
    a.start()
    b.start()
    assert ready_a.wait(timeout=5)
    assert ready_b.wait(timeout=5)
    release.set()
    a.join(timeout=8)
    b.join(timeout=8)
    if a.is_alive():
        a.terminate()
        a.join()
    if b.is_alive():
        b.terminate()
        b.join()
    assert a.exitcode == 0
    assert b.exitcode == 0
    lines = open(trace, encoding="utf-8").read().splitlines()
    assert len(lines) == 4
    assert lines[0].endswith(":enter")
    assert lines[1] == lines[0].replace(":enter", ":exit")
    assert lines[2].endswith(":enter")
    assert lines[3] == lines[2].replace(":enter", ":exit")
