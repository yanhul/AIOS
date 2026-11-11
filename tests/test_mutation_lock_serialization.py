import threading
import time

from core.mutation import _MutationLock


def test_mutation_lock_is_reentrant_and_serializes_threads(tmp_path):
    state = str(tmp_path / "aios")
    entered = threading.Event()
    order = []

    def first_writer():
        with _MutationLock(state):
            with _MutationLock(state):
                entered.set()
                time.sleep(0.05)
                order.append("first")

    def second_writer():
        assert entered.wait(timeout=2)
        with _MutationLock(state):
            order.append("second")

    first = threading.Thread(target=first_writer)
    second = threading.Thread(target=second_writer)
    first.start()
    second.start()
    first.join(timeout=3)
    second.join(timeout=3)

    assert not first.is_alive()
    assert not second.is_alive()
    assert order == ["first", "second"]
