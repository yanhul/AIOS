# AIOS-CONTRACT: WAL, lock and snapshot I/O is descriptor-relative and confined to one trusted root
# AIOS-REGRESSION: Prevent symlink/FIFO/hard-link/parent-swap redirection of WAL, lock and snapshot I/O
# AIOS-OWNER: AIOS control-plane durable persistence
# AIOS-COVERAGE-GAP: Batch 3 adversarial filesystem tests (real filesystem, no mocked primitives)
# AIOS-BASELINE: Batch 3 secure WAL / snapshot / reconciliation
import json
import os
import subprocess
import sys
import threading
import time

import pytest

import core.durable_wal as durable_wal
import core.reconcile as rcn
import core.wal_state_store as state_store
from core.durable_wal import (
    DurableTransitionLog, DurableWalIntegrityError, DurableWalSecurityError,
)
from core.governed_memory import persist_memory
from core.mutation import _MutationLock, apply_mutations
from core.secure_fs import SecureWriteError
from core.wal_state_store import StoreRootMismatchError, WalStateStore

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-relative I/O")
pytestmark = posix_only

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def env(tmp_path):
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    ext = tmp_path / "external"
    ext.mkdir()
    victim = ext / "victim.txt"
    victim.write_bytes(b"EXTERNAL-ORIGINAL\n")
    return root, ext, victim


def _unchanged(victim):
    assert victim.read_bytes() == b"EXTERNAL-ORIGINAL\n"



def test_public_store_apis_cannot_write_memory_namespace(tmp_path):
    store = WalStateStore.for_aios_dir(str(tmp_path / "aios"))
    with pytest.raises(PermissionError, match="governed"):
        store.commit_namespace("memory", [])
    with pytest.raises(PermissionError, match="governed"):
        store.append_namespace("memory", {"mutation_id": "forged"})
    with pytest.raises(PermissionError, match="governed"):
        store.append_namespace_once(
            "memory", {"mutation_id": "forged"}, item_key="mutation_id",
            key_value="forged",
        )


def test_reconcile_detects_corrupt_memory_wal(tmp_path):
    root = tmp_path / "aios"
    root.mkdir()
    memory = root / "memory"
    memory.mkdir()
    (memory / "state.json.wal.jsonl").write_text('{"not":"a committed WAL record"}\n')
    result = rcn.reconcile(str(root))
    assert result["overall"] == "CORRUPTED"
    assert any(item["check"] == "M.memory_wal.integrity" for item in result["findings"])

# ------------------------------------------------------------------ WAL ----

def test_wal_symlink_to_external_file_refused(env):
    root, _, victim = env
    (root / "wal.jsonl").symlink_to(victim)
    wal = DurableTransitionLog(str(root / "wal.jsonl"))
    with pytest.raises(DurableWalSecurityError):
        wal.append(transition="T", payload={})
    with pytest.raises(DurableWalSecurityError):
        wal.replay()
    _unchanged(victim)


def test_wal_dangling_symlink_refused_and_target_not_created(env):
    root, ext, _ = env
    target = ext / "created-by-attacker"
    (root / "wal.jsonl").symlink_to(target)
    wal = DurableTransitionLog(str(root / "wal.jsonl"))
    with pytest.raises(DurableWalSecurityError):
        wal.append(transition="T", payload={})
    with pytest.raises(DurableWalSecurityError):
        wal.replay()  # never an empty WAL
    assert not target.exists()


def test_wal_fifo_refused_without_blocking(env):
    root, _, _ = env
    os.mkfifo(root / "wal.jsonl")
    wal = DurableTransitionLog(str(root / "wal.jsonl"))
    with pytest.raises(DurableWalSecurityError):
        wal.append(transition="T", payload={})
    with pytest.raises(DurableWalSecurityError):
        wal.replay()


def test_wal_hard_link_refused(env):
    root, _, victim = env
    os.link(victim, root / "wal.jsonl")
    wal = DurableTransitionLog(str(root / "wal.jsonl"))
    with pytest.raises(DurableWalSecurityError):
        wal.append(transition="T", payload={})
    with pytest.raises(DurableWalSecurityError):
        wal.replay()
    _unchanged(victim)


def test_wal_symlinked_parent_refused(env):
    root, ext, _ = env
    (root / "sub").symlink_to(ext, target_is_directory=True)
    nested = DurableTransitionLog(str(root / "sub" / "wal.jsonl"), root=str(root))
    with pytest.raises(DurableWalSecurityError):
        nested.append(transition="T", payload={})
    # Default root (= the WAL's parent) being a symlink is refused too.
    default = DurableTransitionLog(str(root / "sub" / "wal.jsonl"))
    with pytest.raises(DurableWalSecurityError):
        default.append(transition="T", payload={})
    assert sorted(os.listdir(ext)) == ["victim.txt"]


def test_wal_path_escape_and_traversal_refused(env):
    root, ext, _ = env
    with pytest.raises(DurableWalSecurityError):
        DurableTransitionLog(str(ext / "wal.jsonl"), root=str(root))
    with pytest.raises(DurableWalSecurityError):
        DurableTransitionLog(str(root) + "/../external/wal.jsonl", root=str(root))
    with pytest.raises(DurableWalSecurityError):
        DurableTransitionLog(str(root) + "/a/../wal.jsonl", root=str(root))


def test_wal_parent_replaced_during_append_never_writes_external(env, monkeypatch):
    root, ext, _ = env
    (root / "sub").mkdir(mode=0o700)
    wal = DurableTransitionLog(str(root / "sub" / "wal.jsonl"), root=str(root))
    wal.append(transition="T", payload={"n": 1})
    real = durable_wal.read_all_fd
    swapped = []

    def swap_then_read(fd):
        if not swapped:
            os.rename(root / "sub", root / "moved")
            (root / "sub").symlink_to(ext, target_is_directory=True)
            swapped.append(True)
        return real(fd)

    monkeypatch.setattr(durable_wal, "read_all_fd", swap_then_read)
    wal.append(transition="T", payload={"n": 2})
    # The held directory descriptor kept the write on the original inode.
    assert sorted(os.listdir(ext)) == ["victim.txt"]
    lines = (root / "moved" / "wal.jsonl").read_bytes().splitlines()
    assert [json.loads(x)["sequence"] for x in lines] == [1, 2]
    monkeypatch.setattr(durable_wal, "read_all_fd", real)
    with pytest.raises(DurableWalSecurityError):
        wal.append(transition="T", payload={"n": 3})
    assert sorted(os.listdir(ext)) == ["victim.txt"]


def test_wal_lock_symlink_refused(env):
    root, _, victim = env
    (root / "wal.jsonl.lock").symlink_to(victim)
    wal = DurableTransitionLog(str(root / "wal.jsonl"))
    with pytest.raises(DurableWalSecurityError):
        wal.append(transition="T", payload={})
    _unchanged(victim)
    assert not (root / "wal.jsonl").exists()


def test_wal_lock_hard_link_and_fifo_refused(env):
    root, _, victim = env
    os.link(victim, root / "wal.jsonl.lock")
    wal = DurableTransitionLog(str(root / "wal.jsonl"))
    with pytest.raises(DurableWalSecurityError):
        wal.replay()
    os.unlink(root / "wal.jsonl.lock")
    os.mkfifo(root / "wal.jsonl.lock")
    with pytest.raises(DurableWalSecurityError):
        wal.replay()
    _unchanged(victim)


def test_wal_lock_replaced_during_acquisition_is_retried(env, monkeypatch):
    root, _, _ = env
    wal = DurableTransitionLog(str(root / "wal.jsonl"))
    lock = root / "wal.jsonl.lock"
    real_flock = durable_wal.fcntl.flock
    calls = []

    def replacing_flock(fd, op):
        if op == durable_wal.fcntl.LOCK_EX:
            calls.append(op)
            if len(calls) == 1:
                os.rename(lock, root / "old.lock")  # split-inode attempt
        return real_flock(fd, op)

    monkeypatch.setattr(durable_wal.fcntl, "flock", replacing_flock)
    wal.append(transition="T", payload={})
    assert len(calls) == 2  # re-validated inode mismatch forced a retry
    assert [r["sequence"] for r in wal.replay().records] == [1]


def test_wal_lock_persistently_replaced_fails_closed(env, monkeypatch):
    root, _, _ = env
    wal = DurableTransitionLog(str(root / "wal.jsonl"))
    lock = root / "wal.jsonl.lock"
    real_flock = durable_wal.fcntl.flock

    def always_replace(fd, op):
        if op == durable_wal.fcntl.LOCK_EX:
            os.unlink(lock)
        return real_flock(fd, op)

    monkeypatch.setattr(durable_wal.fcntl, "flock", always_replace)
    with pytest.raises(DurableWalSecurityError, match="replaced"):
        wal.append(transition="T", payload={})
    assert not (root / "wal.jsonl").exists()


def test_wal_invalid_record_and_checksum_fail_closed_without_writing(env):
    root, _, _ = env
    path = root / "wal.jsonl"
    wal = DurableTransitionLog(str(path))
    wal.append(transition="T", payload={"a": 1})
    row = json.loads(path.read_bytes())
    row["checksum"] = "0" * 64
    path.write_bytes((json.dumps(row) + "\n").encode())
    before = path.read_bytes()
    with pytest.raises(DurableWalIntegrityError, match="checksum"):
        wal.replay()
    with pytest.raises(DurableWalIntegrityError):
        wal.append(transition="T", payload={})
    assert path.read_bytes() == before
    path.write_bytes(b"not json\n")
    with pytest.raises(DurableWalIntegrityError, match="invalid committed"):
        wal.replay()


def test_wal_tail_repair_truncates_only_validated_file(env):
    root, _, victim = env
    path = root / "wal.jsonl"
    wal = DurableTransitionLog(str(path))
    wal.append(transition="T", payload={"a": 1})
    good = path.read_bytes()
    with path.open("ab") as fh:
        fh.write(b'{"partial":')
    wal.append(transition="T", payload={"a": 2})
    assert path.read_bytes().startswith(good)
    assert [r["sequence"] for r in wal.replay().records] == [1, 2]
    # Same repair path aimed at an external file via symlink / hard link.
    victim.write_bytes(good + b'{"partial":')
    snapshot = victim.read_bytes()
    for make in (lambda p: p.symlink_to(victim), lambda p: os.link(victim, p)):
        target = root / "evil.jsonl"
        make(target)
        evil = DurableTransitionLog(str(target))
        with pytest.raises(DurableWalSecurityError):
            evil.append(transition="T", payload={})
        assert victim.read_bytes() == snapshot
        target.unlink()


def test_wal_concurrent_appenders_preserve_integrity_and_order(env):
    root, _, _ = env
    path = root / "wal.jsonl"
    script = (
        "import sys\n"
        "from core.durable_wal import DurableTransitionLog\n"
        "w = DurableTransitionLog(sys.argv[1])\n"
        "for i in range(25):\n"
        "    w.append(transition='T', payload={'worker': sys.argv[2], 'i': i})\n"
    )
    procs = [subprocess.Popen([sys.executable, "-c", script, str(path), str(n)], cwd=REPO)
             for n in range(4)]
    assert [p.wait(timeout=120) for p in procs] == [0, 0, 0, 0]
    records = DurableTransitionLog(str(path)).replay().records
    assert [r["sequence"] for r in records] == list(range(1, 101))
    seen = [(r["payload"]["worker"], r["payload"]["i"]) for r in records]
    assert len(set(seen)) == 100
    for worker in map(str, range(4)):
        assert [i for w, i in seen if w == worker] == list(range(25))


# ------------------------------------------------------------- snapshot ----

def test_snapshot_symlink_refused_for_write_and_load(env):
    root, _, victim = env
    (root / "state.json").symlink_to(victim)
    store = WalStateStore(str(root / "state.json"))
    with pytest.raises(SecureWriteError):
        store._write_snapshot({"x": 1})
    with pytest.raises(SecureWriteError):
        store.load()  # no WAL state: must not read or return external data
    _unchanged(victim)


def test_snapshot_dangling_symlink_refused(env):
    root, ext, _ = env
    target = ext / "planted.json"
    (root / "state.json").symlink_to(target)
    store = WalStateStore(str(root / "state.json"))
    with pytest.raises(SecureWriteError):
        store.load()
    with pytest.raises(SecureWriteError):
        store.save({"x": 1})
    assert not target.exists()


def test_snapshot_fifo_and_directory_refused(env):
    root, _, _ = env
    os.mkfifo(root / "state.json")
    store = WalStateStore(str(root / "state.json"))
    with pytest.raises(SecureWriteError):
        store.load()
    with pytest.raises(SecureWriteError):
        store._write_snapshot({"x": 1})
    os.unlink(root / "state.json")
    (root / "state.json").mkdir()
    with pytest.raises(SecureWriteError):
        store._write_snapshot({"x": 1})


def test_snapshot_hard_link_not_read(env):
    root, _, victim = env
    victim.write_bytes(b'{"forged": true}\n')
    os.link(victim, root / "state.json")
    store = WalStateStore(str(root / "state.json"))
    with pytest.raises(SecureWriteError):
        store.load()


def test_snapshot_symlinked_parent_refused(env):
    root, ext, _ = env
    (root / "sub").symlink_to(ext, target_is_directory=True)
    with pytest.raises(SecureWriteError):
        WalStateStore(str(root / "sub" / "state.json"), root=str(root))
    with pytest.raises(SecureWriteError):
        WalStateStore(str(root / "sub" / "state.json"))
    assert sorted(os.listdir(ext)) == ["victim.txt"]


def test_snapshot_temp_file_cannot_be_redirected(env, monkeypatch):
    root, _, victim = env
    store = WalStateStore(str(root / "state.json"))
    monkeypatch.setattr(state_store.secrets, "token_hex", lambda n: "fixed")
    planted = root / ".state.json.fixed.tmp"
    planted.symlink_to(victim)
    with pytest.raises(FileExistsError):
        store._write_snapshot({"x": 1})
    _unchanged(victim)
    assert planted.is_symlink()  # pre-existing entry is not ours to unlink


def test_snapshot_replace_failure_cleans_up_only_inside_root(env, monkeypatch):
    root, ext, victim = env
    store = WalStateStore(str(root / "state.json"))
    store._write_snapshot({"v": 1})

    def failing_replace(*a, **kw):
        raise OSError("injected replace failure")

    monkeypatch.setattr(state_store.os, "replace", failing_replace)
    with pytest.raises(OSError, match="injected"):
        store._write_snapshot({"v": 2})
    assert sorted(os.listdir(root)) == ["state.json"]  # temp unlinked
    assert json.loads((root / "state.json").read_text()) == {"v": 1}
    assert sorted(os.listdir(ext)) == ["victim.txt"]
    _unchanged(victim)


def test_mismatched_and_escaping_store_roots_rejected(env):
    root, ext, _ = env
    with pytest.raises(StoreRootMismatchError):
        WalStateStore(str(root / "state.json"), str(ext / "wal.jsonl"))
    with pytest.raises(StoreRootMismatchError):
        WalStateStore(str(root / "state.json"), str(root) + "/../external/wal.jsonl")
    with pytest.raises(StoreRootMismatchError):
        WalStateStore(str(ext / "state.json"), root=str(root))
    store = WalStateStore.for_aios_dir(str(root))
    store.assert_bound_to(str(root))
    with pytest.raises(StoreRootMismatchError):
        store.assert_bound_to(str(ext))
    store.wal = DurableTransitionLog(str(ext / "wal.jsonl"))
    with pytest.raises(StoreRootMismatchError):
        store.assert_bound_to(str(root))


def _entity(kind, eid):
    return {
        "entity_type": kind, "entity_id": eid,
        "statement": f"Test persisted {kind} {eid}", "status": "ACTIVE",
        "source_file": "test-fixture", "source_line": 1,
        "source_text": f"Test persisted {kind} {eid}",
        "classification": kind, "imported_at": "2026-10-09T00:00:00Z",
        "snapshot_id": "batch3-snapshot",
    }


def test_persist_memory_rejects_store_outside_trusted_root(tmp_path):
    from tests.test_governed_memory_durable import _authorization, _record, load_memory
    aios = tmp_path / "aios"
    auth = _authorization(str(aios))
    outside = WalStateStore(str(tmp_path / "elsewhere" / "state.json"))
    with pytest.raises(ValueError, match="not bound"):
        persist_memory(outside, _record(), decision_id="D-1", mutation_id="M-1",
                       authority="AIOS_CONTROL_PLANE", **auth)
    assert not outside.wal_path.exists()
    # A subdirectory root beneath aios_dir is still a different root.
    sub = WalStateStore(str(aios / "memory" / "state.json"))
    with pytest.raises(ValueError, match="not bound"):
        persist_memory(sub, _record(), decision_id="D-1", mutation_id="M-1",
                       authority="AIOS_CONTROL_PLANE", **auth)
    bound = WalStateStore.for_aios_dir(str(aios))
    persist_memory(bound, _record(), decision_id="D-1", mutation_id="M-1",
                   authority="AIOS_CONTROL_PLANE", **auth)
    assert len(load_memory(bound)) == 1
    rep = rcn.reconcile(str(aios))
    assert "memory" not in " ".join(f["detail"] for f in rep["findings"]), rep


def test_crash_between_wal_append_and_snapshot_recovers_from_wal(env):
    root, _, _ = env
    script = (
        "import os, sys\n"
        "from core.wal_state_store import WalStateStore\n"
        "class Crash(WalStateStore):\n"
        "    def _write_snapshot(self, state):\n"
        "        os._exit(91)\n"
        "s = Crash(sys.argv[1])\n"
        "s.save({'step': 2})\n"
    )
    store = WalStateStore(str(root / "state.json"))
    store.save({"step": 1})
    proc = subprocess.run([sys.executable, "-c", script, str(root / "state.json")], cwd=REPO)
    assert proc.returncode == 91
    assert json.loads((root / "state.json").read_text()) == {"step": 1}  # stale snapshot
    assert WalStateStore(str(root / "state.json")).load() == {"step": 2}
    assert not [n for n in os.listdir(root) if n.endswith(".tmp")]


# -------------------------------------------------------- reconciliation ----

@pytest.fixture
def seeded(tmp_path):
    aios = tmp_path / "aios"
    apply_mutations(str(aios), [_entity("DECISION", "D-1")], actor="test-setup")
    assert (aios / ".mutation.lock").is_file()
    return aios


def test_reconcile_acquires_lock_before_listing_root(seeded, monkeypatch):
    events = []
    real_lock, real_list = rcn._SharedReadLock, rcn.secure_listdir_beneath

    class RecordingLock(real_lock):
        def __enter__(self):
            result = super().__enter__()
            events.append(("lock", self.held))
            return result

    def recording_list(root, rel):
        if rel is None:
            events.append(("list", None))
        return real_list(root, rel)

    monkeypatch.setattr(rcn, "_SharedReadLock", RecordingLock)
    monkeypatch.setattr(rcn, "secure_listdir_beneath", recording_list)
    rep = rcn.reconcile(str(seeded))
    assert events[:2] == [("lock", True), ("list", None)]
    assert rep["synchronized"] is True and rep["overall"] == "VALID"


def test_reconcile_missing_lock_is_not_a_synchronized_success(seeded):
    os.unlink(seeded / ".mutation.lock")
    rep = rcn.reconcile(str(seeded))
    assert rep["synchronized"] is False
    assert rep["overall"] != "VALID"
    assert ("G.unsynchronized_sweep", "PENDING") in {(f["check"], f["severity"]) for f in rep["findings"]}


def test_reconcile_invalid_lock_is_not_a_synchronized_success(seeded, tmp_path):
    os.unlink(seeded / ".mutation.lock")
    (seeded / ".mutation.lock").symlink_to(tmp_path / "elsewhere")
    rep = rcn.reconcile(str(seeded))
    assert rep["synchronized"] is False
    assert rep["overall"] == "CORRUPTED"
    assert "G.unsafe_lock" in {f["check"] for f in rep["findings"]}
    assert not (tmp_path / "elsewhere").exists()


def test_reconcile_waits_for_concurrent_mutation_and_observes_after_it(seeded, monkeypatch):
    listed = threading.Event()
    real_list = rcn.secure_listdir_beneath

    def recording_list(root, rel):
        if rel is None:
            listed.set()
        return real_list(root, rel)

    monkeypatch.setattr(rcn, "secure_listdir_beneath", recording_list)
    result = {}
    with _MutationLock(str(seeded)):
        worker = threading.Thread(target=lambda: result.update(rcn.reconcile(str(seeded))))
        worker.start()
        time.sleep(0.5)
        assert worker.is_alive() and not listed.is_set()  # blocked before listing
        (seeded / "unexpected-during-mutation").mkdir()
    worker.join(timeout=30)
    assert not worker.is_alive()
    assert result["synchronized"] is True
    assert "G.unexpected_entry" in {f["check"] for f in result["findings"]}


def test_reconcile_reports_unsafe_entries_without_following(seeded, tmp_path):
    ext = tmp_path / "ext"
    ext.mkdir()
    (ext / "D-9.json").write_text("{}")
    (seeded / "requirements").rmdir()
    (seeded / "requirements").symlink_to(ext, target_is_directory=True)
    os.mkfifo(seeded / "decisions" / "D-2.json")
    rep = rcn.reconcile(str(seeded))
    assert rep["overall"] == "CORRUPTED"
    details = " ".join(f["detail"] for f in rep["findings"])
    assert "requirements" in details
    assert "D-9" not in details  # symlinked directory was not listed/followed
