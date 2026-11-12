"""Regression tests for PR #128 secure filesystem findings (F1-F7).

Every test asserts the unsafe operation fails closed AND that files outside
the state root are untouched. POSIX-only primitives (symlink, mkfifo, flock)
are skipped only on platforms that lack them; security failures never skip.
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import threading
import time

import pytest

from core import mutation, secure_fs
from core.mutation import (
    MutationError, StateConflictError, apply_mutations, recover_pending,
    _MutationLock,
)
from core.secure_fs import SecureWriteError, UnsupportedPlatformError

POSIX = os.name == "posix"
posix_only = pytest.mark.skipif(not POSIX, reason="POSIX symlink/FIFO/flock semantics")
fifo_only = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="os.mkfifo unavailable")
ACTOR = "test:secure-hardening"


def entity(eid="R-1"):
    return {
        "entity_type": "REQUIREMENT", "entity_id": eid, "statement": "s",
        "status": "OPEN", "source_file": "r.md", "source_line": 1,
        "source_text": "| R-1 |", "classification": "REQUIREMENT",
        "imported_at": "2026-08-23T00:00:00Z", "snapshot_id": "snap",
    }


def canon(obj):
    return (mutation.canonical_json(obj) + "\n").encode()


@pytest.fixture(autouse=True)
def _no_hang():
    """FIFO handling must never block; fail rather than hang the suite."""
    if not hasattr(signal, "SIGALRM"):
        yield
        return
    def boom(*_):
        raise AssertionError("operation blocked (possible FIFO open without O_NONBLOCK)")
    old = signal.signal(signal.SIGALRM, boom)
    signal.alarm(20)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


@pytest.fixture
def roots(tmp_path):
    state = tmp_path / ".aios"
    outside = tmp_path / "outside"
    outside.mkdir()
    return state, outside


# --- 1 / 10: entity / destination symlinks (F1, F3) -------------------------

@posix_only
def test_entity_symlink_outside_root_is_conflict_not_replay(roots):
    state, outside = roots
    target = outside / "R-1.json"
    target.write_bytes(canon(entity()))  # identical content: must still refuse
    (state / "requirements").mkdir(parents=True)
    (state / "requirements" / "R-1.json").symlink_to(target)
    before = target.read_bytes()
    with pytest.raises(StateConflictError):
        apply_mutations(state, [entity()], ACTOR)
    assert target.read_bytes() == before
    assert sorted(os.listdir(outside)) == ["R-1.json"]


@posix_only
def test_dangling_destination_symlink_is_conflict_and_creates_nothing(roots):
    state, outside = roots
    (state / "requirements").mkdir(parents=True)
    (state / "requirements" / "R-1.json").symlink_to(outside / "created.json")
    with pytest.raises(StateConflictError):
        apply_mutations(state, [entity()], ACTOR)
    assert list(outside.iterdir()) == []


@posix_only
def test_symlinked_entity_parent_dir_is_conflict(roots):
    state, outside = roots
    state.mkdir()
    (state / "requirements").symlink_to(outside, target_is_directory=True)
    with pytest.raises(MutationError):
        apply_mutations(state, [entity()], ACTOR)
    assert list(outside.iterdir()) == []


@posix_only
def test_load_existing_refuses_symlink_directly(roots):
    state, outside = roots
    (outside / "x.json").write_text("{}")
    (state / "requirements").mkdir(parents=True)
    (state / "requirements" / "R-1.json").symlink_to(outside / "x.json")
    with pytest.raises(StateConflictError):
        mutation._load_existing(state, "requirements/R-1.json")


# --- 4: FIFO / special file as entity (F1, F3, F4) --------------------------

@fifo_only
def test_fifo_entity_is_refused_without_blocking(roots):
    state, _ = roots
    (state / "requirements").mkdir(parents=True)
    os.mkfifo(state / "requirements" / "R-1.json")
    with pytest.raises(StateConflictError):
        apply_mutations(state, [entity()], ACTOR)
    with pytest.raises(StateConflictError):
        mutation._load_existing(state, "requirements/R-1.json")


@fifo_only
def test_secure_read_refuses_fifo_and_directory(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    (tmp_path / "d").mkdir()
    with pytest.raises(SecureWriteError):
        secure_fs.secure_read_bytes_beneath(tmp_path, "pipe")
    with pytest.raises(SecureWriteError):
        secure_fs.secure_read_bytes_beneath(tmp_path, "d")


def test_secure_read_missing_is_filenotfound_not_security_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        secure_fs.secure_read_bytes_beneath(tmp_path, "missing")
    assert secure_fs.secure_regular_file_state_beneath(tmp_path, "a/b/missing") is False


@posix_only
def test_secure_read_does_not_leak_descriptors(tmp_path, roots):
    _, outside = roots
    (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    fd_dir = "/proc/self/fd"
    if not os.path.isdir(fd_dir):
        pytest.skip("no /proc/self/fd to count descriptors")
    before = len(os.listdir(fd_dir))
    for _ in range(50):
        with pytest.raises((SecureWriteError, OSError)):
            secure_fs.secure_read_bytes_beneath(tmp_path, "link/x")
        with pytest.raises(FileNotFoundError):
            secure_fs.secure_read_bytes_beneath(tmp_path, "nope/x")
    assert len(os.listdir(fd_dir)) == before


# --- 2 / 3: event directory / event file symlinks (F2) ----------------------

def _committed(state):
    apply_mutations(state, [entity()], ACTOR)
    events = state / "events"
    names = sorted(os.listdir(events))
    assert len(names) == 1
    return events, names[0]


@posix_only
def test_event_directory_symlink_fails_closed_on_replay(roots):
    state, outside = roots
    events, name = _committed(state)
    os.rename(events / name, outside / name)
    os.rmdir(events)
    (state / "events").symlink_to(outside, target_is_directory=True)
    before = (outside / name).read_bytes()
    with pytest.raises(MutationError):
        apply_mutations(state, [entity()], ACTOR)
    assert (outside / name).read_bytes() == before


@posix_only
def test_event_file_symlink_fails_closed_on_replay(roots):
    state, outside = roots
    events, name = _committed(state)
    os.rename(events / name, outside / name)
    (events / name).symlink_to(outside / name)
    before = (outside / name).read_bytes()
    with pytest.raises(StateConflictError):
        mutation._require_committed_event(state, entity())
    with pytest.raises(StateConflictError):
        apply_mutations(state, [entity()], ACTOR)
    assert (outside / name).read_bytes() == before


@fifo_only
def test_event_fifo_fails_closed(roots):
    state, _ = roots
    events, name = _committed(state)
    os.mkfifo(events / "EVT-zzzz.json")
    with pytest.raises(StateConflictError):
        mutation._require_committed_event(state, entity())


def test_missing_or_malformed_event_evidence_fails_closed(roots):
    state, _ = roots
    events, name = _committed(state)
    (events / name).write_text("{not json")
    with pytest.raises(StateConflictError):
        apply_mutations(state, [entity()], ACTOR)
    os.unlink(events / name)
    with pytest.raises(StateConflictError):
        apply_mutations(state, [entity()], ACTOR)


def test_valid_replay_still_succeeds(roots):
    state, _ = roots
    _committed(state)
    res = apply_mutations(state, [entity()], ACTOR)
    assert res["applied"] == [] and res["replayed"] == [["REQUIREMENT", "R-1"]]


# --- 5: FIFO / symlink journal and lock (F4, F5) ----------------------------

@fifo_only
def test_fifo_journal_is_refused(roots):
    state, _ = roots
    batch = state / ".staging" / "batch-x"
    batch.mkdir(parents=True)
    os.mkfifo(batch / "journal.json")
    with pytest.raises(StateConflictError):
        recover_pending(state)


@fifo_only
def test_fifo_lock_file_is_refused(roots):
    state, _ = roots
    state.mkdir()
    os.mkfifo(state / ".mutation.lock")
    with pytest.raises(MutationError, match="lock"):
        apply_mutations(state, [entity()], ACTOR)


@posix_only
def test_symlink_lock_file_is_refused_and_target_untouched(roots):
    state, outside = roots
    state.mkdir()
    target = outside / "victim"
    target.write_text("keep")
    (state / ".mutation.lock").symlink_to(target)
    with pytest.raises(MutationError, match="lock"):
        recover_pending(state)
    assert target.read_text() == "keep"


@posix_only
def test_hardlinked_lock_file_is_refused(roots):
    state, outside = roots
    state.mkdir()
    target = outside / "victim"
    target.write_text("keep")
    try:
        os.link(target, state / ".mutation.lock")
    except OSError as exc:
        pytest.skip(f"hard links unsupported here: {exc}")
    with pytest.raises(MutationError, match="lock"):
        recover_pending(state)
    assert target.read_text() == "keep"


def test_existing_lock_file_is_not_truncated(roots):
    state, _ = roots
    state.mkdir()
    (state / ".mutation.lock").write_bytes(b"sentinel")
    apply_mutations(state, [entity()], ACTOR)
    assert (state / ".mutation.lock").read_bytes() == b"sentinel"


# --- 6/7/8/9: staging, journal, staged payload, malicious recovery ----------

@posix_only
def test_staging_directory_symlink_refused(roots):
    state, outside = roots
    state.mkdir()
    (state / ".staging").symlink_to(outside, target_is_directory=True)
    with pytest.raises(MutationError):
        apply_mutations(state, [entity()], ACTOR)
    assert list(outside.iterdir()) == []


@posix_only
def test_batch_directory_symlink_refused(roots):
    state, outside = roots
    (state / ".staging").mkdir(parents=True)
    (outside / "journal.json").write_text('{"ops": []}')
    (state / ".staging" / "batch-evil").symlink_to(outside, target_is_directory=True)
    with pytest.raises(MutationError):
        recover_pending(state)
    assert (outside / "journal.json").read_text() == '{"ops": []}'


@posix_only
def test_journal_symlink_refused(roots):
    state, outside = roots
    batch = state / ".staging" / "batch-x"
    batch.mkdir(parents=True)
    (outside / "j.json").write_text('{"ops": []}')
    (batch / "journal.json").symlink_to(outside / "j.json")
    with pytest.raises(StateConflictError):
        recover_pending(state)
    assert (outside / "j.json").read_text() == '{"ops": []}'


@posix_only
def test_staged_payload_symlink_refused(roots):
    state, outside = roots
    batch = state / ".staging" / "batch-x"
    batch.mkdir(parents=True)
    payload = canon(entity())
    (outside / "p.tmp").write_bytes(payload)
    (batch / "p.tmp").symlink_to(outside / "p.tmp")
    (batch / "journal.json").write_text(json.dumps({"ops": [{
        "tmp_rel": ".staging/batch-x/p.tmp", "rel_dest": "requirements/R-1.json",
        "digest": hashlib.sha256(payload).hexdigest()}]}))
    with pytest.raises(StateConflictError):
        recover_pending(state)
    assert not (state / "requirements" / "R-1.json").exists()
    assert (outside / "p.tmp").read_bytes() == payload


@pytest.mark.parametrize("op", [
    {"rel_dest": "../escape.json", "tmp_rel": ".staging/batch-x/p.tmp"},
    {"rel_dest": "/abs/escape.json", "tmp_rel": ".staging/batch-x/p.tmp"},
    {"rel_dest": "requirements/R-1.json", "tmp_rel": "../../p.tmp"},
    {"dest": "/etc/passwd", "tmp": "/etc/shadow"},
    {"rel_dest": "requirements/R-1.json"},  # no staged path
    "not-a-dict",
])
def test_recovery_rejects_malicious_or_malformed_journal(roots, op):
    state, outside = roots
    batch = state / ".staging" / "batch-x"
    batch.mkdir(parents=True)
    if isinstance(op, dict):
        op = {**op, "digest": "0" * 64}
    (batch / "journal.json").write_text(json.dumps({"ops": [op]}))
    with pytest.raises(MutationError):
        recover_pending(state)
    assert list(outside.iterdir()) == []
    assert not (state.parent / "escape.json").exists()
    assert (batch / "journal.json").exists(), "refused journal must be preserved"


def test_unexpected_staging_entry_rejected(roots):
    state, _ = roots
    (state / ".staging" / "evil").mkdir(parents=True)
    with pytest.raises(StateConflictError):
        recover_pending(state)


# --- 11: inter-process / inter-thread mutual exclusion (F5) -----------------

@posix_only
def test_mutation_lock_is_mutually_exclusive(roots):
    state, _ = roots
    held, release, second_in = threading.Event(), threading.Event(), threading.Event()

    def first():
        with _MutationLock(state):
            held.set()
            release.wait(10)

    def second():
        held.wait(10)
        with _MutationLock(state):
            second_in.set()

    t1, t2 = threading.Thread(target=first), threading.Thread(target=second)
    t1.start(); t2.start()
    assert held.wait(10)
    time.sleep(0.3)
    assert not second_in.is_set(), "second holder entered while lock held"
    release.set()
    t1.join(10); t2.join(10)
    assert second_in.is_set()


@posix_only
def test_mutation_lock_excludes_other_process(roots):
    import subprocess, sys
    state, _ = roots
    with _MutationLock(state):
        code = ("import fcntl,os,sys;fd=os.open(sys.argv[1],os.O_RDWR);"
                "\ntry:\n fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);print('ACQUIRED')"
                "\nexcept BlockingIOError:\n print('BLOCKED')")
        out = subprocess.run([sys.executable, "-c", code, str(state / ".mutation.lock")],
                             capture_output=True, text=True, timeout=20)
    assert out.stdout.strip() == "BLOCKED", out


@posix_only
def test_lock_retries_when_lock_file_replaced_before_flock(roots, monkeypatch):
    state, _ = roots
    real = secure_fs.secure_fd_matches_beneath
    calls = {"n": 0}

    def flaky(root, rel, fd):
        calls["n"] += 1
        return False if calls["n"] == 1 else real(root, rel, fd)

    monkeypatch.setattr(mutation, "secure_fd_matches_beneath", flaky)
    with _MutationLock(state):
        pass
    assert calls["n"] == 2

    monkeypatch.setattr(mutation, "secure_fd_matches_beneath", lambda *a: False)
    with pytest.raises(MutationError, match="replaced"):
        with _MutationLock(state):
            pass


# --- F6: trust boundary ------------------------------------------------------

@posix_only
def test_symlinked_state_root_is_refused(roots):
    state, outside = roots
    state.symlink_to(outside, target_is_directory=True)
    with pytest.raises(MutationError):
        apply_mutations(state, [entity()], ACTOR)
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("bad", ["../x", "a/../../x", "/abs", "", "a//b", "./a", "a\x00b"])
def test_lexical_escape_rejected_before_io(tmp_path, bad):
    for fn in (secure_fs.secure_read_bytes_beneath, secure_fs.secure_regular_file_state_beneath,
               secure_fs.secure_exists_beneath, secure_fs.secure_unlink_beneath):
        with pytest.raises(SecureWriteError):
            fn(tmp_path / "root", bad)


@posix_only
def test_symlinked_intermediate_component_refused(roots, tmp_path):
    _, outside = roots
    (outside / "secret").write_text("s")
    root = tmp_path / "root"
    root.mkdir()
    (root / "a").symlink_to(outside, target_is_directory=True)
    with pytest.raises(SecureWriteError):
        secure_fs.secure_read_bytes_beneath(root, "a/secret")
    with pytest.raises(SecureWriteError):
        secure_fs.secure_regular_file_state_beneath(root, "a/secret")
    with pytest.raises(SecureWriteError):
        secure_fs.secure_listdir_beneath(root, "a")


def test_missing_trusted_ancestors_are_created(tmp_path):
    state = tmp_path / "x" / "y" / ".aios"
    res = apply_mutations(state, [entity()], ACTOR)
    assert res["applied"] == [["REQUIREMENT", "R-1"]]


# --- 12 / F7: unsupported platform fails closed ------------------------------

def test_unsupported_platform_fails_closed_without_writing(tmp_path, monkeypatch):
    state = tmp_path / ".aios"
    monkeypatch.setattr(secure_fs.os, "supports_dir_fd", set())
    with pytest.raises(UnsupportedPlatformError):
        secure_fs.secure_read_bytes_beneath(state, "x")
    with pytest.raises(UnsupportedPlatformError):
        secure_fs.atomic_write_beneath(state, "x", "y")
    with pytest.raises(MutationError):
        apply_mutations(state, [entity()], ACTOR)
    assert not state.exists()
