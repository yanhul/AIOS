"""PR #128 security hardening batch 2: verification, governed memory,
reconciliation, state initialisation, trust model (F6) and lock discipline.

Every unsafe case asserts (a) the operation fails closed and (b) content
outside the state root is unchanged. Only platform primitives (symlink,
mkfifo, flock) gate execution; security failures never skip.
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from core import mutation, reconcile as rcn, secure_fs, state as state_layout, verification
from core.governed_memory import load_memory, persist_memory, build_memory_record
from core.mutation import TransitionError, _MutationLock, apply_mutations, recover_pending
from core.secure_fs import SecureWriteError
from core.verification import VerificationError, apply_verification, load_verifications, resolve_evidence
from core.wal_state_store import WalStateStore
from tests.test_governed_memory_durable import _authorization, _record

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX symlink/flock semantics")
fifo_only = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="os.mkfifo unavailable")
REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _no_hang():
    if not hasattr(signal, "SIGALRM"):
        yield
        return

    def boom(*_):
        raise AssertionError("operation blocked (FIFO opened without O_NONBLOCK?)")
    old = signal.signal(signal.SIGALRM, boom)
    signal.alarm(30)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def _ent(kind, eid):
    return {
        "entity_type": kind, "entity_id": eid, "statement": f"s {eid}",
        "status": "ACTIVE", "source_file": "f", "source_line": 1,
        "source_text": f"t {eid}", "classification": kind,
        "imported_at": "2026-11-12T00:00:00Z", "snapshot_id": "snap",
    }


def _tree_digest(root: Path):
    """Content+type fingerprint of a tree, no-follow (detects any change)."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in sorted(dirnames + filenames):
            p = Path(dirpath, name)
            st = p.lstat()
            if p.is_symlink():
                out[str(p.relative_to(root))] = ("L", os.readlink(p))
            elif p.is_file():
                out[str(p.relative_to(root))] = ("F", hashlib.sha256(p.read_bytes()).hexdigest(), st.st_mode)
            else:
                out[str(p.relative_to(root))] = ("D" if p.is_dir() else "S", st.st_mode)
    return out


@pytest.fixture
def env(tmp_path):
    state = tmp_path / ".aios"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.json").write_text(json.dumps(_ent("EVIDENCE", "EV-9")), encoding="utf-8")
    return state, outside


def _seed(state):
    apply_mutations(str(state), [_ent("EVIDENCE", "EV-1"), _ent("DECISION", "D-1")], actor="t")


# --------------------------------------------------------------------------
# F6: trust model — ownership / mode invariant and honest rename limitation
# --------------------------------------------------------------------------

@posix_only
def test_group_writable_state_subdir_is_refused_for_read_and_write(env):
    state, outside = env
    _seed(state)
    os.chmod(state / "events", 0o770)
    before = _tree_digest(outside)
    with pytest.raises(SecureWriteError):
        secure_fs.secure_listdir_beneath(state, "events")
    with pytest.raises(SecureWriteError):
        secure_fs.secure_write_bytes_beneath(state, "events/x.json", b"{}")
    with pytest.raises(mutation.MutationError):
        apply_mutations(str(state), [_ent("EVIDENCE", "EV-2")], actor="t")
    assert not (state / "events" / "x.json").exists()
    assert _tree_digest(outside) == before


@posix_only
def test_world_writable_state_root_is_refused(env):
    state, _ = env
    _seed(state)
    os.chmod(state, 0o777)
    with pytest.raises(SecureWriteError):
        secure_fs.secure_read_bytes_beneath(state, "evidence/EV-1.json")
    with pytest.raises(mutation.MutationError):
        recover_pending(str(state))


@posix_only
def test_state_dir_not_owned_by_euid_is_refused(env, monkeypatch):
    state, _ = env
    _seed(state)
    real = os.geteuid()
    if real == 0:
        os.chown(state / "evidence", 65534, -1)  # genuine foreign owner
    else:
        monkeypatch.setattr(secure_fs.os, "geteuid", lambda: real + 1)
    with pytest.raises(SecureWriteError):
        secure_fs.secure_listdir_beneath(state, "evidence")


@posix_only
def test_dir_fd_alone_does_not_prevent_rename_race(env, monkeypatch):
    """Documents the residual F6 limitation honestly: once a directory fd is
    held, renaming that directory OUTSIDE the root does not stop the
    descriptor-relative operation; it acts on the moved inode. Protection
    against other uids comes only from the ownership/mode invariant."""
    state, outside = env
    _seed(state)
    moved = outside / "moved-evidence"
    real_listdir = os.listdir

    def racing_listdir(target):
        if isinstance(target, int) and not moved.exists():
            (state / "evidence").rename(moved)
        return real_listdir(target)

    monkeypatch.setattr(secure_fs.os, "listdir", racing_listdir)
    names = secure_fs.secure_listdir_beneath(state, "evidence")
    assert "EV-1.json" in names          # listing came from the moved inode
    assert moved.is_dir() and not (state / "evidence").exists()


@posix_only
def test_read_helpers_never_create_root(tmp_path):
    root = tmp_path / "a" / "b" / ".aios"
    with pytest.raises(FileNotFoundError):
        secure_fs.secure_read_bytes_beneath(root, "events/x.json")
    assert secure_fs.secure_is_dir_beneath(root, "events") is False
    assert secure_fs.secure_lstat_beneath(root, "events") is None
    assert resolve_evidence(str(root), [["EVIDENCE", "EV-1"]]) == ([], [["EVIDENCE", "EV-1"]])
    assert rcn.reconcile(str(root))["overall"] == "VALID"
    assert not (tmp_path / "a").exists()


# --------------------------------------------------------------------------
# verification.py
# --------------------------------------------------------------------------

def _verification_side_effects(state):
    return sorted(os.listdir(state / "verifications")), sorted(os.listdir(state / "events"))


@posix_only
def test_valid_evidence_still_resolves_and_verifies(env):
    state, _ = env
    _seed(state)
    res, unres = resolve_evidence(str(state), [["EVIDENCE", "EV-1"]])
    assert [e["entity_id"] for e in res] == ["EV-1"] and unres == []
    out = apply_verification(str(state), "DECISION", "D-1", [["EVIDENCE", "EV-1"]], verifier="v")
    assert out["outcome"] == "VERIFIED"
    assert out["verification_id"] in load_verifications(str(state))


@posix_only
def test_evidence_file_symlink_fails_closed(env):
    state, outside = env
    _seed(state)
    (state / "evidence" / "EV-9.json").symlink_to(outside / "secret.json")
    before_out, before_state = _tree_digest(outside), _verification_side_effects(state)
    with pytest.raises(VerificationError):
        resolve_evidence(str(state), [["EVIDENCE", "EV-9"]])
    with pytest.raises(VerificationError):
        apply_verification(str(state), "DECISION", "D-1", [["EVIDENCE", "EV-9"]], verifier="v")
    assert _verification_side_effects(state) == before_state
    assert _tree_digest(outside) == before_out


@posix_only
def test_dangling_evidence_symlink_fails_closed(env):
    state, outside = env
    _seed(state)
    (state / "evidence" / "EV-8.json").symlink_to(outside / "nope.json")
    with pytest.raises(VerificationError):
        resolve_evidence(str(state), [["EVIDENCE", "EV-1"]])
    assert not (outside / "nope.json").exists()


@posix_only
def test_evidence_directory_symlink_fails_closed(env):
    state, outside = env
    _seed(state)
    ev = outside / "ev"
    (state / "evidence").rename(ev)
    (state / "evidence").symlink_to(ev, target_is_directory=True)
    before = _tree_digest(outside)
    with pytest.raises(VerificationError):
        resolve_evidence(str(state), [["EVIDENCE", "EV-1"]])
    assert _tree_digest(outside) == before


@posix_only
@fifo_only
def test_fifo_evidence_is_refused_without_blocking(env):
    state, _ = env
    _seed(state)
    os.mkfifo(state / "evidence" / "EV-7.json")
    with pytest.raises(VerificationError):
        resolve_evidence(str(state), [["EVIDENCE", "EV-1"]])


@posix_only
def test_malformed_and_missing_evidence_stay_unresolved(env):
    state, _ = env
    _seed(state)
    (state / "evidence" / "EV-5.json").write_text("{not json", encoding="utf-8")
    res, unres = resolve_evidence(str(state), [["EVIDENCE", "EV-5"], ["EVIDENCE", "EV-404"]])
    assert res == [] and unres == [["EVIDENCE", "EV-5"], ["EVIDENCE", "EV-404"]]
    out = apply_verification(str(state), "DECISION", "D-1", [["EVIDENCE", "EV-404"]], verifier="v")
    assert out["outcome"] == "UNSUPPORTED"


@posix_only
def test_evidence_directory_replaced_between_check_and_list(env, monkeypatch):
    """Real race window: evidence/ swapped for a symlink after the type check."""
    state, outside = env
    _seed(state)
    real_is_dir = verification.secure_is_dir_beneath
    staged = outside / "attacker-ev"
    staged.mkdir()
    (staged / "EV-9.json").write_text((outside / "secret.json").read_text(), encoding="utf-8")

    def swapping(root, rel):
        result = real_is_dir(root, rel)
        if rel == "evidence" and not (state / "evidence").is_symlink():
            (state / "evidence").rename(outside / "orig-ev")
            (state / "evidence").symlink_to(staged, target_is_directory=True)
        return result

    monkeypatch.setattr(verification, "secure_is_dir_beneath", swapping)
    before = _tree_digest(staged)
    with pytest.raises(VerificationError):
        resolve_evidence(str(state), [["EVIDENCE", "EV-9"]])
    assert _tree_digest(staged) == before


@posix_only
def test_verification_record_symlink_and_event_symlink_fail_closed(env):
    state, outside = env
    _seed(state)
    apply_verification(str(state), "DECISION", "D-1", [["EVIDENCE", "EV-1"]], verifier="v")
    (state / "verifications" / "VF-evil.json").symlink_to(outside / "secret.json")
    with pytest.raises(TransitionError):
        load_verifications(str(state))
    (state / "verifications" / "VF-evil.json").unlink()
    (state / "events" / "EVT-x-y.json").symlink_to(outside / "secret.json")
    with pytest.raises(TransitionError):
        load_verifications(str(state))


# --------------------------------------------------------------------------
# governed_memory.py
# --------------------------------------------------------------------------

@pytest.fixture
def mem(tmp_path):
    aios = tmp_path / "aios"
    auth = _authorization(str(aios))
    store = WalStateStore(str(tmp_path / "state.json"))
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "D-1.json").write_bytes((aios / "decisions" / "D-1.json").read_bytes())
    return aios, auth, store, outside


def _persist(store, auth, decision_id="D-1", record=None):
    return persist_memory(store, record or _record(), decision_id=decision_id, mutation_id="M-1",
                          authority="AIOS_CONTROL_PLANE", **auth)


def _assert_no_memory_side_effects(store, outside, before):
    assert load_memory(store) == []
    assert _tree_digest(outside) == before


@posix_only
def test_decision_symlink_outside_root_is_not_authorization(mem):
    aios, auth, store, outside = mem
    (aios / "decisions" / "D-1.json").unlink()
    (aios / "decisions" / "D-1.json").symlink_to(outside / "D-1.json")
    before = _tree_digest(outside)
    with pytest.raises(ValueError, match="unsafe"):
        _persist(store, auth)
    _assert_no_memory_side_effects(store, outside, before)


@posix_only
def test_dangling_decision_symlink_is_not_authorization(mem):
    aios, auth, store, outside = mem
    (aios / "decisions" / "D-1.json").unlink()
    (aios / "decisions" / "D-1.json").symlink_to(outside / "missing.json")
    before = _tree_digest(outside)
    with pytest.raises(ValueError):
        _persist(store, auth)
    _assert_no_memory_side_effects(store, outside, before)


@posix_only
@fifo_only
def test_fifo_decision_is_refused_without_blocking(mem):
    aios, auth, store, outside = mem
    (aios / "decisions" / "D-1.json").unlink()
    os.mkfifo(aios / "decisions" / "D-1.json")
    before = _tree_digest(outside)
    with pytest.raises(ValueError):
        _persist(store, auth)
    _assert_no_memory_side_effects(store, outside, before)


@posix_only
@pytest.mark.parametrize("payload", [b"{broken", b"[]", b"\xff\xfe", b"{}"])
def test_malformed_decision_is_not_authorization(mem, payload):
    aios, auth, store, outside = mem
    (aios / "decisions" / "D-1.json").write_bytes(payload)
    before = _tree_digest(outside)
    with pytest.raises(Exception) as caught:
        _persist(store, auth)
    assert isinstance(caught.value, (ValueError, mutation.MutationError))
    _assert_no_memory_side_effects(store, outside, before)


@posix_only
def test_missing_decision_and_traversal_id_are_not_authorization(mem):
    aios, auth, store, outside = mem
    (aios / "decisions" / "D-1.json").unlink()
    before = _tree_digest(outside)
    with pytest.raises(ValueError, match="does not resolve"):
        _persist(store, auth)
    rec = build_memory_record(
        memory_type="SEMANTIC", content={"topic": "t", "fact": "f"},
        evidence_refs=[["EVIDENCE", "EV-1"]], predecessor="../evidence/EV-1",
        authority="AIOS_CONTROL_PLANE", source_commit="abc").as_dict()
    with pytest.raises(ValueError):
        _persist(store, auth, decision_id="../evidence/EV-1", record=rec)
    _assert_no_memory_side_effects(store, outside, before)


@posix_only
def test_unsafe_evidence_at_memory_write_time_creates_no_memory(mem):
    aios, auth, store, outside = mem
    (aios / "evidence" / "EV-5.json").symlink_to(outside / "D-1.json")
    before = _tree_digest(outside)
    with pytest.raises(VerificationError):
        _persist(store, auth)
    _assert_no_memory_side_effects(store, outside, before)


@posix_only
def test_valid_decision_still_authorizes_memory(mem):
    _, auth, store, _ = mem
    _persist(store, auth)
    assert len(load_memory(store)) == 1


# --------------------------------------------------------------------------
# reconcile.py
# --------------------------------------------------------------------------

def _checks(rep):
    return {(f["check"], f["severity"]) for f in rep["findings"]}


@posix_only
def test_reconcile_symlinked_state_directory_reported_not_followed(env):
    state, outside = env
    _seed(state)
    (state / "evidence").rename(outside / "real-ev")
    (state / "evidence").symlink_to(outside / "real-ev", target_is_directory=True)
    before = _tree_digest(outside)
    rep = rcn.reconcile(str(state))
    assert rep["overall"] == "CORRUPTED"
    assert ("G.unsafe_entry", "CORRUPTED") in _checks(rep)
    assert not any("EV-1" in f["detail"] and f["check"] == "D.corrupt_file" for f in rep["findings"])
    assert _tree_digest(outside) == before


@posix_only
def test_reconcile_symlinked_root_is_refused(env):
    state, outside = env
    _seed(state)
    link = state.parent / "linked-aios"
    link.symlink_to(state, target_is_directory=True)
    rep = rcn.reconcile(str(link))
    assert _checks(rep) == {("G.unsafe_root", "CORRUPTED")}


@posix_only
def test_reconcile_entity_symlink_and_fifo_reported(env):
    state, outside = env
    _seed(state)
    (state / "evidence" / "EV-9.json").symlink_to(outside / "secret.json")
    if hasattr(os, "mkfifo"):
        os.mkfifo(state / "decisions" / "D-9.json")
    before = _tree_digest(outside)
    rep = rcn.reconcile(str(state))
    corrupt = [f["detail"] for f in rep["findings"] if f["check"] == "D.corrupt_file"]
    assert any("EV-9.json" in d and "unsafe" in d for d in corrupt)
    if hasattr(os, "mkfifo"):
        assert any("D-9.json" in d and "unsafe" in d for d in corrupt)
    assert _tree_digest(outside) == before


def _batch(state, name="batch-1"):
    b = state / ".staging" / name
    b.mkdir(parents=True, mode=0o700)
    return b


@posix_only
def test_reconcile_symlinked_journal(env):
    state, outside = env
    _seed(state)
    (outside / "j.json").write_text(json.dumps({"ops": []}), encoding="utf-8")
    (_batch(state) / "journal.json").symlink_to(outside / "j.json")
    before = _tree_digest(outside)
    rep = rcn.reconcile(str(state))
    assert any(f["check"] == "F.corrupt_journal" and "symlink" in f["detail"] for f in rep["findings"])
    assert ("F.pending_transaction", "PENDING") not in _checks(rep)
    assert _tree_digest(outside) == before


@posix_only
@fifo_only
def test_reconcile_fifo_journal(env):
    state, _ = env
    _seed(state)
    os.mkfifo(_batch(state) / "journal.json")
    rep = rcn.reconcile(str(state))
    assert any(f["check"] == "F.corrupt_journal" and "special" in f["detail"] for f in rep["findings"])


@posix_only
@pytest.mark.parametrize("payload", ["{bad", "[]", json.dumps({"ops": "x"}), json.dumps({"ops": [1]})])
def test_reconcile_malformed_journal(env, payload):
    state, _ = env
    _seed(state)
    (_batch(state) / "journal.json").write_text(payload, encoding="utf-8")
    rep = rcn.reconcile(str(state))
    assert ("F.corrupt_journal", "CORRUPTED") in _checks(rep)


@posix_only
def test_reconcile_journal_paths_confined_to_root(env):
    state, outside = env
    _seed(state)
    ops = [{"dest": str(outside / "secret.json"), "tmp": str(outside / "secret.json"), "digest": "0"},
           {"rel_dest": "../outside/secret.json", "tmp_rel": "x", "digest": "0"}]
    (_batch(state) / "journal.json").write_text(json.dumps({"ops": ops}), encoding="utf-8")
    rep = rcn.reconcile(str(state))
    escaped = [f for f in rep["findings"] if "outside AIOS state root" in f["detail"]]
    assert len(escaped) == 2


@posix_only
def test_reconcile_journal_op_through_symlinked_dir_reported(env):
    state, outside = env
    _seed(state)
    (state / "evidence" / "sub").symlink_to(outside, target_is_directory=True)
    ops = [{"rel_dest": "evidence/sub/secret.json", "tmp_rel": ".staging/batch-1/t", "digest": "0"}]
    (_batch(state) / "journal.json").write_text(json.dumps({"ops": ops}), encoding="utf-8")
    rep = rcn.reconcile(str(state))
    assert any("unsafe entry" in f["detail"] for f in rep["findings"])


@posix_only
def test_reconcile_symlinked_or_hardlinked_lock(env):
    state, outside = env
    _seed(state)
    (state / ".mutation.lock").unlink()
    (outside / "lock").write_text("keep", encoding="utf-8")
    (state / ".mutation.lock").symlink_to(outside / "lock")
    before = _tree_digest(outside)
    rep = rcn.reconcile(str(state))
    assert ("G.unsafe_lock", "CORRUPTED") in _checks(rep)
    assert ("G.unsafe_entry", "CORRUPTED") in _checks(rep)
    assert _tree_digest(outside) == before
    (state / ".mutation.lock").unlink()
    os.link(outside / "lock", state / ".mutation.lock")
    rep = rcn.reconcile(str(state))
    assert ("G.unsafe_lock", "CORRUPTED") in _checks(rep)
    assert (outside / "lock").read_text() == "keep"


@posix_only
def test_reconcile_is_read_only_and_recovery_cleanup_never_escapes(env):
    state, outside = env
    _seed(state)
    b = _batch(state, "batch-evil")
    (b / "evil-dir").symlink_to(outside, target_is_directory=True)
    (b / "evil-file").symlink_to(outside / "secret.json")
    if hasattr(os, "mkfifo"):
        os.mkfifo(b / "evil-fifo")
    before_out, before_state = _tree_digest(outside), _tree_digest(state)
    rep = rcn.reconcile(str(state))
    assert ("F.orphan_staging", "INCONSISTENT") in _checks(rep)
    assert _tree_digest(state) == before_state     # detection only
    recover_pending(str(state))                     # orphan batch removed
    assert not b.exists()
    assert _tree_digest(outside) == before_out      # nothing outside touched


@posix_only
def test_clean_store_reconciles_valid(env):
    state, _ = env
    _seed(state)
    rep = rcn.reconcile(str(state))
    assert rep["overall"] == "VALID", rep["findings"]


# --------------------------------------------------------------------------
# Lock / concurrency (process level)
# --------------------------------------------------------------------------

_HOLD = """
import sys, time
sys.path.insert(0, sys.argv[1])
from core.mutation import _MutationLock
with _MutationLock(sys.argv[2]):
    print("LOCKED", flush=True)
    time.sleep(float(sys.argv[3]))
"""


@posix_only
def test_reconcile_waits_for_exclusive_mutation_lock_in_other_process(env):
    state, _ = env
    _seed(state)
    proc = subprocess.Popen([sys.executable, "-c", _HOLD, str(REPO), str(state), "1.5"],
                            stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "LOCKED"
        done = threading.Event()
        result = {}

        def run():
            result["rep"] = rcn.reconcile(str(state))
            done.set()
        t0 = time.monotonic()
        threading.Thread(target=run, daemon=True).start()
        assert not done.wait(0.5), "reconcile did not wait for the exclusive lock"
        assert done.wait(20)
        assert time.monotonic() - t0 >= 1.0
        assert result["rep"]["overall"] == "VALID"
    finally:
        proc.wait(timeout=20)


_INCR = """
import sys
sys.path.insert(0, sys.argv[1])
from core.mutation import _MutationLock
from core.secure_fs import secure_read_bytes_beneath, secure_write_bytes_beneath
for _ in range(int(sys.argv[3])):
    with _MutationLock(sys.argv[2]):
        try:
            n = int(secure_read_bytes_beneath(sys.argv[2], "tasks/counter"))
        except FileNotFoundError:
            n = 0
        secure_write_bytes_beneath(sys.argv[2], "tasks/counter", str(n + 1).encode())
"""


@posix_only
def test_mutation_lock_mutual_exclusion_across_processes(env):
    state, _ = env
    state_layout.ensure_state_dirs(str(state))
    procs = [subprocess.Popen([sys.executable, "-c", _INCR, str(REPO), str(state), "40"])
             for _ in range(4)]
    for p in procs:
        assert p.wait(timeout=60) == 0
    assert (state / "tasks" / "counter").read_text() == "160"
    # All holders used the same singly-linked lock inode.
    assert os.stat(state / ".mutation.lock").st_nlink == 1


# --------------------------------------------------------------------------
# state.py
# --------------------------------------------------------------------------

@posix_only
def test_ensure_state_dirs_symlinked_root_refused(env):
    state, outside = env
    state.symlink_to(outside, target_is_directory=True)
    before = _tree_digest(outside)
    with pytest.raises(SecureWriteError):
        state_layout.ensure_state_dirs(str(state))
    assert _tree_digest(outside) == before


@posix_only
def test_ensure_state_dirs_symlinked_intermediate_refused(env):
    state, outside = env
    state.mkdir(mode=0o700)
    (state / "events").symlink_to(outside, target_is_directory=True)
    before = _tree_digest(outside)
    with pytest.raises(SecureWriteError):
        state_layout.ensure_state_dirs(str(state))
    assert _tree_digest(outside) == before


@posix_only
def test_ensure_state_dirs_regular_file_root_refused(env):
    state, _ = env
    state.write_text("x")
    with pytest.raises(SecureWriteError):
        state_layout.ensure_state_dirs(str(state))
    assert state.read_text() == "x"


@posix_only
def test_ensure_state_dirs_existing_missing_ancestors_and_repeat(tmp_path):
    pre = tmp_path / "pre" / ".aios"
    pre.mkdir(parents=True)
    (pre / "events").mkdir()
    (pre / "events" / "keep.json").write_text("{}")
    paths = state_layout.ensure_state_dirs(str(pre))
    assert paths == [os.path.join(str(pre), n) for n in state_layout.STATE_DIRS]
    assert all(os.path.isdir(p) and not os.path.islink(p) for p in paths)
    assert state_layout.ensure_state_dirs(str(pre)) == paths
    assert (pre / "events" / "keep.json").read_text() == "{}"
    deep = tmp_path / "a" / "b" / "c" / ".aios"
    state_layout.ensure_state_dirs(str(deep))
    assert sorted(os.listdir(deep)) == sorted(state_layout.STATE_DIRS)
    assert (deep.stat().st_mode & 0o777) == 0o700


@posix_only
def test_ensure_state_dirs_permission_failure_fails_closed(tmp_path):
    parent = tmp_path / "p"
    parent.mkdir()
    state = parent / ".aios"
    if os.geteuid() == 0:
        # root bypasses DAC; a foreign-owned root is the meaningful failure.
        state.mkdir(mode=0o700)
        os.chown(state, 65534, -1)
        with pytest.raises(SecureWriteError):
            state_layout.ensure_state_dirs(str(state))
        assert os.listdir(state) == []
    else:
        os.chmod(parent, 0o500)
        try:
            with pytest.raises(PermissionError):
                state_layout.ensure_state_dirs(str(state))
        finally:
            os.chmod(parent, 0o700)
        assert not state.exists()


# --------------------------------------------------------------------------
# Cross-module: authority / policy / capability / effects / snapshot paths
# --------------------------------------------------------------------------

def _swap_for_outside_symlink(path: Path, outside: Path) -> None:
    copy = outside / ("copy-" + path.name)
    copy.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(copy)


@posix_only
@pytest.mark.parametrize("which", ["contract", "permit", "policy", "capability"])
def test_symlinked_authority_artifacts_never_authorize_memory(mem, which):
    from core.capabilities import CAPABILITY_STATE_FILE
    from core.policy_registry import POLICIES_DIR
    aios, auth, store, outside = mem
    targets = {
        "contract": aios / "authority" / "contracts" / (auth["contract_id"] + ".json"),
        "permit": aios / "authority" / "permits" / (auth["permit_id"] + ".json"),
        "policy": next((aios / POLICIES_DIR).iterdir()),
        "capability": aios / CAPABILITY_STATE_FILE,
    }
    _swap_for_outside_symlink(targets[which], outside)
    before = _tree_digest(outside)
    with pytest.raises(Exception) as caught:
        _persist(store, auth)
    assert "unsafe" in repr(caught.value) + repr(caught.value.__cause__) + repr(caught.value.__context__)
    _assert_no_memory_side_effects(store, outside, before)


@posix_only
def test_symlinked_effects_dir_fails_closed(env):
    from core.external_effect import load_effects
    state, outside = env
    _seed(state)
    (state / "effects").symlink_to(outside, target_is_directory=True)
    (outside / "e.json").write_text(json.dumps({"record_type": "EXTERNAL_EFFECT", "effect_id": "x"}))
    with pytest.raises(mutation.StateConflictError):
        load_effects(str(state))


@posix_only
def test_snapshot_never_written_through_symlink(env):
    from core.snapshot import SnapshotDirError, SnapshotExistsError, create_snapshot
    state, outside = env
    state.mkdir(mode=0o700)
    (state / "snapshots").symlink_to(outside, target_is_directory=True)
    before = _tree_digest(outside)
    with pytest.raises(SnapshotDirError):
        create_snapshot(str(state / "snapshots"), inventory=[], entities=[], contradictions=[],
                        unresolved=[], metadata={}, snapshot_id="SNAP-x")
    assert _tree_digest(outside) == before
    (state / "snapshots").unlink()
    (state / "snapshots").mkdir(mode=0o700)
    (state / "snapshots" / "SNAP-y").symlink_to(outside, target_is_directory=True)
    with pytest.raises((SnapshotDirError, SnapshotExistsError)):
        create_snapshot(str(state / "snapshots"), inventory=[], entities=[], contradictions=[],
                        unresolved=[], metadata={}, snapshot_id="SNAP-y")
    assert _tree_digest(outside) == before
