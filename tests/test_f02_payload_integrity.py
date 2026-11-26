# AIOS-CONTRACT: Staged payloads are installed only as new, digest-verified, service-owned inodes of an authorised txn.
# AIOS-REGRESSION: Content TOCTOU, hard-link aliasing, fsync/copy failure reported as success (F-02 P1).
# AIOS-OWNER: AIOS control-plane effect ledger (L5)
# AIOS-COVERAGE-GAP: Attacks now target the residue of a real committed txn.
# AIOS-BASELINE: audit baseline 74941fff2d28e1955c4b1ca263a2d866ac90d56d
"""F-02 staged-payload integrity: content TOCTOU, hard-link aliasing, I/O
failure injection, cleanup safety and replay. Each test establishes the
attack precondition and asserts the on-disk outcome."""
import errno
import hashlib
import os
import stat
import sys
from pathlib import Path

import pytest

from core import mutation as m
from tests.l5_helpers import assert_txn_quarantined, inflight, staged_files, state

pytestmark = pytest.mark.skipif(not m._FD_SAFE, reason="requires dir_fd/O_NOFOLLOW (see test_fd_safe_on_linux)")

GOOD_OBJ, EVIL_OBJ = {"good": True}, {"evil": True}
GOOD = b'{"good":true}\n'
EVIL = b'{"evil":true}\n'
_real_read, _real_fsync, _real_unlink = os.read, os.fsync, os.unlink

# F-03/F-04 P0: every scenario attacks the residue of a REAL committed
# transaction (crashed after its commit point), because planted batches are
# never executed at all (tests/test_l5_p0_remediation.py).


def _store(tmp_path):
    aios = tmp_path / "store" / ".aios"
    (aios / "entities").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "victim.json").write_bytes(b"original\n")
    return aios, outside


def _batch(aios, monkeypatch, obj=None):
    """In-flight committed txn for entities/x.json; returns (batch, staged path)."""
    batch = inflight(aios, [("entities/x.json", GOOD_OBJ if obj is None else obj)], monkeypatch)
    (staged,) = staged_files(batch)
    return batch, staged


def _tree(root):
    snap = {}
    for dp, dns, fns in os.walk(root, followlinks=False):
        for n in dns + fns:
            p = os.path.join(dp, n)
            snap[p] = (("link", os.readlink(p)) if os.path.islink(p)
                       else ("file", Path(p).read_bytes()) if os.path.isfile(p) else ("dir", None))
    return snap


def _l5tmps(root):
    return [p for p in _tree(root) if p.endswith(m._DEST_TMP_SUFFIX)]


def _assert_quarantined(aios):
    qid = assert_txn_quarantined(aios)
    return Path(aios, m.QUARANTINE_DIR, qid, "evidence")


def test_fd_safe_on_linux():
    """Guards against the TOCTOU/integrity tests silently skipping on CI."""
    if sys.platform.startswith("linux"):
        assert m._FD_SAFE


# --- 1. pathname replaced after the CAS check ------------------------------

def test_staged_path_replaced_after_cas_check_is_not_committed(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    batch, staged = _batch(aios, monkeypatch)
    real, swapped = m._dest_state_at, {"v": False}

    def hook(*args):
        out = real(*args)
        if not swapped["v"]:
            swapped["v"] = True
            os.unlink(staged)
            fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, EVIL)  # different regular file, service-owned, 0600
            os.close(fd)
        return out
    monkeypatch.setattr(m, "_dest_state_at", hook)
    evidence = _assert_quarantined(aios)
    assert swapped["v"]
    assert not (aios / "entities" / "x.json").exists()
    assert (evidence / staged.name).read_bytes() == EVIL  # evidence: the swap really happened
    assert _l5tmps(aios) == []


# --- 2. open inode modified while copying -----------------------------------

def test_inplace_write_to_open_staged_inode_during_copy_is_refused(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    batch, staged = _batch(aios, monkeypatch, {"a": "A" * 64})
    monkeypatch.setattr(m, "_COPY_CHUNK", 8)
    ino = staged.stat().st_ino
    real_apply = m._apply_op
    active, calls = {"value": False}, {"n": 0}

    def apply(*args, **kwargs):
        active["value"] = True
        return real_apply(*args, **kwargs)

    def read(fd, size):
        if active["value"] and os.fstat(fd).st_ino == ino:
            calls["n"] += 1
            if calls["n"] == 2:  # first chunk was already copied to the destination temp
                with open(staged, "r+b") as fh:
                    fh.seek(16)
                    fh.write(b"Z" * 8)
        return _real_read(fd, size)
    monkeypatch.setattr(m, "_apply_op", apply)
    monkeypatch.setattr(m.os, "read", read)
    evidence = _assert_quarantined(aios)
    assert calls["n"] >= 2
    assert not (aios / "entities" / "x.json").exists()
    assert b"Z" in (evidence / staged.name).read_bytes()
    assert _l5tmps(aios) == []


# --- 3/4. hard-link aliasing --------------------------------------------------

def test_staged_hard_link_to_outside_file_is_refused(tmp_path, monkeypatch):
    aios, outside = _store(tmp_path)
    batch, staged = _batch(aios, monkeypatch)
    src = outside / "src.json"
    src.write_bytes(GOOD)
    os.chmod(src, 0o600)
    staged.unlink()
    os.link(src, staged)
    assert staged.stat().st_ino == src.stat().st_ino  # precondition
    _assert_quarantined(aios)
    assert not (aios / "entities" / "x.json").exists()
    assert src.read_bytes() == GOOD


def test_link_created_during_copy_does_not_alias_installed_file(tmp_path, monkeypatch):
    """Copy-to-new-inode invariant: a link taken during the copy names the
    staged inode, never the installed one."""
    aios, outside = _store(tmp_path)
    batch, staged = _batch(aios, monkeypatch)
    ino = staged.stat().st_ino
    alias = outside / "alias.json"
    real_apply = m._apply_op
    active, calls = {"value": False}, {"n": 0}

    def apply(*args, **kwargs):
        active["value"] = True
        return real_apply(*args, **kwargs)

    def read(fd, size):
        if active["value"] and os.fstat(fd).st_ino == ino:
            calls["n"] += 1
            if calls["n"] == 1:
                os.link(staged, alias)
        return _real_read(fd, size)
    monkeypatch.setattr(m, "_apply_op", apply)
    monkeypatch.setattr(m.os, "read", read)
    m.recover_pending(str(aios))
    dest = aios / "entities" / "x.json"
    assert alias.stat().st_ino == ino  # attacker holds a name for the staged inode
    assert dest.stat().st_ino != ino and dest.stat().st_nlink == 1
    alias.write_bytes(EVIL)  # 4. mutate external source after install
    assert dest.read_bytes() == GOOD
    assert m.unresolved_quarantine(str(aios)) == []


def test_commit_batch_installs_independent_inode(tmp_path):
    aios, _ = _store(tmp_path)
    out = m.commit_batch(str(aios), [("entities/x.json", {"good": True})])
    st = os.lstat(out[0])
    assert stat.S_ISREG(st.st_mode) and st.st_nlink == 1
    assert not os.listdir(aios / ".staging")


# --- 5/6/7. failure injection ------------------------------------------------

def _assert_retained_then_replays(aios, batch, dest_bytes=GOOD):
    assert (batch / "journal.v3.json").exists()
    assert state(aios)["phase"] == "APPLYING"
    assert m.unresolved_quarantine(str(aios)) == []
    assert _l5tmps(aios) == []
    m.recover_pending(str(aios))  # clean replay completes
    assert (aios / "entities" / "x.json").read_bytes() == dest_bytes
    assert not batch.exists() and state(aios)["phase"] == "IDLE"


def test_failure_during_copy_leaves_nothing_committed(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    obj = {"g": "x" * 300}
    batch, staged = _batch(aios, monkeypatch, obj)
    monkeypatch.setattr(m, "_COPY_CHUNK", 16)
    ino = staged.stat().st_ino
    real_apply = m._apply_op
    active, calls = {"value": False}, {"n": 0}

    def apply(*args, **kwargs):
        active["value"] = True
        return real_apply(*args, **kwargs)

    def read(fd, size):
        if active["value"] and os.fstat(fd).st_ino == ino:
            calls["n"] += 1
            if calls["n"] == 3:
                raise OSError(errno.EIO, "injected copy failure")
        return _real_read(fd, size)
    monkeypatch.setattr(m, "_apply_op", apply)
    monkeypatch.setattr(m.os, "read", read)
    with pytest.raises(m.RecoveryIncompleteError):
        m.recover_pending(str(aios))
    assert not (aios / "entities" / "x.json").exists()
    monkeypatch.setattr(m.os, "read", _real_read)
    _assert_retained_then_replays(aios, batch, (m.canonical_json(obj) + "\n").encode())


def test_failure_during_digest_verification_is_not_success(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    batch, _staged = _batch(aios, monkeypatch)

    class Broken:
        def update(self, _):
            pass

        def hexdigest(self):
            raise RuntimeError("injected digest failure")
    monkeypatch.setattr(m, "_new_digest", Broken)
    with pytest.raises(RuntimeError, match="injected digest failure"):
        m.recover_pending(str(aios))
    assert not (aios / "entities" / "x.json").exists()
    monkeypatch.setattr(m, "_new_digest", hashlib.sha256)
    _assert_retained_then_replays(aios, batch)


@pytest.mark.parametrize("kind", ["file", "dir"])
def test_fsync_failure_is_not_reported_as_success(tmp_path, monkeypatch, kind):
    aios, _ = _store(tmp_path)
    batch, _staged = _batch(aios, monkeypatch)
    hit = {"v": False}
    want = stat.S_ISREG if kind == "file" else stat.S_ISDIR
    entities_ino = (aios / "entities").stat().st_ino

    def fsync(fd):
        st = os.fstat(fd)
        # file: the new destination inode; dir: the destination parent after rename
        target = (want(st.st_mode) and (kind == "file" and st.st_uid == os.geteuid()
                                        and st.st_ino not in (batch.stat().st_ino,))
                  or (kind == "dir" and st.st_ino == entities_ino))
        if not hit["v"] and target and (kind == "dir" or stat.S_IMODE(st.st_mode) == 0o644):
            hit["v"] = True
            raise OSError(errno.EIO, f"injected {kind} fsync failure")
        return _real_fsync(fd)
    monkeypatch.setattr(m.os, "fsync", fsync)
    with pytest.raises(m.RecoveryIncompleteError):
        m.recover_pending(str(aios))
    assert hit["v"]
    if kind == "file":  # failed before install
        assert not (aios / "entities" / "x.json").exists()
    monkeypatch.setattr(m.os, "fsync", _real_fsync)
    _assert_retained_then_replays(aios, batch)


# --- 8. cleanup never follows symlinks ---------------------------------------

def test_cleanup_of_swapped_dest_temp_does_not_follow_symlink(tmp_path, monkeypatch):
    aios, outside = _store(tmp_path)
    batch, staged = _batch(aios, monkeypatch)
    victim = outside / "victim.json"
    ino = staged.stat().st_ino
    real_apply = m._apply_op
    active = {"value": False}

    def apply(*args, **kwargs):
        active["value"] = True
        return real_apply(*args, **kwargs)

    def read(fd, size):
        if active["value"] and os.fstat(fd).st_ino == ino:
            [tmp] = _l5tmps(aios)
            os.unlink(tmp)
            os.symlink(victim, tmp)
            raise OSError(errno.EIO, "injected failure after swap")
        return _real_read(fd, size)
    monkeypatch.setattr(m, "_apply_op", apply)
    monkeypatch.setattr(m.os, "read", read)
    with pytest.raises(m.RecoveryIncompleteError):
        m.recover_pending(str(aios))
    assert victim.read_bytes() == b"original\n"
    assert _l5tmps(aios) == []  # the planted link itself was removed


def test_finalized_cleanup_does_not_follow_symlinks_out_of_store(tmp_path, monkeypatch):
    aios, outside = _store(tmp_path)
    keep = outside / "keepdir"
    keep.mkdir()
    (keep / "precious.txt").write_bytes(b"keep\n")
    real = m._cleanup_finalized
    planted = {"v": False}

    def hook(lay, st):
        batch = aios / ".staging" / st["txn"]["batch_name"]
        if batch.is_dir() and not planted["v"]:
            planted["v"] = True
            os.symlink(keep, batch / "linkdir")
            os.symlink(outside / "victim.json", batch / "linkfile")
        return real(lay, st)
    monkeypatch.setattr(m, "_cleanup_finalized", hook)
    before = _tree(outside)
    m.commit_batch(str(aios), [("entities/x.json", GOOD_OBJ)])
    assert planted["v"]
    assert _tree(outside) == before
    assert os.listdir(aios / ".staging") == []


def test_stale_dest_temps_from_a_crash_are_swept_without_following_links(tmp_path, monkeypatch):
    aios, outside = _store(tmp_path)
    stale = aios / "entities" / f".x.json.dead{m._DEST_TMP_SUFFIX}"
    os.symlink(outside / "victim.json", stale)
    _batch(aios, monkeypatch)
    m.recover_pending(str(aios))
    assert not os.path.lexists(stale)
    assert (outside / "victim.json").read_bytes() == b"original\n"


# --- 9. crash between install and finalization ------------------------------

class Crash(BaseException):
    pass


def test_crash_after_all_installs_before_finalization_replays_with_cas(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    real, n = m._apply_op, {"v": 0}

    def apply(*a, **k):
        real(*a, **k)
        n["v"] += 1
        if n["v"] == 2:
            raise Crash()
    monkeypatch.setattr(m, "_apply_op", apply)
    with pytest.raises(Crash):
        m.commit_batch(str(aios), [("entities/a.json", {"a": 1}), ("entities/b.json", {"b": 2})])
    monkeypatch.setattr(m, "_apply_op", real)
    [batch] = os.listdir(aios / ".staging")
    assert (aios / ".staging" / batch / "journal.v3.json").exists()
    assert state(aios)["phase"] == "APPLYING"
    a_before = (aios / "entities" / "a.json").stat().st_ino
    m.recover_pending(str(aios))
    assert (aios / "entities" / "a.json").stat().st_ino == a_before  # CAS: already applied, not rewritten
    assert b'"b"' in (aios / "entities" / "b.json").read_bytes()
    assert os.listdir(aios / ".staging") == [] and m.unresolved_quarantine(str(aios)) == []


# --- mismatched payload never overwrites committed content -------------------

def test_mismatched_payload_never_overwrites_destination(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    batch, staged = _batch(aios, monkeypatch)
    with open(staged, "wb") as fh:
        fh.write(EVIL)  # journal still names GOOD's digest
    _assert_quarantined(aios)
    assert not (aios / "entities" / "x.json").exists()


# --- platforms without the primitives fail closed ---------------------------

def test_unsupported_platform_commit_fails_closed(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    monkeypatch.setattr(m, "_FD_SAFE", False)
    with pytest.raises(m.L5PlatformUnsupportedError):
        m.commit_batch(str(aios), [("entities/x.json", {"a": 1})])
    assert not (aios / "entities" / "x.json").exists()
    staging = aios / ".staging"
    assert not staging.exists() or os.listdir(staging) == []  # nothing staged


def test_unsupported_platform_recovery_fails_closed_and_retains_batch(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    batch, _staged = _batch(aios, monkeypatch)
    monkeypatch.setattr(m, "_FD_SAFE", False)
    with pytest.raises(m.L5PlatformUnsupportedError):
        m.recover_pending(str(aios))
    with pytest.raises(m.L5PlatformUnsupportedError):
        m.unresolved_quarantine(str(aios))
    assert not (aios / "entities" / "x.json").exists()
    assert (batch / "journal.v3.json").exists()
