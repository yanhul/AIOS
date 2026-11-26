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

pytestmark = pytest.mark.skipif(not m._FD_SAFE, reason="requires dir_fd/O_NOFOLLOW (see test_fd_safe_on_linux)")

GOOD = b'{"good": true}\n'
EVIL = b'{"evil": true}\n'
_real_read, _real_fsync, _real_unlink = os.read, os.fsync, os.unlink


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _store(tmp_path):
    aios = tmp_path / "store" / ".aios"
    (aios / "entities").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "victim.json").write_bytes(b"original\n")
    return aios, outside


def _batch(aios, name="batch-a", ops=None, write=True):
    """ops: list of (tmp_name, rel_dest, bytes). Journal digest = sha(bytes)."""
    batch = aios / ".staging" / name
    batch.mkdir(parents=True, exist_ok=True)
    jops = []
    for tmp_name, rel, data in ops or [("x.tmp", "entities/x.json", GOOD)]:
        if write:
            (batch / tmp_name).write_bytes(data)
        jops.append({"tmp": str(batch / tmp_name), "dest": str(aios / rel), "digest": _sha(data)})
    j = {"format": 2, "batch_id": name, "ops": jops, "body_digest": m._journal_body_digest(name, jops)}
    (batch / "journal.v2.json").write_text(m.canonical_json(j))
    return batch


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


def _assert_quarantined(aios, name="batch-a"):
    with pytest.raises(m.LedgerBlockedError) as ei:
        m.recover_pending(str(aios))
    assert not isinstance(ei.value, m.RecoveryIncompleteError)
    assert name in m.unresolved_quarantine(str(aios))
    return ei.value


def test_fd_safe_on_linux():
    """Guards against the TOCTOU/integrity tests silently skipping on CI."""
    if sys.platform.startswith("linux"):
        assert m._FD_SAFE


# --- 1. pathname replaced after early digest check --------------------------

def test_staged_path_replaced_after_digest_check_is_not_committed(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    (aios / "entities" / "x.json").write_bytes(b"committed-before\n")
    batch = _batch(aios)
    real, swapped = m._digest_staged_confined, {"v": False}

    def hook(*args):
        out = real(*args)  # descriptor-relative early check sees GOOD
        if not swapped["v"]:
            swapped["v"] = True
            os.unlink(batch / "x.tmp")
            (batch / "x.tmp").write_bytes(EVIL)  # different regular file
        return out
    monkeypatch.setattr(m, "_digest_staged_confined", hook)
    _assert_quarantined(aios)
    assert swapped["v"]
    assert (aios / "entities" / "x.json").read_bytes() == b"committed-before\n"
    q = aios / m.QUARANTINE_DIR / "batch-a" / "x.tmp"
    assert q.read_bytes() == EVIL  # evidence: the swap really happened
    assert _l5tmps(aios) == []


# --- 2. open inode modified while copying -----------------------------------

def test_inplace_write_to_open_staged_inode_during_copy_is_refused(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    data = b"A" * 64
    batch = _batch(aios, ops=[("x.tmp", "entities/x.json", data)])
    monkeypatch.setattr(m, "_COPY_CHUNK", 8)
    staged = batch / "x.tmp"

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
                    fh.seek(32)
                    fh.write(b"Z" * 8)
        return _real_read(fd, size)
    monkeypatch.setattr(m, "_apply_op", apply)
    monkeypatch.setattr(m.os, "read", read)
    _assert_quarantined(aios)
    assert calls["n"] >= 2
    assert not (aios / "entities" / "x.json").exists()
    assert b"Z" in (aios / m.QUARANTINE_DIR / "batch-a" / "x.tmp").read_bytes()
    assert _l5tmps(aios) == []


# --- 3/4. hard-link aliasing --------------------------------------------------

def test_staged_hard_link_to_outside_file_is_refused(tmp_path):
    aios, outside = _store(tmp_path)
    src = outside / "src.json"
    src.write_bytes(GOOD)
    batch = _batch(aios, write=False)
    os.link(src, batch / "x.tmp")
    assert (batch / "x.tmp").stat().st_ino == src.stat().st_ino  # precondition
    _assert_quarantined(aios)
    assert not (aios / "entities" / "x.json").exists()
    assert src.read_bytes() == GOOD


def test_link_created_during_copy_does_not_alias_installed_file(tmp_path, monkeypatch):
    aios, outside = _store(tmp_path)
    batch = _batch(aios)
    staged = batch / "x.tmp"
    ino = staged.stat().st_ino
    alias = outside / "alias.json"
    real_apply = m._apply_op
    active = {"value": False}
    calls = {"n": 0}
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

def _assert_retained_then_replays(aios, dest_bytes=GOOD):
    assert (aios / ".staging" / "batch-a" / "journal.v2.json").exists()
    assert m.unresolved_quarantine(str(aios)) == []
    assert _l5tmps(aios) == []
    m.recover_pending(str(aios))  # clean replay completes
    assert (aios / "entities" / "x.json").read_bytes() == dest_bytes
    assert not (aios / ".staging" / "batch-a").exists()


def test_failure_during_copy_leaves_nothing_committed(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    batch = _batch(aios, ops=[("x.tmp", "entities/x.json", GOOD * 20)])
    monkeypatch.setattr(m, "_COPY_CHUNK", 16)

    ino = (batch / "x.tmp").stat().st_ino
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
    _assert_retained_then_replays(aios, GOOD * 20)


def test_failure_during_digest_verification_is_not_success(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    _batch(aios)

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
    _assert_retained_then_replays(aios)


@pytest.mark.parametrize("kind", ["file", "dir"])
def test_fsync_failure_is_not_reported_as_success(tmp_path, monkeypatch, kind):
    aios, _ = _store(tmp_path)
    _batch(aios)
    hit = {"v": False}
    want = stat.S_ISREG if kind == "file" else stat.S_ISDIR

    def fsync(fd):
        if not hit["v"] and want(os.fstat(fd).st_mode):
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
    _assert_retained_then_replays(aios)


# --- 8. cleanup never follows symlinks ---------------------------------------

def test_cleanup_of_swapped_dest_temp_does_not_follow_symlink(tmp_path, monkeypatch):
    aios, outside = _store(tmp_path)
    batch = _batch(aios)
    victim = outside / "victim.json"

    ino = (batch / "x.tmp").stat().st_ino
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


def test_batch_cleanup_does_not_follow_symlinks_out_of_store(tmp_path):
    aios, outside = _store(tmp_path)
    batch = _batch(aios)
    keep = outside / "keepdir"
    keep.mkdir()
    (keep / "precious.txt").write_bytes(b"keep\n")
    os.symlink(keep, batch / "linkdir")
    os.symlink(outside / "victim.json", batch / "linkfile")
    before = _tree(outside)
    m.recover_pending(str(aios))
    assert _tree(outside) == before
    assert not os.path.lexists(batch)


def test_stale_dest_temps_from_a_crash_are_swept_without_following_links(tmp_path):
    aios, outside = _store(tmp_path)
    stale = aios / "entities" / f".x.json.dead{m._DEST_TMP_SUFFIX}"
    os.symlink(outside / "victim.json", stale)
    _batch(aios)
    m.recover_pending(str(aios))
    assert not os.path.lexists(stale)
    assert (outside / "victim.json").read_bytes() == b"original\n"


# --- 9. crash between install and journal cleanup ---------------------------

class Crash(BaseException):
    pass


def test_crash_after_all_installs_before_journal_cleanup_replays(tmp_path, monkeypatch):
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
    assert (aios / ".staging" / batch / "journal.v2.json").exists()
    a_before = (aios / "entities" / "a.json").read_bytes()
    m.recover_pending(str(aios))
    assert (aios / "entities" / "a.json").read_bytes() == a_before
    assert b'"b"' in (aios / "entities" / "b.json").read_bytes()
    assert os.listdir(aios / ".staging") == [] and m.unresolved_quarantine(str(aios)) == []


def test_crash_after_install_before_staged_unlink_replays(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    batch = _batch(aios)

    def unlink(path, *a, **k):
        if path == "x.tmp" and k.get("dir_fd") is not None:
            raise Crash()
        return _real_unlink(path, *a, **k)
    monkeypatch.setattr(m.os, "unlink", unlink)
    with pytest.raises(Crash):
        m.recover_pending(str(aios))
    monkeypatch.setattr(m.os, "unlink", _real_unlink)
    assert (aios / "entities" / "x.json").read_bytes() == GOOD
    assert (batch / "x.tmp").exists() and (batch / "journal.v2.json").exists()
    m.recover_pending(str(aios))
    assert (aios / "entities" / "x.json").read_bytes() == GOOD
    assert not batch.exists()


# --- mismatched payload never overwrites committed content -------------------

def test_mismatched_payload_never_overwrites_committed_destination(tmp_path):
    aios, _ = _store(tmp_path)
    (aios / "entities" / "x.json").write_bytes(GOOD)
    batch = _batch(aios)
    (batch / "x.tmp").write_bytes(EVIL)  # journal still names GOOD's digest
    _assert_quarantined(aios)
    assert (aios / "entities" / "x.json").read_bytes() == GOOD


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
    _batch(aios)
    monkeypatch.setattr(m, "_FD_SAFE", False)
    with pytest.raises(m.L5PlatformUnsupportedError):
        m.recover_pending(str(aios))
    assert not (aios / "entities" / "x.json").exists()
    assert m.unresolved_quarantine(str(aios)) == []
    assert (aios / ".staging" / "batch-a" / "journal.v2.json").exists()
