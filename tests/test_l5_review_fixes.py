# AIOS-CONTRACT: L5 store path bootstrap never trusts an unvalidated pathname: no realpath before O_NOFOLLOW,
#   symlinks followed only from trusted directories when owned by root/euid, missing components created with
#   mkdirat inside validated parents. Non-root service and POSIX ACL behaviour of the trust boundary.
# AIOS-REGRESSION: Independent review of 0db9638: realpath-before-O_NOFOLLOW redirect into another store (F4a),
#   path-based os.makedirs bootstrap following attacker symlinks (F4b), no non-root/ACL coverage (F10/F11).
# AIOS-OWNER: AIOS control-plane effect ledger (L5)
# AIOS-COVERAGE-GAP: Bootstrap symlink trust, creation races, service uid != 0, ACL mask semantics.
# AIOS-BASELINE: review baseline 0db9638744526c1b78d379b42612553af1f1d551
"""Post-review regression tests for the L5 path bootstrap and trust boundary.

Real different-UID tests need root + setpriv (to act as uid 65534 / 1000).
When ``AIOS_L5_REQUIRE_PRIVILEGED=1`` (the privileged CI job) a missing
prerequisite FAILS instead of skipping.
"""
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from core import mutation as m

ATTACKER, SERVICE = 65534, 1000
REQUIRE = os.environ.get("AIOS_L5_REQUIRE_PRIVILEGED") == "1"
_PRIV = hasattr(os, "geteuid") and os.geteuid() == 0 and shutil.which("setpriv") is not None
needs_priv = pytest.mark.skipif(not _PRIV and not REQUIRE,
                                reason="needs root + setpriv to act as other uids")
pytestmark = pytest.mark.skipif(not m._FD_SAFE, reason="requires POSIX dir_fd/O_NOFOLLOW/fchmod")


def test_privileged_prerequisites_present_when_required():
    """In the privileged CI job a silent skip would hide M13-M15; fail instead."""
    if REQUIRE:
        assert _PRIV, "AIOS_L5_REQUIRE_PRIVILEGED=1 but not root or setpriv missing"


@pytest.fixture
def base():
    """A /var/tmp tree reachable by other uids (search permission only)."""
    d = tempfile.mkdtemp(prefix="l5rev-", dir="/var/tmp" if os.path.isdir("/var/tmp") else None)
    os.chmod(d, 0o755)
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


def _as(uid, cmd):
    return subprocess.run(["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups", "sh", "-c", cmd],
                          capture_output=True, text=True)


def _read(p):
    return json.loads(Path(p).read_text())


# ---------------------------------------------------------------------------
# F4a: no realpath before validation
# ---------------------------------------------------------------------------

@needs_priv
def test_F4a_attacker_symlink_in_caller_path_does_not_redirect_into_victim_store(base):
    victim = base / "victim" / "proj" / ".aios"
    m.commit_batch(str(victim), [("decisions/v.json", {"owner": "victim"})])
    att = base / "att"
    att.mkdir()
    os.chown(att, ATTACKER, ATTACKER)
    r = _as(ATTACKER, f"ln -s {victim.parent} {att}/proj")
    assert r.returncode == 0, r.stderr
    with pytest.raises(m.L5UnsafeLayoutError, match="owned by uid 65534"):
        m.commit_batch(str(att / "proj" / ".aios"), [("decisions/v.json", {"owner": "redirected"})])
    assert _read(victim / "decisions" / "v.json") == {"owner": "victim"}


def test_F4a_root_or_euid_owned_symlink_in_trusted_dir_is_followed(base):
    """The /tmp -> /private/tmp case: a trusted link in a trusted dir is fine."""
    real = base / "real"
    real.mkdir()
    (base / "link").symlink_to(real)
    out = m.commit_batch(str(base / "link" / "p" / ".aios"), [("decisions/a.json", {"a": 1})])
    assert _read(real / "p" / ".aios" / "decisions" / "a.json") == {"a": 1}
    assert out == [str(base / "link" / "p" / ".aios" / "decisions/a.json")]
    assert (real / "p" / ".aios.mutation.lock").is_file()   # lock in the physical parent


@needs_priv
def test_F4a_foreign_owned_symlink_in_sticky_dir_is_not_followed(base):
    sticky = base / "sticky"
    sticky.mkdir()
    os.chmod(sticky, 0o1777)
    real = base / "real"
    m.commit_batch(str(real / ".aios"), [("decisions/a.json", {"a": 1})])
    link = sticky / "store"
    link.symlink_to(real)
    os.lchown(link, ATTACKER, ATTACKER)
    with pytest.raises(m.L5UnsafeLayoutError, match="symlink .* owned by uid 65534"):
        m.commit_batch(str(link / ".aios"), [("decisions/a.json", {"a": 2})])
    assert _read(real / ".aios" / "decisions" / "a.json") == {"a": 1}


def test_F4a_symlink_loop_is_refused(base):
    (base / "l1").symlink_to(base / "l2")
    (base / "l2").symlink_to(base / "l1")
    import signal

    def hang(*_):
        raise AssertionError("symlink loop was not bounded (hang)")
    old = signal.signal(signal.SIGALRM, hang)
    signal.alarm(20)
    try:
        with pytest.raises(m.L5UnsafeLayoutError, match="too many symlinks"):
            m.commit_batch(str(base / "l1" / ".aios"), [("decisions/a.json", {"a": 1})])
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def test_F4a_dotdot_is_resolved_physically_not_lexically(base):
    """'link/..' is the parent of the link TARGET (kernel semantics), never a
    lexical shortcut that would skip validating the target."""
    (base / "x" / "deep").mkdir(parents=True)
    (base / "y").mkdir()
    (base / "y" / "jump").symlink_to(base / "x" / "deep")
    m.commit_batch(str(base / "y" / "jump" / ".." / ".aios"), [("decisions/a.json", {"a": 1})])
    assert (base / "x" / ".aios" / "decisions" / "a.json").is_file()
    assert not (base / "y" / ".aios").exists()


def test_F4a_pathlike_and_relative_paths_are_accepted(base, monkeypatch):
    monkeypatch.chdir(base)
    m.commit_batch(Path("rel") / ".aios", [("decisions/a.json", {"a": 1})])
    assert (base / "rel" / ".aios" / "decisions" / "a.json").is_file()


# ---------------------------------------------------------------------------
# F4b: no path-based bootstrap
# ---------------------------------------------------------------------------

@needs_priv
def test_F4b_bootstrap_never_creates_through_attacker_symlink(base):
    att = base / "att2"
    att.mkdir()
    os.chmod(att, 0o777)                 # writable by everyone, no sticky bit
    target = base / "rootonly"
    target.mkdir()
    assert _as(ATTACKER, f"ln -s {target} {att}/x").returncode == 0
    with pytest.raises(m.L5UnsafeLayoutError, match="group/other-writable"):
        m.commit_batch(str(att / "x" / ".aios"), [("decisions/y.json", {"y": 1})])
    assert os.listdir(target) == []      # no .aios, no lock: nothing created before validation
    assert sorted(os.listdir(att)) == ["x"]


@needs_priv
def test_F4b_attacker_precreated_component_in_sticky_dir_is_refused(base):
    sticky = base / "tmp"
    sticky.mkdir()
    os.chmod(sticky, 0o1777)
    assert _as(ATTACKER, f"mkdir {sticky}/proj").returncode == 0
    with pytest.raises(m.L5UnsafeLayoutError, match="owned by uid 65534"):
        m.commit_batch(str(sticky / "proj" / ".aios"), [("decisions/a.json", {"a": 1})])
    assert os.listdir(sticky / "proj") == []


def test_F4b_component_swapped_after_mkdirat_is_refused(base, monkeypatch):
    elsewhere = base / "elsewhere"
    elsewhere.mkdir()
    real_mkdir = os.mkdir
    hit = {"v": False}

    def racing(path, mode=0o777, *, dir_fd=None):
        real_mkdir(path, mode, dir_fd=dir_fd)
        if path == "fresh" and not hit["v"]:
            hit["v"] = True
            os.rename(base / "fresh", base / "fresh.moved")
            os.symlink(elsewhere, base / "fresh")
    monkeypatch.setattr(m.os, "mkdir", racing)
    with pytest.raises(m.L5UnsafeLayoutError):
        m.commit_batch(str(base / "fresh" / ".aios"), [("decisions/a.json", {"a": 1})])
    assert hit["v"] and os.listdir(elsewhere) == []


@pytest.mark.parametrize("umask", [0o000, 0o077])
def test_F4b_bootstrap_modes_are_explicit(base, umask):
    old = os.umask(umask)
    try:
        m.commit_batch(str(base / "a" / "b" / ".aios"), [("decisions/a.json", {"a": 1})])
    finally:
        os.umask(old)
    for p in (base / "a", base / "a" / "b", base / "a" / "b" / ".aios", base / "a" / "b" / ".aios" / "decisions",
              base / "a" / "b" / ".aios" / "events"):
        assert stat.S_IMODE(p.stat().st_mode) == 0o755, p
    for p in (".staging", ".l5"):
        assert stat.S_IMODE((base / "a" / "b" / ".aios" / p).stat().st_mode) == 0o700


def test_F4b_read_only_entry_points_never_create(base):
    missing = base / "nope" / ".aios"
    assert m.unresolved_quarantine(str(missing)) == []
    assert m.inspect_pending(str(missing))["pending"] == []
    assert not (base / "nope").exists()


# ---------------------------------------------------------------------------
# F10: non-root service uid vs a different attacker uid
# ---------------------------------------------------------------------------

_SERVICE_SCRIPT = r"""
import json, os, sys
sys.path.insert(0, {repo!r})
from core import mutation as m
aios, step = {aios!r}, sys.argv[1]
out = {{"uid": os.geteuid()}}
try:
    if step == "init":
        m.commit_batch(aios, [("decisions/a.json", {{"v": 1}})])
    elif step == "commit":
        m.commit_batch(aios, [("decisions/a.json", {{"v": 2}})])
    elif step == "crash":
        real = m._apply_op
        m._apply_op = lambda *a, **k: (_ for _ in ()).throw(OSError(5, "crash"))
        try:
            m.commit_batch(aios, [("decisions/a.json", {{"v": 3}})])
        except m.RecoveryIncompleteError:
            out["crashed"] = True
    elif step == "recover":
        m.recover_pending(aios)
    out["state"] = json.load(open(os.path.join(aios, ".l5", "state.json")))
    out["a"] = json.load(open(os.path.join(aios, "decisions", "a.json")))
    out["inspect"] = m.inspect_pending(aios)
except Exception as exc:
    out["error"] = f"{{type(exc).__name__}}: {{exc}}"
print(json.dumps(out))
"""


@needs_priv
def test_F10_non_root_service_uid_against_different_attacker_uid(base):
    home = base / "svc"
    home.mkdir()
    os.chown(home, SERVICE, SERVICE)
    aios = home / "proj" / ".aios"
    repo = str(Path(__file__).resolve().parents[1])
    script = base / "svc.py"
    script.write_text(_SERVICE_SCRIPT.format(repo=repo, aios=str(aios)))
    os.chmod(script, 0o644)

    def service(step):
        r = subprocess.run(["setpriv", f"--reuid={SERVICE}", f"--regid={SERVICE}", "--clear-groups",
                            sys.executable, "-I", str(script), step], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        return json.loads(r.stdout)

    out = service("init")
    assert "error" not in out and out["uid"] == SERVICE and out["a"] == {"v": 1}
    for p, mode in ((aios / ".staging", 0o700), (aios / ".l5", 0o700), (aios / ".l5" / "state.json", 0o600)):
        st = p.stat()
        assert st.st_uid == SERVICE and stat.S_IMODE(st.st_mode) == mode, p
    assert service("crash").get("crashed")                 # in-flight committed txn left on disk
    attempts = {
        "plant batch": f"mkdir {aios}/.staging/batch-evil",
        "read state": f"cat {aios}/.l5/state.json",
        "list staging": f"ls {aios}/.staging",
        "overwrite dest": f"echo x > {aios}/decisions/a.json",
        "create dest": f"echo x > {aios}/decisions/new.json",
        "replace staging": f"mv {aios}/.staging {aios}/.staging-x",
        "lock": f"echo x > {home}/proj/.aios.mutation.lock",
        "resolve": f"mkdir -p {aios}/.quarantine/q && touch {aios}/.quarantine/q/RESOLVED.json",
    }
    for what, cmd in attempts.items():
        r = _as(ATTACKER, cmd + " 2>&1")
        assert r.returncode != 0 and "Permission denied" in (r.stdout + r.stderr), (what, r.stdout)
    out = service("recover")
    assert "error" not in out, out
    assert out["a"] == {"v": 3} and out["state"]["phase"] == "IDLE"
    assert out["inspect"] == {"phase": "IDLE", "pending": [], "quarantined": []}
    # A store owned by the attacker uid is refused by the service uid.
    att_home = base / "att"
    att_home.mkdir()
    os.chown(att_home, ATTACKER, ATTACKER)
    script2 = base / "svc2.py"
    script2.write_text(_SERVICE_SCRIPT.format(repo=repo, aios=str(att_home / ".aios")))
    r = subprocess.run(["setpriv", f"--reuid={SERVICE}", f"--regid={SERVICE}", "--clear-groups",
                        sys.executable, "-I", str(script2), "init"], capture_output=True, text=True)
    assert "L5UnsafeLayoutError" in json.loads(r.stdout)["error"]


# ---------------------------------------------------------------------------
# F11: POSIX ACL semantics (Linux access/default ACL xattrs)
# ---------------------------------------------------------------------------

_U_OBJ, _USER, _G_OBJ, _MASK, _OTHER, _UNDEF = 1, 2, 4, 0x10, 0x20, 0xFFFFFFFF


def _acl(entries):
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", t, p, i) for t, p, i in entries)


def _set_acl(path, name, mask):
    try:
        os.setxattr(path, name, _acl([(_U_OBJ, 7, _UNDEF), (_USER, 7, ATTACKER), (_G_OBJ, 5, _UNDEF),
                                      (_MASK, mask, _UNDEF), (_OTHER, 5, _UNDEF)]))
    except (OSError, AttributeError) as exc:
        if REQUIRE:
            pytest.fail(f"POSIX ACL xattrs required in the privileged job but unsupported: {exc}")
        pytest.skip(f"POSIX ACL xattrs unsupported here: {exc}")


def test_F11_named_user_write_acl_on_destination_dir_is_refused(base):
    aios = base / ".aios"
    m.commit_batch(str(aios), [("decisions/a.json", {"a": 1})])
    _set_acl(aios / "decisions", "system.posix_acl_access", 7)  # attacker rwx, mask rwx
    assert stat.S_IMODE((aios / "decisions").stat().st_mode) & 0o020   # mask is reported as group bits
    with pytest.raises(m.StateConflictError, match="group/other-writable"):
        m.commit_batch(str(aios), [("decisions/b.json", {"b": 1})])


def test_F11_acl_write_grant_on_staging_is_refused(base):
    aios = base / ".aios"
    m.commit_batch(str(aios), [("decisions/a.json", {"a": 1})])
    _set_acl(aios / ".staging", "system.posix_acl_access", 7)
    with pytest.raises(m.L5UnsafeLayoutError):
        m.commit_batch(str(aios), [("decisions/b.json", {"b": 1})])


@needs_priv
def test_F11_inherited_default_acl_is_masked_by_explicit_modes(base):
    aios = base / "acl" / ".aios"
    aios.mkdir(parents=True)
    _set_acl(aios, "system.posix_acl_default", 7)  # every child would grant the attacker rwx
    m.commit_batch(str(aios), [("decisions/a.json", {"a": 1})])
    assert stat.S_IMODE((aios / ".staging").stat().st_mode) == 0o700
    for target in (".staging/evil", ".l5/evil", "decisions/evil.json"):
        r = _as(ATTACKER, f"touch {aios}/{target} 2>&1")
        assert r.returncode != 0, (target, r.stdout)


# ---------------------------------------------------------------------------
# F9: reconcile understands protected L5 state and journal v3 (read-only)
# ---------------------------------------------------------------------------

def _tree_bytes(root):
    out = {}
    for dp, dns, fns in os.walk(root):
        for n in dns + fns:
            p = os.path.join(dp, n)
            st = os.lstat(p)
            out[p] = (stat.S_IMODE(st.st_mode), st.st_ino,
                      Path(p).read_bytes() if stat.S_ISREG(st.st_mode) else None)
    return out


def _f_findings(rep):
    return sorted((f["check"], f["severity"]) for f in rep["findings"] if f["check"].startswith("F."))


def test_F9_reconcile_reports_inflight_v3_as_pending_not_orphan(base, monkeypatch):
    from core import reconcile as rc
    from tests.l5_helpers import inflight
    aios = base / ".aios"
    m.commit_batch(str(aios), [("decisions/a.json", {"a": 1})])
    inflight(aios, [("decisions/a.json", {"a": 2})], monkeypatch)
    before = _tree_bytes(base)
    rep = rc.reconcile(str(aios))
    assert _f_findings(rep) == [("F.pending_transaction", "PENDING")]
    assert _tree_bytes(base) == before          # reconcile never mutates or recovers


def test_F9_reconcile_reports_quarantine_and_untracked_journals(base, monkeypatch):
    from core import reconcile as rc
    from tests.l5_helpers import inflight, planted_batch
    aios = base / ".aios"
    m.commit_batch(str(aios), [("decisions/a.json", {"a": 1})])
    batch = inflight(aios, [("decisions/a.json", {"a": 2})], monkeypatch)
    (batch / "journal.v3.json").unlink()
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))
    planted_batch(aios, "batch-forged", [("x.tmp", aios / "decisions" / "z.json", b"z\n")])
    (aios / ".staging" / "batch-empty").mkdir()
    rep = rc.reconcile(str(aios))
    assert _f_findings(rep) == [("F.orphan_staging", "INCONSISTENT"), ("F.quarantined_transaction", "CORRUPTED"),
                                ("F.unresolved_quarantine", "CORRUPTED"), ("F.untracked_journal", "CORRUPTED")]
    assert rep["overall"] == "CORRUPTED"


def test_F9_reconcile_reports_unsafe_layout(base):
    from core import reconcile as rc
    aios = base / ".aios"
    m.commit_batch(str(aios), [("decisions/a.json", {"a": 1})])
    os.chmod(aios / ".staging", 0o777)
    rep = rc.reconcile(str(aios))
    assert ("F.l5_unsafe_layout", "CORRUPTED") in _f_findings(rep)


def test_F9_reconcile_clean_after_resolution(base, monkeypatch):
    from core import reconcile as rc
    from tests.l5_helpers import inflight, resolve, state
    aios = base / ".aios"
    m.commit_batch(str(aios), [("decisions/a.json", {"a": 1})])
    batch = inflight(aios, [("decisions/a.json", {"a": 2})], monkeypatch)
    (batch / "journal.v3.json").unlink()
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))
    resolve(aios, state(aios)["txn"]["quarantine_id"])
    m.recover_pending(str(aios))
    assert _f_findings(rc.reconcile(str(aios))) == []


def test_store_root_must_not_be_sticky_world_writable_even_though_ancestors_may(base):
    """Kills M8: the store-root rule is stricter than the ancestor rule (a sticky
    world-writable directory is an acceptable ancestor, never a store root),
    including on read-only entry points that do not call verify()."""
    aios = base / ".aios"
    m.commit_batch(str(aios), [("decisions/a.json", {"a": 1})])
    os.chmod(aios, 0o1777)
    with pytest.raises(m.L5UnsafeLayoutError, match="store root"):
        m.unresolved_quarantine(str(aios))
    with pytest.raises(m.L5UnsafeLayoutError, match="store root"):
        m.inspect_pending(str(aios))
    with pytest.raises(m.L5UnsafeLayoutError):
        m.commit_batch(str(aios), [("decisions/a.json", {"a": 2})])
    assert _read(aios / "decisions" / "a.json") == {"a": 1}
