# AIOS-CONTRACT: F-03/F-04 P0: only a txn named by protected .l5/state.json (digest-bound journal) executes; layout ownership/modes, CAS recovery, anti-replay and quarantine authorisation are enforced.
# AIOS-REGRESSION: Audit F03-1..F03-9, F04-1..F04-4, R-1..R-5 (yanhul/aios audit of 74941ff).
# AIOS-OWNER: AIOS control-plane effect ledger (L5)
# AIOS-COVERAGE-GAP: A1-A8, B1-B6, C2-C7, D1-D8 and mutation-killing tests M4/M5/M9/M13/M15/M16/M26/M36.
# AIOS-BASELINE: audit baseline 74941fff2d28e1955c4b1ca263a2d866ac90d56d
"""F-03/F-04 P0 remediation regression suite (post-remediation).

Each test names its audit ID. The original audit PoCs (which asserted the
VULNERABLE baseline behaviour) are kept unchanged outside the repository; this
suite asserts the SAFE property instead.

Attacker model exercised here: a different-uid staging writer (real uid
switch where the environment allows: root + setpriv; otherwise the test is
SKIPPED with the missing prerequisite) and in-process tampering that stands in
for it. Same-uid attackers are out of scope (docs/L5_TRUST_MODEL.md).
"""
import hashlib
import json
import multiprocessing
import os
import shutil
import stat
import subprocess
import uuid
from pathlib import Path

import pytest

from core import mutation as m
from tests.l5_helpers import (assert_txn_quarantined, assert_untracked_quarantined, inflight, journal,
                              planted_batch, quarantine_ids, resolve, staged_files, state, tree)

pytestmark = pytest.mark.skipif(not m._FD_SAFE, reason="requires POSIX dir_fd/O_NOFOLLOW/fchmod")

ATTACKER_UID = 65534
_HAVE_SETPRIV = shutil.which("setpriv") is not None
needs_uid_switch = pytest.mark.skipif(
    not (hasattr(os, "geteuid") and os.geteuid() == 0 and _HAVE_SETPRIV),
    reason="real different-UID test needs root + setpriv to run commands as uid 65534")
needs_root = pytest.mark.skipif(not (hasattr(os, "geteuid") and os.geteuid() == 0),
                                reason="needs root to chown objects to a foreign uid")


def _store(tmp_path):
    aios = tmp_path / "store" / ".aios"
    (aios / "entities").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "victim.json").write_bytes(b"original\n")
    return aios, outside


def _bytes(obj):
    return (m.canonical_json(obj) + "\n").encode()


def _read(aios, rel):
    return json.loads(Path(aios, rel).read_text())


def _as_attacker(cmd):
    return subprocess.run(["setpriv", f"--reuid={ATTACKER_UID}", f"--regid={ATTACKER_UID}",
                           "--clear-groups", "sh", "-c", cmd], capture_output=True, text=True)


def _world_traversable(path):
    """Let the attacker uid reach the store (only search permission on ancestors)."""
    p = Path(path)
    for parent in [p] + list(p.parents):
        if str(parent) in ("/", "/tmp"):
            break
        os.chmod(parent, stat.S_IMODE(os.stat(parent).st_mode) | 0o711)


# ===========================================================================
# A. Journal authenticity, strict parsing, anti-replay
# ===========================================================================

def test_A1_forged_v2_journal_never_installs_record(tmp_path):
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/seed.json", {"s": 1})])
    planted_batch(aios, "batch-forged", [("evil.tmp", aios / "policies" / "forged.json",
                                          _bytes({"allow": "*"}))])
    assert_untracked_quarantined(aios, "batch-forged")
    assert not (aios / "policies" / "forged.json").exists()
    with pytest.raises(m.LedgerBlockedError):   # legit commit cannot launder it
        m.commit_batch(str(aios), [("entities/legit.json", {"x": 1})])
    assert not (aios / "policies" / "forged.json").exists()


def test_A1b_forged_v3_journal_with_leaked_store_id_is_not_executed(tmp_path):
    """Even an attacker who knows the store_id and the v3 schema cannot get a
    batch executed: authorisation is the protected state, not the journal."""
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/seed.json", {"s": 1})])
    st = state(aios)
    bid = uuid.uuid4().hex
    bdir = aios / ".staging" / f"batch-{bid}"
    bdir.mkdir(mode=0o700)
    payload = _bytes({"allow": "*"})
    src = f"{uuid.uuid4().hex}.tmp"
    (bdir / src).write_bytes(payload)
    os.chmod(bdir / src, 0o600)
    j = {"format": 3, "store_id": st["store_id"], "batch_id": bid, "batch_name": bdir.name,
         "seq": st["next_seq"], "ops": [{"src": src, "dest": ["policies", "forged.json"], "prior": None,
                                         "new": hashlib.sha256(payload).hexdigest()}]}
    (bdir / "journal.v3.json").write_bytes(m.canonical_json(j).encode())
    os.chmod(bdir / "journal.v3.json", 0o600)
    assert_untracked_quarantined(aios, bdir.name)
    assert not (aios / "policies" / "forged.json").exists()


def test_A2_forged_audit_event_never_installed(tmp_path):
    aios, _ = _store(tmp_path)
    ev = {"kind": "mutation", "action": "entity.imported", "entity_type": "DECISION"}
    ev["event_id"] = m.event_identity(ev)
    rel = f"events/EVT-20260101T000000Z-{ev['event_id']}.json"
    planted_batch(aios, "batch-ev", [("e.tmp", aios / rel, _bytes(ev))])
    assert_untracked_quarantined(aios, "batch-ev")
    assert not (aios / rel).exists()


def test_A3_legacy_journal_downgrade_is_rejected(tmp_path):
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/d.json", {"v": "legit"})])
    bdir = aios / ".staging" / "batch-legacy"
    bdir.mkdir(mode=0o700)
    payload = b'{"legacy":"forged"}\n'
    (bdir / "p.tmp").write_bytes(payload)
    (bdir / "journal.json").write_text(json.dumps({"ops": [{
        "tmp": str(bdir / "p.tmp"), "dest": str(aios / "entities" / "d.json"),
        "digest": hashlib.sha256(payload).hexdigest()}]}))
    assert_untracked_quarantined(aios, "batch-legacy")
    assert _read(aios, "entities/d.json") == {"v": "legit"}


def test_A3b_store_without_protected_state_quarantines_pre_v3_residue(tmp_path):
    """Upgrade path: a pre-v3 store with staging residue and no .l5/state.json
    never rolls that residue forward."""
    aios, _ = _store(tmp_path)
    planted_batch(aios, "batch-old-engine", [("x.tmp", aios / "entities" / "x.json", _bytes({"o": 1}))])
    assert not (aios / ".l5").exists()
    assert_untracked_quarantined(aios, "batch-old-engine")
    assert not (aios / "entities" / "x.json").exists()
    assert state(aios)["phase"] == "IDLE"


def test_A4_replay_of_older_committed_transaction_is_rejected(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    captured = tmp_path / "captured-v1"
    real = m._cleanup_finalized

    def capture(lay, st):
        b = aios / ".staging" / st["txn"]["batch_name"]
        if b.is_dir() and not captured.exists():
            shutil.copytree(b, captured, symlinks=True)
        return real(lay, st)
    monkeypatch.setattr(m, "_cleanup_finalized", capture)
    m.commit_batch(str(aios), [("entities/r.json", {"v": 1})])       # attacker observes v1 batch
    monkeypatch.setattr(m, "_cleanup_finalized", real)
    m.commit_batch(str(aios), [("entities/r.json", {"v": 2})])       # current state
    shutil.copytree(captured, aios / ".staging" / captured.name.replace("captured-v1", "batch-replay"),
                    symlinks=True)
    assert_untracked_quarantined(aios, "batch-replay")
    assert _read(aios, "entities/r.json") == {"v": 2}


def test_A4b_replay_of_older_journal_into_inflight_batch_is_rejected(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    captured = {}
    real = m._cleanup_finalized

    def capture(lay, st):
        b = aios / ".staging" / st["txn"]["batch_name"]
        if b.is_dir() and not captured:
            captured["journal"] = (b / "journal.v3.json").read_bytes()
            captured["staged"] = {p.name: p.read_bytes() for p in staged_files(b)}
        return real(lay, st)
    monkeypatch.setattr(m, "_cleanup_finalized", capture)
    m.commit_batch(str(aios), [("entities/r.json", {"v": 1})])
    monkeypatch.setattr(m, "_cleanup_finalized", real)
    batch = inflight(aios, [("entities/r.json", {"v": 2})], monkeypatch)
    m.recover_pending(str(aios))                                     # v2 durable
    batch = inflight(aios, [("entities/r.json", {"v": 3})], monkeypatch)
    for p in staged_files(batch):
        p.unlink()
    for name, data in captured["staged"].items():
        (batch / name).write_bytes(data)
        os.chmod(batch / name, 0o600)
    (batch / "journal.v3.json").write_bytes(captured["journal"])     # replayed, self-consistent v1 journal
    assert_txn_quarantined(aios, "COMMITTED_JOURNAL_UNTRUSTED")
    assert _read(aios, "entities/r.json") == {"v": 2}


def test_A5_batch_directory_replacement_with_same_name_is_rejected(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    batch = inflight(aios, [("entities/x.json", {"v": 1})], monkeypatch)
    parked = tmp_path / "parked"
    os.rename(batch, parked)                 # keep the original inode alive elsewhere
    shutil.copytree(parked, batch)           # same name + bytes, different inode
    os.chmod(batch, 0o700)
    assert_txn_quarantined(aios, "COMMITTED_BATCH_UNTRUSTED")
    assert not (aios / "entities" / "x.json").exists()


def test_A5b_renamed_inflight_batch_is_untracked_and_txn_not_guessed(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    batch = inflight(aios, [("entities/x.json", {"v": 1})], monkeypatch)
    os.rename(batch, batch.with_name("batch-" + uuid.uuid4().hex))
    with pytest.raises(m.LedgerBlockedError, match="untracked staging entries"):
        m.recover_pending(str(aios))
    assert not (aios / "entities" / "x.json").exists()
    assert state(aios)["phase"] == "APPLYING"     # committed txn retained, never discarded


def test_A5c_sequence_numbers_are_never_reused(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    seqs = []
    m.commit_batch(str(aios), [("entities/a.json", {"i": 0})])
    seqs.append(state(aios)["last_finalized_seq"])
    with monkeypatch.context() as mp:            # aborted (PREPARED) transaction burns its seq
        mp.setattr(m, "_replace", lambda *a, **k: (_ for _ in ()).throw(OSError(5, "crash")))
        with pytest.raises(OSError):
            m.commit_batch(str(aios), [("entities/a.json", {"i": 1})])
    m.recover_pending(str(aios))
    for i in range(2, 5):
        m.commit_batch(str(aios), [("entities/a.json", {"i": i})])
        seqs.append(state(aios)["last_finalized_seq"])
    assert seqs == [1, 3, 4, 5]
    assert state(aios)["next_seq"] == 6


@pytest.mark.parametrize("raw,why", [
    (b'{"a":1,"a":2}', "duplicate"),
    (b'{"a": 1}', "canonical"),
    (b'{"b":1,"a":2}', "canonical"),
    (b'{"a":NaN}', "non-finite"),
    (b'{"a":"\xc3\xa9"}', "canonical"),          # non-ASCII must be \\u-escaped
    (b'\xff', "not valid JSON"),
])
def test_A6_strict_parser_rejects_noncanonical_and_duplicate_keys(raw, why):
    with pytest.raises(m._JournalInvalid, match=why):
        m._strict_loads(raw, "journal")


def _txn_and_journal():
    txn = {"seq": 4, "batch_id": "a" * 32, "batch_name": "batch-" + "a" * 32}
    op = {"src": "b" * 32 + ".tmp", "dest": ["entities", "x.json"], "prior": None, "new": "c" * 64}
    j = {"format": 3, "store_id": "d" * 32, "batch_id": txn["batch_id"], "batch_name": txn["batch_name"],
         "seq": 4, "ops": [op]}
    return txn, j


@pytest.mark.parametrize("mutate", [
    lambda j: j.update(extra=1),
    lambda j: j["ops"][0].update(extra=1),
    lambda j: j.update(format=2),
    lambda j: j.update(format=True),
    lambda j: j.update(seq=True),
    lambda j: j.update(seq=5),
    lambda j: j.update(store_id="e" * 32),
    lambda j: j.update(batch_name="batch-other"),
    lambda j: j["ops"][0].update(dest=["..", "x"]),
    lambda j: j["ops"][0].update(dest=[".STAGING", "x"]),
    lambda j: j["ops"][0].update(dest="entities/x.json"),
    lambda j: j["ops"][0].update(src="../x.tmp"),
    lambda j: j["ops"][0].update(prior=""),
    lambda j: j["ops"][0].update(new=None),
    lambda j: j.update(ops=[]),
    lambda j: j["ops"].append(dict(j["ops"][0], dest=["entities", "y.json"])),   # A8 shared src
    lambda j: j["ops"].append(dict(j["ops"][0], src="f" * 32 + ".tmp",
                                   dest=["Entities", "X.json"])),                # case alias dest
])
def test_A6_schema_rejects_unknown_fields_types_and_binding_mismatch(mutate):
    txn, j = _txn_and_journal()
    m._validate_journal(json.loads(json.dumps(j)), txn, "d" * 32)  # baseline accepted
    mutate(j)
    with pytest.raises(m._JournalInvalid):
        m._validate_journal(j, txn, "d" * 32)


def test_A7_missing_journal_after_partial_apply_is_quarantined_not_discarded(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/x.json", {"v": "old"}), ("entities/y.json", {"v": "old"})])
    batch = inflight(aios, [("entities/x.json", {"v": "new"}), ("entities/y.json", {"v": "new"})],
                     monkeypatch, fail_at=2)
    assert _read(aios, "entities/x.json") == {"v": "new"}         # partially applied
    (batch / "journal.v3.json").unlink()
    qid = assert_txn_quarantined(aios, "COMMITTED_JOURNAL_UNTRUSTED")
    assert (aios / ".quarantine" / qid / "evidence").is_dir()     # evidence kept, nothing deleted
    assert len(staged_files(aios / ".quarantine" / qid / "evidence")) == 2
    assert _read(aios, "entities/y.json") == {"v": "old"}         # not guessed


def test_A8_duplicate_destinations_are_rejected_at_commit(tmp_path):
    aios, _ = _store(tmp_path)
    for dup in (["entities/x.json", "entities/x.json"], ["entities/x.json", "entities/./x.json"]):
        with pytest.raises(m.StateConflictError, match="duplicate"):
            m.commit_batch(str(aios), [(dup[0], {"a": 1}), (dup[1], {"a": 2})])
    assert not (aios / "entities" / "x.json").exists()
    assert state(aios)["next_seq"] == 1


# ===========================================================================
# B. Trust boundary: ownership, modes, pinned layout, lock, protected state
# ===========================================================================

def test_B1_world_writable_staging_blocks_before_anything_is_read(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/seed.json", {"s": 1})])
    planted_batch(aios, "batch-w", [("x.tmp", aios / "entities" / "w.json", _bytes({"w": 1}))])
    os.chmod(aios / ".staging", 0o777)
    with pytest.raises(m.L5UnsafeLayoutError, match="group/other-writable|expected 700"):
        m.recover_pending(str(aios))
    assert not (aios / "entities" / "w.json").exists()
    assert (aios / ".staging" / "batch-w").is_dir()               # untouched evidence


@needs_root
def test_B1b_foreign_uid_batch_in_private_staging_is_never_executed(tmp_path):
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/seed.json", {"s": 1})])
    b = planted_batch(aios, "batch-foreign", [("x.tmp", aios / "entities" / "w.json", _bytes({"w": 1}))])
    for p in [b] + list(b.iterdir()):
        os.chown(p, ATTACKER_UID, ATTACKER_UID)
    assert_untracked_quarantined(aios, "batch-foreign")
    assert not (aios / "entities" / "w.json").exists()


@needs_uid_switch
def test_B1c_real_different_uid_cannot_write_staging_or_store(tmp_path):
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/seed.json", {"s": 1})])
    _world_traversable(aios)
    for target in (".staging/batch-x", ".l5/x", "entities/x.json", ".staging/../entities/y"):
        r = _as_attacker(f"mkdir {aios / target} 2>&1 || exit 7")
        assert r.returncode != 0, (target, r.stdout)
    r = _as_attacker(f"ls {aios / '.staging'} {aios / '.l5'} 2>&1; exit 0")
    assert "Permission denied" in r.stdout
    assert os.listdir(aios / ".staging") == []
    st = os.stat(aios / ".staging")
    assert st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700


@needs_uid_switch
def test_B2_attacker_cannot_self_resolve_quarantine(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    batch = inflight(aios, [("entities/x.json", {"v": 1})], monkeypatch)
    (batch / "journal.v3.json").write_text("{")
    qid = assert_txn_quarantined(aios)
    _world_traversable(aios)
    r = _as_attacker(f"echo '{{}}' > {aios / '.quarantine' / qid / 'RESOLVED.json'} 2>&1")
    assert r.returncode != 0 and "Permission denied" in (r.stdout + r.stderr)
    assert qid in m.unresolved_quarantine(str(aios))


@needs_root
@pytest.mark.parametrize("kind", ["foreign_owner", "world_writable", "symlink", "hardlink", "fifo"])
def test_B2b_invalid_resolution_records_do_not_resolve(tmp_path, monkeypatch, kind):
    aios, outside = _store(tmp_path)
    batch = inflight(aios, [("entities/x.json", {"v": 1})], monkeypatch)
    (batch / "journal.v3.json").write_text("{")
    qid = assert_txn_quarantined(aios)
    rec = aios / ".quarantine" / qid / "RESOLVED.json"
    if kind == "symlink":
        os.symlink(outside / "victim.json", rec)
    elif kind == "hardlink":
        os.link(outside / "victim.json", rec)
    elif kind == "fifo":
        os.mkfifo(rec)
    else:
        rec.write_text("{}")
        if kind == "foreign_owner":
            os.chown(rec, ATTACKER_UID, ATTACKER_UID)
        else:
            os.chmod(rec, 0o666)
    assert qid in m.unresolved_quarantine(str(aios))
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))


@needs_root
def test_B2c_legacy_attacker_owned_quarantine_entry_cannot_self_resolve(tmp_path):
    """Baseline PoC B2: an attacker-owned legacy entry plus attacker RESOLVED.json."""
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/seed.json", {"s": 1})])
    legacy = aios / ".quarantine" / "batch-evil"
    legacy.mkdir(parents=True)
    (legacy / "RESOLVED.json").write_text("{}")
    for p in (legacy, legacy / "RESOLVED.json"):
        os.chown(p, ATTACKER_UID, ATTACKER_UID)
    assert m.unresolved_quarantine(str(aios)) == ["batch-evil"]
    with pytest.raises(m.LedgerBlockedError):
        m.commit_batch(str(aios), [("entities/x.json", {"x": 1})])


def test_B2d_service_owned_resolution_record_resolves(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    batch = inflight(aios, [("entities/x.json", {"v": 1})], monkeypatch)
    (batch / "journal.v3.json").write_text("{")
    qid = assert_txn_quarantined(aios)
    resolve(aios, qid)
    m.commit_batch(str(aios), [("entities/y.json", {"y": 1})])
    assert state(aios)["phase"] == "IDLE" and m.unresolved_quarantine(str(aios)) == []
    assert (aios / ".quarantine" / qid / "evidence" / "journal.v3.json").exists()  # evidence retained


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "world_writable"])
def test_B3_unsafe_lock_file_is_refused(tmp_path, kind):
    aios, outside = _store(tmp_path)
    lock = Path(m._mutation_lock_path(str(aios)))
    target = outside / "lock-target"
    if kind == "symlink":
        os.symlink(target, lock)
    elif kind == "hardlink":
        target.write_text("")
        os.link(target, lock)
    else:
        lock.write_text("")
        os.chmod(lock, 0o666)
    with pytest.raises(m.L5UnsafeLayoutError, match="lock file"):
        m.commit_batch(str(aios), [("entities/x.json", {"a": 1})])
    if kind == "symlink":
        assert not target.exists()                       # never created through the link
    assert not (aios / "entities" / "x.json").exists()


@needs_root
def test_B3b_foreign_owned_lock_file_is_refused(tmp_path):
    aios, _ = _store(tmp_path)
    lock = Path(m._mutation_lock_path(str(aios)))
    lock.write_text("")
    os.chmod(lock, 0o600)
    os.chown(lock, ATTACKER_UID, ATTACKER_UID)
    with pytest.raises(m.L5UnsafeLayoutError, match="lock file"):
        m.recover_pending(str(aios))


@pytest.mark.parametrize("which", ["root_mode", "ancestor_mode", "root_owner"])
def test_B4_store_root_or_ancestor_altered_after_initialisation(tmp_path, which):
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/a.json", {"v": 1})])
    if which == "root_mode":
        os.chmod(aios, 0o777)
    elif which == "ancestor_mode":
        os.chmod(aios.parent, 0o777)                    # group/other-writable, no sticky bit
    else:
        if os.geteuid() != 0:
            pytest.skip("needs root to chown the store root to a foreign uid")
        os.chown(aios, ATTACKER_UID, ATTACKER_UID)
    with pytest.raises(m.L5UnsafeLayoutError):
        m.commit_batch(str(aios), [("entities/a.json", {"v": 2})])
    assert _read(aios, "entities/a.json") == {"v": 1}
    with pytest.raises(m.L5UnsafeLayoutError):
        m.unresolved_quarantine(str(aios))


def test_B4b_root_mode_altered_mid_commit_is_detected_before_commit_point(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    real = m._write_new_file_at
    hit = {"v": False}

    def hook(dir_fd, name, data, *a, **k):
        if name == m._JOURNAL_TMP_NAME and not hit["v"]:
            hit["v"] = True
            os.chmod(aios, 0o777)
        return real(dir_fd, name, data, *a, **k)
    monkeypatch.setattr(m, "_write_new_file_at", hook)
    with pytest.raises(m.L5UnsafeLayoutError):
        m.commit_batch(str(aios), [("entities/a.json", {"v": 1})])
    assert hit["v"] and state(aios)["phase"] == "PREPARED"
    assert not (aios / "entities" / "a.json").exists()


def test_B5_staging_replaced_after_pinning_is_detected(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    real = m._write_new_file_at
    hit = {"v": False}

    def hook(dir_fd, name, data, *a, **k):
        if name == m._JOURNAL_TMP_NAME and not hit["v"]:
            hit["v"] = True
            os.rename(aios / ".staging", aios / ".staging-pinned")
            os.mkdir(aios / ".staging", 0o700)
        return real(dir_fd, name, data, *a, **k)
    monkeypatch.setattr(m, "_write_new_file_at", hook)
    with pytest.raises(m.L5UnsafeLayoutError, match=r"\.staging was replaced"):
        m.commit_batch(str(aios), [("entities/a.json", {"v": 1})])
    assert hit["v"]
    assert state(aios)["phase"] == "PREPARED"            # never reached the commit point
    assert not (aios / "entities" / "a.json").exists()
    assert os.listdir(aios / ".staging") == []           # nothing written through the new name
    assert len(os.listdir(aios / ".staging-pinned")) == 1  # writes stayed on the pinned FD


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "mode", "corrupt", "tmp_symlink"])
def test_B6_protected_state_substitution_is_refused(tmp_path, kind):
    aios, outside = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/a.json", {"v": 1})])
    sp = aios / ".l5" / "state.json"
    if kind == "symlink":
        fake = outside / "state.json"
        fake.write_bytes(sp.read_bytes())
        sp.unlink()
        os.symlink(fake, sp)
    elif kind == "hardlink":
        os.link(sp, outside / "alias.json")
    elif kind == "mode":
        os.chmod(sp, 0o644)
    elif kind == "corrupt":
        st = json.loads(sp.read_text())
        st["next_seq"] = 1                                # sequence rollback
        sp.write_text(m.canonical_json(st))
    else:
        os.symlink(outside / "victim.json", aios / ".l5" / ("state.json." + "0" * 32 + ".tmp"))
        os.symlink(outside / "victim.json", aios / ".l5" / "planted")
    before = tree(outside)
    with pytest.raises(m.L5UnsafeLayoutError):
        m.commit_batch(str(aios), [("entities/a.json", {"v": 2})])
    assert _read(aios, "entities/a.json") == {"v": 1}
    assert tree(outside) == before or kind == "tmp_symlink"


def test_B6b_state_publication_never_writes_through_old_inode(tmp_path):
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/a.json", {"v": 1})])
    sp = aios / ".l5" / "state.json"
    fd = os.open(sp, os.O_RDONLY)
    before = os.read(fd, 1 << 16)
    ino = os.fstat(fd).st_ino
    m.commit_batch(str(aios), [("entities/a.json", {"v": 2})])
    os.lseek(fd, 0, 0)
    assert os.read(fd, 1 << 16) == before and sp.stat().st_ino != ino   # new inode each transition
    os.close(fd)
    st = os.stat(sp)
    assert stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1


# ===========================================================================
# C. Quarantine collisions, destination path integrity, permissions
# ===========================================================================

def test_C2_quarantine_id_collision_never_loses_evidence(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/seed.json", {"s": 1})])
    planted_batch(aios, "batch-c", [("x.tmp", aios / "entities" / "c.json", _bytes({"c": 1}))])
    fixed = uuid.UUID("0" * 32)
    pre = aios / ".quarantine" / f"batch-c~{fixed.hex}"
    pre.mkdir(parents=True)
    os.chmod(aios / ".quarantine", 0o700)
    (pre / "older-evidence").write_text("keep")
    os.chmod(pre, 0o700)
    resolve(aios, pre.name)                       # an older, resolved entry with the colliding id
    seq = iter([fixed, uuid.UUID("1" * 32)])
    real_uuid4 = uuid.uuid4
    monkeypatch.setattr(m.uuid, "uuid4", lambda: next(seq, None) or real_uuid4())
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))
    assert (pre / "older-evidence").read_text() == "keep"
    assert (aios / ".quarantine" / f"batch-c~{'1' * 32}" / "evidence" / "journal.v2.json").is_file()


def test_C3_preexisting_empty_quarantine_dir_blocks_and_is_not_overwritten(tmp_path):
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/seed.json", {"s": 1})])
    (aios / ".quarantine" / "batch-e").mkdir(parents=True)
    planted_batch(aios, "batch-e", [("x.tmp", aios / "entities" / "e.json", _bytes({"e": 1}))])
    with pytest.raises(m.LedgerBlockedError, match="unresolved"):
        m.recover_pending(str(aios))
    assert os.listdir(aios / ".quarantine" / "batch-e") == []
    assert (aios / ".staging" / "batch-e").is_dir()        # untouched; nothing executed
    assert not (aios / "entities" / "e.json").exists()


def test_C4_symlinked_destination_component_is_refused(tmp_path, monkeypatch):
    aios, outside = _store(tmp_path)
    (aios / "entities").rmdir()
    os.symlink(outside, aios / "entities")
    with pytest.raises(m.StateConflictError):
        m.commit_batch(str(aios), [("entities/s.json", {"s": 1})])
    assert sorted(os.listdir(outside)) == ["victim.json"]


def test_C4b_parent_swapped_after_walk_installs_via_pinned_fd(tmp_path, monkeypatch):
    aios, outside = _store(tmp_path)
    real, done = m._sweep_stale_dest_tmps, {"v": False}

    def hook(parent_fd, name):
        if not done["v"]:
            done["v"] = True
            os.replace(aios / "entities", aios / "entities.moved")
            os.symlink(outside, aios / "entities")
        return real(parent_fd, name)
    monkeypatch.setattr(m, "_sweep_stale_dest_tmps", hook)
    m.commit_batch(str(aios), [("entities/x.json", {"x": 1})])
    assert done["v"]
    assert sorted(os.listdir(outside)) == ["victim.json"]           # never through the symlink
    assert (aios / "entities.moved" / "x.json").is_file()            # landed in pinned inode


def test_C4c_case_alias_of_reserved_directory_is_refused(tmp_path):
    aios, _ = _store(tmp_path)
    for rel in (".Staging/x.json", ".QUARANTINE/q/RESOLVED.json", ".L5/state.json"):
        with pytest.raises(m.StateConflictError):
            m.commit_batch(str(aios), [(rel, {"a": 1})])


def test_C4d_reserved_directory_alias_by_inode_is_refused(tmp_path, monkeypatch):
    """Stand-in for a case-insensitive filesystem: a destination component that
    resolves to the .quarantine inode is refused by identity, not by name."""
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/seed.json", {"s": 1})])
    real = m._open_dir_at

    def aliasing(dir_fd, name, create=False, mode=m._DEST_NEW_DIR_MODE):
        return real(dir_fd, ".l5" if name == "alias" else name, create=create, mode=mode)
    monkeypatch.setattr(m, "_open_dir_at", aliasing)
    with pytest.raises(m.StateConflictError, match="reserved"):
        m.commit_batch(str(aios), [("alias/state.json", {"a": 1})])


def test_C5_fifo_staged_payload_is_refused_without_open(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    batch = inflight(aios, [("entities/f.json", {"f": 1})], monkeypatch)
    (staged,) = staged_files(batch)
    staged.unlink()
    os.mkfifo(staged, 0o600)
    real_open = os.open
    opened = {"v": False}

    def tracked(path, flags, *a, **k):
        if path == staged.name:
            opened["v"] = True
        return real_open(path, flags, *a, **k)
    monkeypatch.setattr(m.os, "open", tracked)
    assert_txn_quarantined(aios, "ROLL_FORWARD_REJECTED")
    assert not opened["v"], "FIFO was opened before its type was validated"
    assert not (aios / "entities" / "f.json").exists()


def test_C6_install_replaces_inode_and_refuses_hardlinked_destination(tmp_path):
    aios, outside = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/h.json", {"h": 1})])
    ino1 = (aios / "entities" / "h.json").stat().st_ino
    m.commit_batch(str(aios), [("entities/h.json", {"h": 2})])
    assert (aios / "entities" / "h.json").stat().st_ino != ino1     # new inode, never in-place
    alias = outside / "alias.json"
    os.link(aios / "entities" / "h.json", alias)
    with pytest.raises(m.StateConflictError, match="hard links"):
        m.commit_batch(str(aios), [("entities/h.json", {"h": 3})])
    assert json.loads(alias.read_text()) == {"h": 2}                # alias never mutated


@pytest.mark.parametrize("prior,expected", [(None, 0o644), (0o600, 0o600), (0o664, 0o644),
                                            (0o4755, 0o755), (0o640, 0o640)])
@pytest.mark.parametrize("umask", [0o000, 0o077])
def test_C7_destination_mode_follows_documented_policy(tmp_path, prior, expected, umask):
    aios, _ = _store(tmp_path)
    p = aios / "entities" / "p.json"
    if prior is not None:
        m.commit_batch(str(aios), [("entities/p.json", {"p": 0})])
        os.chmod(p, prior)
    old = os.umask(umask)
    try:
        m.commit_batch(str(aios), [("entities/p.json", {"p": 1}), ("entities/new/q.json", {"q": 1})])
    finally:
        os.umask(old)
    assert stat.S_IMODE(p.stat().st_mode) == expected
    assert stat.S_IMODE((aios / "entities" / "new").stat().st_mode) == 0o755
    assert stat.S_IMODE((aios / "entities" / "new" / "q.json").stat().st_mode) == 0o644
    for d in (".staging", ".l5"):
        assert stat.S_IMODE((aios / d).stat().st_mode) == 0o700


def test_C7b_group_writable_destination_directory_is_refused(tmp_path):
    aios, _ = _store(tmp_path)
    os.chmod(aios / "entities", 0o775)
    with pytest.raises(m.StateConflictError, match="group/other-writable"):
        m.commit_batch(str(aios), [("entities/x.json", {"x": 1})])


# ===========================================================================
# D. Races and crash points
# ===========================================================================

def test_D1_symlink_swap_after_staged_verification_before_use(tmp_path, monkeypatch):
    aios, outside = _store(tmp_path)
    secret = outside / "secret.txt"
    batch = inflight(aios, [("entities/leak.json", {"x": 1})], monkeypatch)
    (staged,) = staged_files(batch)
    secret.write_bytes(staged.read_bytes())          # same digest as the authorised payload
    os.chmod(secret, 0o600)
    real = m._preverify

    def racing(lay, bfd, ops):
        real(lay, bfd, ops)
        staged.unlink()
        os.symlink(secret, staged)                   # swap after check, before use
    monkeypatch.setattr(m, "_preverify", racing)
    assert_txn_quarantined(aios, "ROLL_FORWARD_REJECTED")
    assert not (aios / "entities" / "leak.json").exists()


def test_D2_hardlinked_destination_before_replay_verification(tmp_path, monkeypatch):
    aios, outside = _store(tmp_path)
    inflight(aios, [("entities/l.json", {"l": 1}), ("entities/m.json", {"m": 1})], monkeypatch, fail_at=2)
    os.link(aios / "entities" / "l.json", outside / "alias.json")
    assert_txn_quarantined(aios, "ROLL_FORWARD_REJECTED")
    assert not (aios / "entities" / "m.json").exists()


def test_D3_batch_replaced_between_journal_verification_and_cleanup(tmp_path, monkeypatch):
    aios, outside = _store(tmp_path)
    batch = inflight(aios, [("entities/x.json", {"x": 1})], monkeypatch)
    keep = outside / "keep"
    keep.mkdir()
    (keep / "journal.v3.json").write_text("keep")
    real = m._cleanup_finalized

    def hook(lay, st):
        if batch.is_dir() and not batch.is_symlink():
            os.rename(batch, batch.with_name(batch.name + "-parked"))
            os.symlink(keep, batch)
        return real(lay, st)
    monkeypatch.setattr(m, "_cleanup_finalized", hook)
    with pytest.raises(m.LedgerBlockedError, match="finalized seq"):
        m.recover_pending(str(aios))
    assert (keep / "journal.v3.json").read_text() == "keep"
    assert _read(aios, "entities/x.json") == {"x": 1}              # committed data durable
    assert state(aios)["phase"] == "IDLE"
    assert quarantine_ids(aios, batch.name)


class Crash(BaseException):
    pass


def test_D4_crash_after_finalized_before_cleanup_never_replays(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    with monkeypatch.context() as mp:
        mp.setattr(m, "_rmtree_at", lambda *a, **k: (_ for _ in ()).throw(Crash()))
        with pytest.raises(Crash):
            m.commit_batch(str(aios), [("entities/x.json", {"v": 1})])
    st = state(aios)
    assert st["phase"] == "CLEANUP" and st["last_finalized_seq"] == st["txn"]["seq"]
    batch = aios / ".staging" / st["txn"]["batch_name"]
    for p in staged_files(batch):                    # tampered residue must not matter
        p.write_bytes(b'{"v":"evil"}\n')
    monkeypatch.setattr(m, "_apply_op", lambda *a, **k: pytest.fail("FINALIZED residue was replayed"))
    m.recover_pending(str(aios))
    assert _read(aios, "entities/x.json") == {"v": 1}
    assert not batch.exists() and state(aios)["phase"] == "IDLE"


def test_D5_crash_after_journal_rename_before_dir_fsync(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/x.json", {"v": 1})])
    real_replace, real_fsync = m._replace, os.fsync
    armed = {"v": False}

    def replace(src, dst, **k):
        real_replace(src, dst, **k)
        if dst == m._JOURNAL_NAME:
            armed["v"] = True

    def fsync(fd):
        if armed["v"]:
            armed["v"] = False
            raise Crash()                            # power loss right after the rename
        return real_fsync(fd)
    with monkeypatch.context() as mp:
        mp.setattr(m, "_replace", replace)
        mp.setattr(m.os, "fsync", fsync)
        with pytest.raises(Crash):
            m.commit_batch(str(aios), [("entities/x.json", {"v": 2})])
    assert state(aios)["phase"] == "PREPARED"        # commit point is the protected state, not the journal
    m.recover_pending(str(aios))
    assert _read(aios, "entities/x.json") == {"v": 1}
    assert state(aios)["phase"] == "IDLE" and os.listdir(aios / ".staging") == []


def test_D6_ambiguous_commit_point_durability_is_resolved_from_state(tmp_path, monkeypatch):
    """fsync of .l5 fails after the COMMIT_POINT rename: the caller is told the
    outcome is ambiguous, and recovery decides from what is on disk."""
    aios, _ = _store(tmp_path)
    real_state_replace, real_fsync = m._state_replace, os.fsync
    armed = {"v": False}

    def sreplace(src, dst, **k):
        real_state_replace(src, dst, **k)
        if json.loads((aios / ".l5" / "state.json").read_text())["phase"] == "COMMIT_POINT":
            armed["v"] = True

    def fsync(fd):
        if armed["v"]:
            armed["v"] = False
            raise OSError(5, "EIO on directory fsync")
        return real_fsync(fd)
    with monkeypatch.context() as mp:
        mp.setattr(m, "_state_replace", sreplace)
        mp.setattr(m.os, "fsync", fsync)
        with pytest.raises(m.RecoveryIncompleteError, match="ambiguous"):
            m.commit_batch(str(aios), [("entities/x.json", {"v": 1})])
    m.recover_pending(str(aios))
    assert _read(aios, "entities/x.json") == {"v": 1}     # rename was visible: rolled forward
    assert state(aios)["phase"] == "IDLE"


@pytest.mark.parametrize("phase_to_crash", ["PREPARED", "COMMIT_POINT", "APPLYING", "FINALIZED", "CLEANUP", "IDLE"])
def test_D7_crash_at_every_state_transition_converges(tmp_path, monkeypatch, phase_to_crash):
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/a.json", {"v": 0}), ("entities/b.json", {"v": 0})])
    real = m._state_replace

    def sreplace(src, dst, **k):
        data = os.open(src, os.O_RDONLY, dir_fd=k["src_dir_fd"])
        try:
            phase = json.loads(os.read(data, 1 << 16))["phase"]
        finally:
            os.close(data)
        if phase == phase_to_crash:
            raise Crash()                            # die before this transition is published
        return real(src, dst, **k)
    with monkeypatch.context() as mp:
        mp.setattr(m, "_state_replace", sreplace)
        with pytest.raises(Crash):
            m.commit_batch(str(aios), [("entities/a.json", {"v": 1}), ("entities/b.json", {"v": 1})])
    m.recover_pending(str(aios))
    a, b = _read(aios, "entities/a.json")["v"], _read(aios, "entities/b.json")["v"]
    assert a == b, "torn state after recovery"
    expected = 0 if phase_to_crash in ("PREPARED", "COMMIT_POINT") else 1
    assert a == expected
    assert state(aios)["phase"] == "IDLE" and os.listdir(aios / ".staging") == []
    assert m.unresolved_quarantine(str(aios)) == []


def _worker(aios, wid, n, out):
    errs = 0
    for i in range(n):
        try:
            if i % 4 == 0:
                m.recover_pending(aios)
            else:
                m.commit_batch(aios, [(f"entities/w{wid}.json", {"i": i}),
                                      ("entities/shared.json", {"w": wid, "i": i})])
        except Exception as exc:  # noqa: BLE001 - recorded and asserted below, never hidden
            errs += 1
            out.put(repr(exc))
    out.put(("done", wid, errs))


def test_concurrent_commit_and_recovery_never_reuse_sequence(tmp_path):
    aios, _ = _store(tmp_path)
    ctx = multiprocessing.get_context("fork")
    out = ctx.Queue()
    procs = [ctx.Process(target=_worker, args=(str(aios), w, 12, out)) for w in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(120)
    results = [out.get(timeout=10) for _ in range(len(procs))]
    errors = [r for r in results if not (isinstance(r, tuple) and r[0] == "done")]
    assert not errors, errors
    assert all(r[2] == 0 for r in results), results
    st = state(aios)
    commits = 4 * sum(1 for i in range(12) if i % 4)
    assert st["phase"] == "IDLE" and st["last_finalized_seq"] == commits and st["next_seq"] == commits + 1
    assert os.listdir(aios / ".staging") == [] and m.unresolved_quarantine(str(aios)) == []


# ===========================================================================
# Mutation-killing tests (each pins one defence-in-depth layer)
# ===========================================================================

def test_D1b_hardlink_swap_after_preverify_is_refused(tmp_path, monkeypatch):
    """Kills M4: a staged payload replaced by a hard link after pre-verification
    is refused at use time even when the bytes match."""
    aios, outside = _store(tmp_path)
    batch = inflight(aios, [("entities/x.json", {"x": 1})], monkeypatch)
    (staged,) = staged_files(batch)
    ext = outside / "ext.bin"
    ext.write_bytes(staged.read_bytes())
    os.chmod(ext, 0o600)
    real = m._preverify

    def racing(lay, bfd, ops):
        real(lay, bfd, ops)
        staged.unlink()
        os.link(ext, staged)
    monkeypatch.setattr(m, "_preverify", racing)
    assert_txn_quarantined(aios, "ROLL_FORWARD_REJECTED")
    assert not (aios / "entities" / "x.json").exists()


def test_D1c_symlink_swap_between_type_check_and_open_never_opens_target(tmp_path, monkeypatch):
    """Kills M5: the lstat-then-open window. With O_NOFOLLOW the external
    inode is never opened; the inode comparison alone would open it first."""
    aios, outside = _store(tmp_path)
    batch = inflight(aios, [("entities/x.json", {"x": 1})], monkeypatch)
    (staged,) = staged_files(batch)
    ext = outside / "ext.bin"
    ext.write_bytes(staged.read_bytes())
    os.chmod(ext, 0o600)
    ext_ino = ext.stat().st_ino
    real_stat, real_open = os.stat, os.open
    state_ = {"swapped": False, "opened_ext": False}

    def stat_hook(path, *a, **k):
        out = real_stat(path, *a, **k)
        if path == staged.name and not state_["swapped"] and k.get("follow_symlinks") is False:
            state_["swapped"] = True
            staged.unlink()
            os.symlink(ext, staged)
        return out

    def open_hook(path, flags, *a, **k):
        fd = real_open(path, flags, *a, **k)
        try:
            if os.fstat(fd).st_ino == ext_ino:
                state_["opened_ext"] = True
        except OSError:
            pass
        return fd
    monkeypatch.setattr(m.os, "stat", stat_hook)
    monkeypatch.setattr(m.os, "open", open_hook)
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))
    monkeypatch.setattr(m.os, "stat", real_stat)
    assert state_["swapped"] and not state_["opened_ext"]
    assert not (aios / "entities" / "x.json").exists()


def test_B1d_read_only_inventory_refuses_unsafe_layout(tmp_path):
    """Kills M9: read-only entry points (no verify()) still validate the layout."""
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/seed.json", {"s": 1})])
    os.chmod(aios / ".staging", 0o777)
    with pytest.raises(m.L5UnsafeLayoutError):
        m.inspect_pending(str(aios))
    with pytest.raises(m.L5UnsafeLayoutError):
        m.unresolved_quarantine(str(aios))


@needs_root
def test_B2e_attacker_renames_service_file_to_resolved_in_owned_legacy_entry(tmp_path):
    """Kills M13: inside an attacker-owned legacy quarantine dir the attacker can
    rename a service-owned 0600 file (e.g. the old engine's QUARANTINE.json) to
    RESOLVED.json. File checks pass; the entry must still be unresolved."""
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/seed.json", {"s": 1})])
    legacy = aios / ".quarantine" / "batch-evil"
    legacy.mkdir(parents=True)
    rec = legacy / "RESOLVED.json"
    rec.write_text('{"classification":"x"}')
    os.chmod(rec, 0o600)                    # service-owned, private, nlink 1
    os.chown(legacy, ATTACKER_UID, ATTACKER_UID)
    assert m.unresolved_quarantine(str(aios)) == ["batch-evil"]


@needs_root
def test_B1e_foreign_owned_payload_in_authorised_txn_is_refused(tmp_path, monkeypatch):
    """Kills M15: object owner is part of the trust anchor."""
    aios, _ = _store(tmp_path)
    batch = inflight(aios, [("entities/x.json", {"x": 1})], monkeypatch)
    (staged,) = staged_files(batch)
    os.chown(staged, ATTACKER_UID, ATTACKER_UID)
    assert_txn_quarantined(aios, "ROLL_FORWARD_REJECTED")
    assert not (aios / "entities" / "x.json").exists()


def test_D8_destination_changed_between_preverify_and_install_is_a_conflict(tmp_path, monkeypatch):
    """Kills M16: recovery CAS never overwrites unrelated newer data."""
    aios, _ = _store(tmp_path)
    inflight(aios, [("entities/x.json", {"x": 1})], monkeypatch)
    real = m._preverify

    def racing(lay, bfd, ops):
        real(lay, bfd, ops)
        p = aios / "entities" / "x.json"
        p.write_bytes(b'{"unrelated":"newer"}\n')
    monkeypatch.setattr(m, "_preverify", racing)
    assert_txn_quarantined(aios, "ROLL_FORWARD_REJECTED")
    assert _read(aios, "entities/x.json") == {"unrelated": "newer"}


def test_D8b_destination_neither_prior_nor_new_is_quarantined(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/x.json", {"v": 1})])
    inflight(aios, [("entities/x.json", {"v": 2})], monkeypatch)
    (aios / "entities" / "x.json").write_bytes(b'{"v":"third-party"}\n')
    assert_txn_quarantined(aios, "ROLL_FORWARD_REJECTED")
    assert _read(aios, "entities/x.json") == {"v": "third-party"}


def test_D8c_absent_prior_is_explicit_and_already_applied_is_skipped(tmp_path, monkeypatch):
    aios, _ = _store(tmp_path)
    batch = inflight(aios, [("entities/n.json", {"n": 1}), ("entities/o.json", {"o": 1})],
                     monkeypatch, fail_at=2)
    ops = journal(batch)["ops"]
    assert [op["prior"] for op in ops] == [None, None]          # absent prior represented explicitly
    ino = (aios / "entities" / "n.json").stat().st_ino
    m.recover_pending(str(aios))
    assert (aios / "entities" / "n.json").stat().st_ino == ino  # == new: skipped, not rewritten
    assert _read(aios, "entities/o.json") == {"o": 1}


def test_D5b_prepared_residue_with_unexpected_entry_is_quarantined(tmp_path, monkeypatch):
    """Kills M26: PREPARED is not assumed harmless; foreign content is evidence."""
    aios, _ = _store(tmp_path)
    with monkeypatch.context() as mp:
        mp.setattr(m, "_replace", lambda *a, **k: (_ for _ in ()).throw(OSError(5, "crash")))
        with pytest.raises(OSError):
            m.commit_batch(str(aios), [("entities/x.json", {"x": 1})])
    st = state(aios)
    assert st["phase"] == "PREPARED"
    batch = aios / ".staging" / st["txn"]["batch_name"]
    planted = batch / "note.txt"
    planted.write_text("unexpected")
    os.chmod(planted, 0o600)
    qid = assert_txn_quarantined(aios, "PREPARED_BATCH_UNTRUSTED")
    assert (aios / ".quarantine" / qid / "evidence" / "note.txt").is_file()
    assert not (aios / "entities" / "x.json").exists()


@pytest.mark.parametrize("edit", [
    lambda st: st.update(phase="PREPARED", txn=m._txn(st["next_seq"], "a" * 32)),        # seq not yet allocated
    lambda st: st.update(phase="PREPARED", txn=m._txn(st["next_seq"] + 5, "a" * 32)),
    lambda st: st.update(last_finalized_seq=st["next_seq"]),
    lambda st: st.update(phase="APPLYING", txn=m._txn(1, "a" * 32)),                     # unbound committed phase
    lambda st: st.update(phase="BOGUS"),
    lambda st: st.update(extra=1),
])
def test_B6c_inconsistent_protected_state_is_refused(tmp_path, edit):
    """Kills M36: a protected state whose sequence/phase invariants do not hold
    (e.g. a rolled-back or hand-edited state) blocks L5 instead of being trusted."""
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/a.json", {"v": 1})])
    sp = aios / ".l5" / "state.json"
    st = json.loads(sp.read_text())
    edit(st)
    sp.write_text(m.canonical_json(st))
    with pytest.raises(m.L5UnsafeLayoutError, match="corrupt"):
        m.recover_pending(str(aios))
    assert _read(aios, "entities/a.json") == {"v": 1}


def test_C2b_overlong_untracked_entry_name_is_quarantined(tmp_path):
    aios, _ = _store(tmp_path)
    m.commit_batch(str(aios), [("entities/seed.json", {"s": 1})])
    name = "b" * 250
    (aios / ".staging" / name).mkdir()
    with pytest.raises(m.LedgerBlockedError, match="untracked staging entries"):
        m.recover_pending(str(aios))
    [qid] = m.unresolved_quarantine(str(aios))
    assert len(qid) <= 255 and (aios / ".quarantine" / qid / "evidence").is_dir()
