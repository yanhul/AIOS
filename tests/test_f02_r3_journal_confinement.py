# AIOS-CONTRACT: Journal reads and batch cleanup stay directory-FD confined; swaps are detected via pinned FDs.
# AIOS-REGRESSION: Journal/batch symlink or hard-link redirection (F-02 R3).
# AIOS-OWNER: AIOS control-plane effect ledger (L5)
# AIOS-COVERAGE-GAP: Batch swap before apply and after FINALIZED.
# AIOS-BASELINE: audit baseline 74941fff2d28e1955c4b1ca263a2d866ac90d56d
"""F-02-R3: journal reads and cleanup must remain directory-FD confined.

Ported to the F-03/F-04 P0 engine: attacks mutate the residue of a REAL
committed transaction (crashed after its commit point); planted batches are
never executed (tests/test_l5_p0_remediation.py)."""
import os

import pytest

from core import mutation as m
from tests.l5_helpers import (assert_txn_quarantined, assert_untracked_quarantined, inflight,
                              quarantine_ids, state)

pytestmark = pytest.mark.skipif(not m._FD_SAFE, reason="requires dir_fd/O_NOFOLLOW")


def _store(tmp_path):
    aios = tmp_path / "store" / ".aios"
    (aios / "entities").mkdir(parents=True)
    return aios


def test_journal_symlink_is_not_opened_and_txn_is_quarantined(tmp_path, monkeypatch):
    aios = _store(tmp_path)
    batch = inflight(aios, [("entities/payload.json", {"v": 1})], monkeypatch)
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "journal.v3.json"
    victim.write_bytes((batch / "journal.v3.json").read_bytes())  # identical bytes
    victim_ino = victim.stat().st_ino
    (batch / "journal.v3.json").unlink()
    os.symlink(victim, batch / "journal.v3.json")

    real_open = os.open
    opened = {"value": False}

    def tracked_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if os.fstat(fd).st_ino == victim_ino:
            opened["value"] = True
        return fd
    monkeypatch.setattr(m.os, "open", tracked_open)
    assert_txn_quarantined(aios, "COMMITTED_JOURNAL_UNTRUSTED")
    assert not opened["value"]
    assert not (aios / "entities" / "payload.json").exists()


def test_batch_swap_before_apply_is_detected_via_pinned_fd(tmp_path, monkeypatch):
    aios = _store(tmp_path)
    batch = inflight(aios, [("entities/payload.json", {"v": 1})], monkeypatch)
    parked = batch.with_name(batch.name + "-parked")
    outside = tmp_path / "outside"
    outside.mkdir()
    external_journal = outside / "journal.v3.json"
    external_journal.write_text("do not delete", encoding="utf-8")
    real_load = m._load_bound_journal
    swapped = {"value": False}

    def load(*args):
        out = real_load(*args)
        if not swapped["value"]:
            os.rename(batch, parked)
            os.symlink(outside, batch, target_is_directory=True)
            swapped["value"] = True
        return out
    monkeypatch.setattr(m, "_load_bound_journal", load)
    with pytest.raises(m.LedgerBlockedError, match="ROLL_FORWARD_REJECTED"):
        m.recover_pending(str(aios))
    assert swapped["value"]
    assert external_journal.read_text(encoding="utf-8") == "do not delete"
    assert list(outside.iterdir()) == [external_journal]
    assert not (aios / "entities" / "payload.json").exists()
    assert state(aios)["phase"] == "QUARANTINED"


def test_journal_hardlink_is_rejected_before_external_inode_is_read(tmp_path, monkeypatch):
    aios = _store(tmp_path)
    batch = inflight(aios, [("entities/payload.json", {"v": 1})], monkeypatch)
    outside = tmp_path / "outside-hardlink"
    outside.mkdir()
    victim = outside / "journal.json"
    victim.write_bytes((batch / "journal.v3.json").read_bytes())
    os.chmod(victim, 0o600)
    (batch / "journal.v3.json").unlink()
    os.link(victim, batch / "journal.v3.json")
    victim_ino = victim.stat().st_ino
    real_read = os.read
    read_victim = {"value": False}

    def tracked_read(fd, size):
        if os.fstat(fd).st_ino == victim_ino:
            read_victim["value"] = True
        return real_read(fd, size)
    monkeypatch.setattr(m.os, "read", tracked_read)
    assert_txn_quarantined(aios, "COMMITTED_JOURNAL_UNTRUSTED")
    assert not read_victim["value"]
    assert victim.exists()


def test_commit_staging_writes_stay_on_open_batch_fd_after_path_swap(tmp_path, monkeypatch):
    aios = _store(tmp_path)
    outside = tmp_path / "outside-commit"
    outside.mkdir()
    victim = outside / "victim.txt"
    victim.write_text("preserve", encoding="utf-8")
    before = victim.read_bytes()
    staging = aios / ".staging"
    real_write = m._write_new_file_at
    swapped = {"value": False, "name": None}

    def swap_then_write(dir_fd, name, data, *a, **k):
        if not swapped["value"] and name.endswith(".tmp") and not name.startswith("state"):
            [batch_name] = os.listdir(staging)
            swapped["name"] = batch_name
            os.rename(staging / batch_name, staging / (batch_name + "-parked"))
            os.symlink(outside, staging / batch_name, target_is_directory=True)
            swapped["value"] = True
        return real_write(dir_fd, name, data, *a, **k)

    monkeypatch.setattr(m, "_write_new_file_at", swap_then_write)
    with pytest.raises(m.L5UnsafeLayoutError, match="batch directory was replaced"):
        m.commit_batch(str(aios), [("entities/payload.json", {"v": 1})])
    assert swapped["value"]
    assert victim.read_bytes() == before
    assert list(outside.iterdir()) == [victim]
    assert state(aios)["phase"] == "PREPARED"          # never reached the commit point
    assert not (aios / "entities" / "payload.json").exists()
    # Recovery treats the swapped name and the parked dir as untrusted residue.
    monkeypatch.setattr(m, "_write_new_file_at", real_write)
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))
    assert victim.read_bytes() == before and list(outside.iterdir()) == [victim]
    assert not (aios / "entities" / "payload.json").exists()


def test_cleanup_remains_fd_confined_if_batch_swaps_after_finalization(tmp_path, monkeypatch):
    aios = _store(tmp_path)
    outside = tmp_path / "outside-commit-cleanup"
    outside.mkdir()
    external_journal = outside / "journal.v3.json"
    external_journal.write_text("preserve", encoding="utf-8")
    real = m._cleanup_finalized
    swapped = {"value": False, "name": None}

    def hook(lay, st):
        name = st["txn"]["batch_name"]
        staging = aios / ".staging"
        if not swapped["value"] and (staging / name).is_dir():
            os.rename(staging / name, staging / (name + "-parked"))
            os.symlink(outside, staging / name, target_is_directory=True)
            swapped.update(value=True, name=name)
        return real(lay, st)
    monkeypatch.setattr(m, "_cleanup_finalized", hook)
    with pytest.raises(m.LedgerBlockedError, match="finalized seq 1"):
        m.commit_batch(str(aios), [("entities/payload.json", {"v": 1})])
    assert swapped["value"]
    assert external_journal.read_text(encoding="utf-8") == "preserve"
    # The transaction itself is durable: FINALIZED was persisted before cleanup.
    assert (aios / "entities" / "payload.json").is_file()
    assert state(aios)["phase"] == "IDLE" and state(aios)["last_finalized_seq"] == 1
    assert quarantine_ids(aios, swapped["name"])       # symlink preserved as evidence
    assert (aios / ".staging" / (swapped["name"] + "-parked")).is_dir()


def test_non_directory_staging_entry_is_quarantined_and_blocks_store(tmp_path):
    aios = _store(tmp_path)
    staging = aios / ".staging"
    staging.mkdir(mode=0o700)
    bad = staging / "batch-not-a-directory"
    bad.write_text("not a batch directory", encoding="utf-8")
    qid = assert_untracked_quarantined(aios, "batch-not-a-directory")
    assert (aios / ".quarantine" / qid / "evidence").is_file()
