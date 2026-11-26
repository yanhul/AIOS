# AIOS-CONTRACT: Replay never opens external inodes through swapped batch/destination components.
# AIOS-REGRESSION: Replay reads redirected through swapped symlinks (F-02 R1/R2).
# AIOS-OWNER: AIOS control-plane effect ledger (L5)
# AIOS-COVERAGE-GAP: Ported to authorised in-flight transactions.
# AIOS-BASELINE: audit baseline 74941fff2d28e1955c4b1ca263a2d866ac90d56d
"""F-02-R1/R2: replay reads must remain confined to the L5 store.

Ported to the F-03/F-04 P0 engine (attacks against a REAL in-flight txn)."""
import hashlib
import os

import pytest

from core import mutation as m
from tests.l5_helpers import assert_txn_quarantined, inflight, staged_files, state

pytestmark = pytest.mark.skipif(not m._FD_SAFE, reason="requires dir_fd/O_NOFOLLOW")


def _store(tmp_path):
    aios = tmp_path / "store" / ".aios"
    (aios / "entities").mkdir(parents=True)
    return aios


def _tracked_open(monkeypatch, ino):
    real_open = os.open
    seen = {"value": False}

    def tracked_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        try:
            if os.fstat(fd).st_ino == ino:
                seen["value"] = True
        except OSError:
            pass
        return fd
    monkeypatch.setattr(m.os, "open", tracked_open)
    return seen


def test_batch_directory_swap_never_opens_external_staged_file(tmp_path, monkeypatch):
    aios = _store(tmp_path)
    batch = inflight(aios, [("entities/payload.json", {"v": 1})], monkeypatch)
    (staged,) = staged_files(batch)
    parked = batch.with_name(batch.name + "-parked")
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / staged.name
    original = staged.read_bytes()
    victim.write_bytes(original)  # same digest: digest-only checks cannot detect it
    os.chmod(victim, 0o600)
    real_open_batch = m._open_txn_batch
    swapped = {"done": False}

    def swap_after_open(lay, st, bound):
        fd = real_open_batch(lay, st, bound)
        if not swapped["done"]:
            os.rename(batch, parked)
            os.symlink(outside, batch, target_is_directory=True)
            swapped["done"] = True
        return fd
    monkeypatch.setattr(m, "_open_txn_batch", swap_after_open)
    opened = _tracked_open(monkeypatch, victim.stat().st_ino)
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))
    assert swapped["done"]
    assert not opened["value"], "external staged file was opened through swapped batch symlink"
    assert victim.read_bytes() == original
    assert not (aios / "entities" / "payload.json").exists()
    assert state(aios)["phase"] == "QUARANTINED"


def test_valid_inflight_replay_succeeds(tmp_path, monkeypatch):
    aios = _store(tmp_path)
    batch = inflight(aios, [("entities/payload.json", {"v": "ordinary"})], monkeypatch)
    (staged,) = staged_files(batch)
    payload = staged.read_bytes()
    m.recover_pending(str(aios))
    assert (aios / "entities" / "payload.json").read_bytes() == payload
    assert hashlib.sha256(payload).hexdigest() == m._digest_bytes(payload)
    assert not batch.exists()
    assert m.unresolved_quarantine(str(aios)) == [] and state(aios)["phase"] == "IDLE"


def test_destination_parent_swap_never_opens_external_destination(tmp_path, monkeypatch):
    aios = _store(tmp_path)
    entities = aios / "entities"
    batch = inflight(aios, [("entities/payload.json", {"v": 1})], monkeypatch)
    (staged,) = staged_files(batch)
    payload = staged.read_bytes()
    outside = tmp_path / "outside-destination"
    outside.mkdir()
    victim = outside / "payload.json"
    victim.write_bytes(payload)  # matching digest must not make a symlink path acceptable
    os.rename(entities, aios / "entities-original")
    os.symlink(outside, entities, target_is_directory=True)
    opened = _tracked_open(monkeypatch, victim.stat().st_ino)
    assert_txn_quarantined(aios, "ROLL_FORWARD_REJECTED")
    assert not opened["value"], "external destination was opened through swapped parent symlink"
    assert victim.read_bytes() == payload


def test_staged_hardlink_is_rejected_before_external_inode_is_read(tmp_path, monkeypatch):
    aios = _store(tmp_path)
    batch = inflight(aios, [("entities/payload.json", {"v": 1})], monkeypatch)
    (staged,) = staged_files(batch)
    payload = staged.read_bytes()
    outside = tmp_path / "outside-hardlink"
    outside.mkdir()
    victim = outside / "victim.bin"
    victim.write_bytes(payload)
    os.chmod(victim, 0o600)
    staged.unlink()
    os.link(victim, staged)
    victim_ino = victim.stat().st_ino
    real_read = os.read
    read_victim = {"value": False}

    def tracked_read(fd, size):
        if os.fstat(fd).st_ino == victim_ino:
            read_victim["value"] = True
        return real_read(fd, size)
    monkeypatch.setattr(m.os, "read", tracked_read)
    assert_txn_quarantined(aios, "ROLL_FORWARD_REJECTED")
    assert not read_victim["value"]
    assert victim.read_bytes() == payload
