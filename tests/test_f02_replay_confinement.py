"""F-02-R1/R2: replay reads must remain confined to the L5 store."""
import hashlib
import os
from pathlib import Path

import pytest

from core import mutation as m

pytestmark = pytest.mark.skipif(not m._FD_SAFE, reason="requires dir_fd/O_NOFOLLOW")


def _make_batch(aios, payload):
    batch = aios / ".staging" / "batch-r2"
    batch.mkdir(parents=True)
    staged = batch / "payload.tmp"
    staged.write_bytes(payload)
    op = {"tmp": str(staged), "dest": str(aios / "entities" / "payload.json"),
          "digest": hashlib.sha256(payload).hexdigest()}
    journal = {"format": 2, "batch_id": "batch-r2", "ops": [op],
               "body_digest": m._journal_body_digest("batch-r2", [op])}
    (batch / "journal.v2.json").write_text(m.canonical_json(journal), encoding="utf-8")
    return batch


def test_batch_directory_swap_never_opens_external_staged_file(tmp_path, monkeypatch):
    aios = tmp_path / "store" / ".aios"
    (aios / "entities").mkdir(parents=True)
    (aios / ".staging").mkdir()
    batch = _make_batch(aios, b"trusted payload\n")
    parked = aios / ".staging" / "batch-r2-parked"
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "payload.tmp"
    victim.write_bytes(b"trusted payload\n")  # same digest, so digest-only checks cannot detect the redirect
    victim_ino = victim.stat().st_ino

    real_staged_name = m._staged_name
    swapped = {"done": False}

    def swap_after_lexical_validation(batch_dir, tmp):
        name = real_staged_name(batch_dir, tmp)
        if not swapped["done"]:
            os.rename(batch, parked)
            os.symlink(outside, batch, target_is_directory=True)
            swapped["done"] = True
        return name

    real_open = os.open
    opened_victim = {"value": False}

    def tracked_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        try:
            if os.fstat(fd).st_ino == victim_ino:
                opened_victim["value"] = True
        except OSError:
            pass
        return fd

    monkeypatch.setattr(m, "_staged_name", swap_after_lexical_validation)
    monkeypatch.setattr(m.os, "open", tracked_open)
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))

    assert swapped["done"]
    assert not opened_victim["value"], "external staged file was opened through swapped batch symlink"
    assert victim.read_bytes() == b"trusted payload\n"
    assert m.unresolved_quarantine(str(aios)) == ["batch-r2"]
    assert (aios / ".quarantine" / "batch-r2").is_symlink()
    assert (aios / ".quarantine" / "batch-r2.QUARANTINE.json").is_file()


def test_staged_digest_uses_descriptor_walk_and_valid_replay_still_succeeds(tmp_path):
    aios = tmp_path / "store" / ".aios"
    (aios / "entities").mkdir(parents=True)
    (aios / ".staging").mkdir()
    payload = b"ordinary payload\n"
    batch = _make_batch(aios, payload)
    assert m._digest_staged_confined(str(aios), batch.name, "payload.tmp") == hashlib.sha256(payload).hexdigest()
    m.recover_pending(str(aios))
    assert (aios / "entities" / "payload.json").read_bytes() == payload
    assert not batch.exists()
    assert m.unresolved_quarantine(str(aios)) == []


def test_destination_parent_swap_never_opens_external_destination(tmp_path, monkeypatch):
    aios = tmp_path / "store" / ".aios"
    entities = aios / "entities"
    entities.mkdir(parents=True)
    (aios / ".staging").mkdir()
    payload = b"matching destination bytes\n"
    batch = _make_batch(aios, payload)
    # Simulate a crash after installation: the staged entry is gone and the
    # destination is the only remaining copy named by the committed journal.
    (batch / "payload.tmp").unlink()
    (entities / "payload.json").write_bytes(payload)
    outside = tmp_path / "outside-destination"
    outside.mkdir()
    victim = outside / "payload.json"
    victim.write_bytes(payload)  # matching digest must not make a symlink path acceptable
    victim_ino = victim.stat().st_ino

    real_digest = m._digest_staged_confined
    swapped = {"done": False}
    def swap_after_staged_hash(*args):
        digest = real_digest(*args)  # None: staged file is absent
        if not swapped["done"]:
            os.rename(entities, aios / "entities-original")
            os.symlink(outside, entities, target_is_directory=True)
            swapped["done"] = True
        return digest

    real_open = os.open
    opened_victim = {"value": False}
    def tracked_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if os.fstat(fd).st_ino == victim_ino:
            opened_victim["value"] = True
        return fd

    monkeypatch.setattr(m, "_digest_staged_confined", swap_after_staged_hash)
    monkeypatch.setattr(m.os, "open", tracked_open)
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))
    assert swapped["done"]
    assert not opened_victim["value"], "external destination was opened through swapped parent symlink"
    assert victim.read_bytes() == payload
    assert m.unresolved_quarantine(str(aios)) == ["batch-r2"]


def test_staged_hardlink_is_rejected_before_external_inode_is_read(tmp_path, monkeypatch):
    aios = tmp_path / "store" / ".aios"
    (aios / "entities").mkdir(parents=True)
    (aios / ".staging").mkdir()
    payload = b"same bytes through a hard link\n"
    batch = _make_batch(aios, payload)
    staged = batch / "payload.tmp"
    outside = tmp_path / "outside-hardlink"
    outside.mkdir()
    victim = outside / "victim.bin"
    victim.write_bytes(payload)
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
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))
    assert not read_victim["value"]
    assert victim.read_bytes() == payload
    assert m.unresolved_quarantine(str(aios)) == ["batch-r2"]
