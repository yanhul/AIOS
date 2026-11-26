"""F-02-R3: journal reads and cleanup must remain directory-FD confined."""
import hashlib
import os

import pytest

from core import mutation as m

pytestmark = pytest.mark.skipif(not m._FD_SAFE, reason="requires dir_fd/O_NOFOLLOW")


def _batch(aios, payload=b"safe\n"):
    batch = aios / ".staging" / "batch-r3"
    batch.mkdir(parents=True)
    staged = batch / "payload.tmp"
    staged.write_bytes(payload)
    op = {"tmp": str(staged), "dest": str(aios / "entities" / "payload.json"),
          "digest": hashlib.sha256(payload).hexdigest()}
    journal = {"format": 2, "batch_id": "batch-r3", "ops": [op],
               "body_digest": m._journal_body_digest("batch-r3", [op])}
    (batch / "journal.v2.json").write_text(m.canonical_json(journal), encoding="utf-8")
    return batch


def test_journal_symlink_is_not_opened_and_batch_is_quarantined(tmp_path, monkeypatch):
    aios = tmp_path / "store" / ".aios"
    (aios / "entities").mkdir(parents=True)
    (aios / ".staging").mkdir()
    batch = _batch(aios)
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "journal.v2.json"
    victim.write_text("{}", encoding="utf-8")
    victim_ino = victim.stat().st_ino
    (batch / "journal.v2.json").unlink()
    os.symlink(victim, batch / "journal.v2.json")

    real_open = os.open
    opened = {"value": False}
    def tracked_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if os.fstat(fd).st_ino == victim_ino:
            opened["value"] = True
        return fd
    monkeypatch.setattr(m.os, "open", tracked_open)

    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))
    assert not opened["value"]
    assert victim.read_text(encoding="utf-8") == "{}"
    assert m.unresolved_quarantine(str(aios)) == ["batch-r3"]


def test_journal_unlink_uses_original_batch_fd_after_directory_swap(tmp_path, monkeypatch):
    aios = tmp_path / "store" / ".aios"
    (aios / "entities").mkdir(parents=True)
    (aios / ".staging").mkdir()
    batch = _batch(aios, b"must install\n")
    parked = aios / ".staging" / "batch-r3-parked"
    outside = tmp_path / "outside"
    outside.mkdir()
    external_journal = outside / "journal.v2.json"
    external_journal.write_text("do not delete", encoding="utf-8")

    real_apply = m._apply_op
    swapped = {"value": False}
    def apply(*args, **kwargs):
        result = real_apply(*args, **kwargs)
        if not swapped["value"]:
            os.rename(batch, parked)
            os.symlink(outside, batch, target_is_directory=True)
            swapped["value"] = True
        return result
    monkeypatch.setattr(m, "_apply_op", apply)

    m.recover_pending(str(aios))
    assert swapped["value"]
    assert external_journal.read_text(encoding="utf-8") == "do not delete"
    assert (aios / "entities" / "payload.json").read_bytes() == b"must install\n"
    assert not (aios / ".staging" / "batch-r3").is_symlink()
    # The renamed original batch is a later, uncommitted cleanup candidate.
    assert (parked / "journal.v2.json").exists() is False


def test_journal_hardlink_is_rejected_before_external_inode_is_read(tmp_path, monkeypatch):
    aios = tmp_path / "store" / ".aios"
    (aios / "entities").mkdir(parents=True)
    (aios / ".staging").mkdir()
    batch = _batch(aios)
    outside = tmp_path / "outside-hardlink"
    outside.mkdir()
    victim = outside / "journal.json"
    victim.write_bytes((batch / "journal.v2.json").read_bytes())
    (batch / "journal.v2.json").unlink()
    os.link(victim, batch / "journal.v2.json")
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
    assert victim.exists()
    assert m.unresolved_quarantine(str(aios)) == ["batch-r3"]


def test_commit_staging_writes_stay_on_open_batch_fd_after_path_swap(tmp_path, monkeypatch):
    aios = tmp_path / "store" / ".aios"
    outside = tmp_path / "outside-commit"
    outside.mkdir()
    victim = outside / "victim.txt"
    victim.write_text("preserve", encoding="utf-8")
    before = victim.read_bytes()
    staging = aios / ".staging"
    real_write = m._write_staged_at
    swapped = {"value": False, "name": None}

    def swap_then_write(batch_fd, name, payload):
        if not swapped["value"]:
            [batch_name] = os.listdir(staging)
            swapped["name"] = batch_name
            os.rename(staging / batch_name, staging / (batch_name + "-parked"))
            os.symlink(outside, staging / batch_name, target_is_directory=True)
            swapped["value"] = True
        return real_write(batch_fd, name, payload)

    monkeypatch.setattr(m, "_write_staged_at", swap_then_write)
    with pytest.raises(m.LedgerBlockedError):
        m.commit_batch(str(aios), [("entities/payload.json", {"v": 1})])

    assert swapped["value"]
    assert victim.read_bytes() == before
    assert list(outside.iterdir()) == [victim]
    assert m.unresolved_quarantine(str(aios)) == [swapped["name"]]
    parked = staging / (swapped["name"] + "-parked")
    assert (parked / "journal.v2.json").is_file()
    assert list(outside.iterdir()) == [victim]


def test_commit_journal_unlink_remains_fd_confined_if_batch_swaps_after_identity_check(tmp_path, monkeypatch):
    aios = tmp_path / "store" / ".aios"
    outside = tmp_path / "outside-commit-cleanup"
    outside.mkdir()
    external_journal = outside / "journal.v2.json"
    external_journal.write_text("preserve", encoding="utf-8")
    real_stat = os.stat
    swapped = {"value": False, "name": None}

    def stat(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if (not swapped["value"] and isinstance(path, str) and path.startswith("batch-")
                and kwargs.get("dir_fd") is not None and kwargs.get("follow_symlinks") is False):
            staging = aios / ".staging"
            swapped["name"] = path
            os.rename(staging / path, staging / (path + "-parked"))
            os.symlink(outside, staging / path, target_is_directory=True)
            swapped["value"] = True
        return result

    monkeypatch.setattr(m.os, "stat", stat)
    result = m.commit_batch(str(aios), [("entities/payload.json", {"v": 1})])
    assert result == [str(aios / "entities" / "payload.json")]
    assert swapped["value"]
    assert external_journal.read_text(encoding="utf-8") == "preserve"
    assert not (aios / ".staging" / swapped["name"]).is_symlink()
    assert (aios / ".staging" / (swapped["name"] + "-parked")).is_dir()


def test_non_directory_batch_entry_is_quarantined_and_blocks_store(tmp_path):
    aios = tmp_path / "store" / ".aios"
    (aios / "entities").mkdir(parents=True)
    staging = aios / ".staging"
    staging.mkdir()
    bad = staging / "batch-not-a-directory"
    bad.write_text("not a batch directory", encoding="utf-8")
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))
    assert (aios / ".quarantine" / "batch-not-a-directory").is_file()
    assert m.unresolved_quarantine(str(aios)) == ["batch-not-a-directory"]
    with pytest.raises(m.LedgerBlockedError):
        m.recover_pending(str(aios))
