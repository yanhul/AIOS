import json
import os
import uuid

import pytest

from core.mutation import StateConflictError, commit_batch, recover_pending


def _batch(root):
    staging = root / ".staging"
    staging.mkdir(parents=True, exist_ok=True)
    batch_id = uuid.uuid4().hex
    batch = staging / f"batch-{batch_id}"
    batch.mkdir(mode=0o700)
    return batch_id, batch


def test_l5_recovery_preserves_orphan_batch_and_fails_closed(tmp_path):
    root = tmp_path / ".aios"
    batch_id, batch = _batch(root)

    with pytest.raises(StateConflictError, match="no journal"):
        recover_pending(str(root))

    assert batch.exists()
    assert list(batch.iterdir()) == []


def test_l5_recovery_rejects_journal_destination_escape(tmp_path):
    root = tmp_path / ".aios"
    batch_id, batch = _batch(root)
    tmp_name = f"{uuid.uuid4().hex}.tmp"
    journal = {
        "batch_id": batch_id,
        "ops": [{
            "tmp": str(batch / tmp_name),
            "dest": str(tmp_path / "outside.json"),
            "digest": "a" * 64,
        }],
    }
    journal_path = batch / "journal.json"
    journal_path.write_text(json.dumps(journal), encoding="utf-8")
    os.chmod(journal_path, 0o600)

    with pytest.raises(StateConflictError, match="escapes the store"):
        recover_pending(str(root))

    assert journal_path.exists()
    assert not (tmp_path / "outside.json").exists()


def test_l5_recovery_rejects_batch_id_mismatch(tmp_path):
    root = tmp_path / ".aios"
    _, batch = _batch(root)
    journal_path = batch / "journal.json"
    journal_path.write_text(json.dumps({"batch_id": "0" * 32, "ops": [{"bad": 1}]}), encoding="utf-8")
    os.chmod(journal_path, 0o600)

    with pytest.raises(StateConflictError, match="batch identity"):
        recover_pending(str(root))

    assert journal_path.exists()


def test_l5_mutation_lock_rejects_symlink(tmp_path):
    root = tmp_path / ".aios"
    root.mkdir()
    target = tmp_path / "attacker-controlled-lock"
    target.write_bytes(b"")
    (root / ".mutation.lock").symlink_to(target)

    with pytest.raises(StateConflictError, match="safely open"):
        recover_pending(str(root))

    assert target.read_bytes() == b""


def test_l5_commit_rejects_destination_path_escape(tmp_path):
    root = tmp_path / ".aios"

    with pytest.raises(StateConflictError, match="escapes the authority store"):
        commit_batch(str(root), [("../outside.json", {"state": "UNKNOWN"})])

    assert not (tmp_path / "outside.json").exists()
