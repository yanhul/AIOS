from __future__ import annotations

import os

import pytest

from core.mutation import MutationError, commit_batch


pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX symlink regression")


def test_commit_batch_rejects_symlinked_parent_without_writing_outside(tmp_path):
    state_root = tmp_path / ".aios"
    outside = tmp_path / "outside"
    state_root.mkdir()
    outside.mkdir()
    (state_root / "effects").symlink_to(outside, target_is_directory=True)

    with pytest.raises(MutationError, match="secure mutation destination rejected"):
        commit_batch(state_root, [("effects/escape.json", {"payload": "must-not-escape"})])

    assert not (outside / "escape.json").exists()


def test_commit_batch_rejects_symlink_leaf_without_modifying_target(tmp_path):
    state_root = tmp_path / ".aios"
    outside = tmp_path / "outside.json"
    state_root.mkdir()
    outside.write_text('{"safe":true}\n', encoding="utf-8")
    (state_root / "effects").mkdir()
    (state_root / "effects" / "target.json").symlink_to(outside)

    with pytest.raises(MutationError, match="secure mutation destination rejected"):
        commit_batch(state_root, [("effects/target.json", {"payload": "must-not-overwrite"})])

    assert outside.read_text(encoding="utf-8") == '{"safe":true}\n'


def test_commit_batch_rejects_symlinked_staging_root(tmp_path):
    state_root = tmp_path / ".aios"
    outside = tmp_path / "outside"
    state_root.mkdir()
    outside.mkdir()
    (state_root / ".staging").symlink_to(outside, target_is_directory=True)
    with pytest.raises(Exception):
        commit_batch(state_root, [("effects/escape.json", {"payload": "blocked"})])
    assert list(outside.iterdir()) == []


def test_recovery_rejects_symlinked_journal_without_reading_outside(tmp_path):
    from core.mutation import recover_pending
    state_root = tmp_path / ".aios"
    batch = state_root / ".staging" / "batch-hostile"
    outside = tmp_path / "outside.json"
    batch.mkdir(parents=True)
    outside.write_text('{"not":"a journal"}', encoding="utf-8")
    (batch / "journal.json").symlink_to(outside)
    with pytest.raises(Exception):
        recover_pending(state_root)
    assert outside.read_text(encoding="utf-8") == '{"not":"a journal"}'


def test_recovery_rejects_symlinked_staged_payload_without_following_it(tmp_path):
    import hashlib
    import json
    from core.mutation import recover_pending
    state_root = tmp_path / ".aios"
    batch = state_root / ".staging" / "batch-hostile"
    batch.mkdir(parents=True)
    outside = tmp_path / "outside.tmp"
    payload = b'{"outside":true}\\n'
    outside.write_bytes(payload)
    journal = {"batch_id": "hostile", "ops": [{
        "tmp": str(outside), "tmp_rel": ".staging/batch-hostile/payload.tmp",
        "dest": str(state_root / "effects" / "escape.json"),
        "rel_dest": "effects/escape.json",
        "digest": hashlib.sha256(payload).hexdigest(),
    }]}
    (batch / "payload.tmp").symlink_to(outside)
    (batch / "journal.json").write_text(json.dumps(journal), encoding="utf-8")
    with pytest.raises(Exception):
        recover_pending(state_root)
    assert not (state_root / "effects" / "escape.json").exists()
    assert outside.read_bytes() == payload
