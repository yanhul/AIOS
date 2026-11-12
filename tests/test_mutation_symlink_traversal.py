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
