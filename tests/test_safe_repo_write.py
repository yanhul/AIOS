from __future__ import annotations

import os

import pytest

from core.safe_repo_write import atomic_write_beneath


def test_atomic_write_creates_nested_file_without_path_based_following(tmp_path):
    atomic_write_beneath(tmp_path, "nested/deeper/module.py", "VALUE = 2\n")
    assert (tmp_path / "nested/deeper/module.py").read_text(encoding="utf-8") == "VALUE = 2\n"


@pytest.mark.skipif(os.name != "posix", reason="dirfd/O_NOFOLLOW writer is POSIX-only")
def test_atomic_write_rejects_symlinked_parent(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir()
    (tmp_path / "alias").symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        atomic_write_beneath(tmp_path, "alias/payload.txt", "owned")
    assert not (outside / "payload.txt").exists()


@pytest.mark.skipif(os.name != "posix", reason="dirfd/O_NOFOLLOW writer is POSIX-only")
def test_atomic_write_replaces_neither_nor_follows_symlink_target(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside-file")
    outside.write_text("original", encoding="utf-8")
    (tmp_path / "alias.txt").symlink_to(outside)
    with pytest.raises(OSError, match="non-regular"):
        atomic_write_beneath(tmp_path, "alias.txt", "tampered")
    assert outside.read_text(encoding="utf-8") == "original"


def test_atomic_write_rejects_traversal(tmp_path):
    with pytest.raises(ValueError, match="unsafe"):
        atomic_write_beneath(tmp_path, "../outside.txt", "nope")

@pytest.mark.skipif(os.name != "posix", reason="dirfd/O_NOFOLLOW writer is POSIX-only")
def test_atomic_write_preserves_existing_permission_bits(tmp_path):
    target = tmp_path / "run_tool.sh"
    target.write_text("#!/bin/sh\\nexit 0\\n", encoding="utf-8")
    target.chmod(0o751)

    atomic_write_beneath(tmp_path, "run_tool.sh", "#!/bin/sh\\necho repaired\\n")

    assert target.read_text(encoding="utf-8") == "#!/bin/sh\\necho repaired\\n"
    assert target.stat().st_mode & 0o777 == 0o751
