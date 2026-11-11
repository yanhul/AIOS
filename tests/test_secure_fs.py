from __future__ import annotations

import errno
import os

import pytest

from core import secure_fs


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-relative write primitive")
def test_atomic_write_creates_nested_file(tmp_path):
    secure_fs.atomic_write_beneath(tmp_path, "nested/module.py", "VALUE = 7\n")
    assert (tmp_path / "nested/module.py").read_text(encoding="utf-8") == "VALUE = 7\n"


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-relative write primitive")
def test_symlink_swap_after_root_open_is_rejected(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "nested").mkdir()
    (outside / "module.py").write_text("SAFE = True\n", encoding="utf-8")

    real_open = os.open
    root_opened = False

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal root_opened
        result = real_open(path, flags, mode, dir_fd=dir_fd)
        if not root_opened and dir_fd is None:
            root_opened = True
            (root / "nested").rename(root / "nested-original")
            (root / "nested").symlink_to(outside, target_is_directory=True)
        return result

    monkeypatch.setattr(secure_fs.os, "supports_dir_fd", set(os.supports_dir_fd) | {swapping_open})
    monkeypatch.setattr(secure_fs.os, "open", swapping_open)
    with pytest.raises(OSError) as caught:
        secure_fs.atomic_write_beneath(root, "nested/module.py", "PWNED = True\n")
    assert caught.value.errno in (errno.ELOOP, errno.ENOTDIR)
    assert (outside / "module.py").read_text(encoding="utf-8") == "SAFE = True\n"


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-relative write primitive")
def test_atomic_write_rejects_symlink_leaf(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("SAFE\n", encoding="utf-8")
    (tmp_path / "target.txt").symlink_to(outside)
    with pytest.raises(secure_fs.SecureWriteError, match="symlink"):
        secure_fs.atomic_write_beneath(tmp_path, "target.txt", "PWNED\n")
    assert outside.read_text(encoding="utf-8") == "SAFE\n"
