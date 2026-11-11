"""Descriptor-relative, no-follow repository writes.

POSIX writes walk directory descriptors with O_NOFOLLOW and replace relative
to the held parent descriptor. Unsupported platforms fail closed.
"""
from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path, PurePosixPath


class SecureWriteError(RuntimeError):
    pass


def atomic_write_beneath(root: str | os.PathLike[str], raw: str, content: str) -> None:
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise SecureWriteError("invalid repository write path")
    path = raw.replace("\\", "/")
    if len(path) >= 2 and path[1] == ":":
        raise SecureWriteError("repository write path must be relative")
    normalized = PurePosixPath(path)
    if normalized.is_absolute() or ".." in normalized.parts or not normalized.parts:
        raise SecureWriteError("repository write path escapes root")
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise SecureWriteError("secure descriptor-relative writes are unsupported on this platform")

    root_fd = os.open(Path(root).resolve(strict=True),
                      os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW)
    parent_fd = root_fd
    opened = []
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
        for part in normalized.parts[:-1]:
            try:
                child_fd = os.open(part, flags, dir_fd=parent_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(part, mode=0o755, dir_fd=parent_fd)
                except FileExistsError:
                    pass
                child_fd = os.open(part, flags, dir_fd=parent_fd)
            opened.append(child_fd)
            parent_fd = child_fd

        target_name = normalized.parts[-1]
        try:
            leaf_stat = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            leaf_stat = None
        if leaf_stat is not None and stat.S_ISLNK(leaf_stat.st_mode):
            raise SecureWriteError("refusing symlink target")

        temp_name = ".aios-write-" + secrets.token_hex(16)
        temp_fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                          0o600, dir_fd=parent_fd)
        try:
            with os.fdopen(temp_fd, "w", encoding="utf-8", newline="") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, target_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
    finally:
        for fd in reversed(opened):
            os.close(fd)
        os.close(root_fd)
