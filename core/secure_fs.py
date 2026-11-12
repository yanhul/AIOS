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


def _open_root_fd(root: str | os.PathLike[str]) -> int:
    absolute = Path(os.path.abspath(os.fspath(root)))
    parent = absolute.parent.resolve(strict=True)
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        try:
            os.mkdir(absolute.name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        return os.open(absolute.name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _parts(raw: str) -> tuple[str, ...]:
    if not isinstance(raw, str) or not raw or "\\x00" in raw:
        raise SecureWriteError("invalid relative path")
    value = raw.replace("\\\\", "/")
    p = PurePosixPath(value)
    if p.is_absolute() or any(x in ("", ".", "..") for x in value.split("/")):
        raise SecureWriteError("path must remain beneath root")
    return tuple(p.parts)


def _walk_parent(root_fd: int, parts: tuple[str, ...], create: bool = False):
    current = root_fd
    opened = []
    try:
        for part in parts[:-1]:
            try:
                child = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, mode=0o700, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW, dir_fd=current)
            opened.append(child)
            current = child
        return current, opened
    except Exception:
        for fd in reversed(opened):
            os.close(fd)
        raise


def secure_makedirs_beneath(root, relative: str) -> None:
    parts = _parts(relative)
    root_fd = _open_root_fd(root)
    opened = []
    try:
        current = root_fd
        for part in parts:
            try:
                child = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW, dir_fd=current)
            except FileNotFoundError:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW, dir_fd=current)
            opened.append(child)
            current = child
    finally:
        for fd in reversed(opened):
            os.close(fd)
        os.close(root_fd)


def secure_write_bytes_beneath(root, relative: str, payload: bytes) -> None:
    parts = _parts(relative)
    root_fd = _open_root_fd(root)
    parent_fd, opened = _walk_parent(root_fd, parts, create=True)
    try:
        name = parts[-1]
        try:
            st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            st = None
        if st is not None and stat.S_ISLNK(st.st_mode):
            raise SecureWriteError("refusing symlink target")
        temp = ".aios-tmp-" + secrets.token_hex(16)
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            try:
                os.unlink(temp, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
    finally:
        for fd in reversed(opened):
            os.close(fd)
        os.close(root_fd)


def secure_read_bytes_beneath(root, relative: str) -> bytes:
    parts = _parts(relative)
    root_fd = _open_root_fd(root)
    parent_fd, opened = _walk_parent(root_fd, parts)
    try:
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            chunks = []
            while True:
                block = os.read(fd, 1048576)
                if not block:
                    return b"".join(chunks)
                chunks.append(block)
        finally:
            os.close(fd)
    finally:
        for fd in reversed(opened):
            os.close(fd)
        os.close(root_fd)


def secure_exists_beneath(root, relative: str) -> bool:
    parts = _parts(relative)
    root_fd = _open_root_fd(root)
    parent_fd, opened = _walk_parent(root_fd, parts)
    try:
        try:
            os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False
    finally:
        for fd in reversed(opened):
            os.close(fd)
        os.close(root_fd)


def secure_is_dir_beneath(root, relative: str) -> bool:
    parts = _parts(relative)
    root_fd = _open_root_fd(root)
    parent_fd, opened = _walk_parent(root_fd, parts)
    try:
        try:
            return stat.S_ISDIR(os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False).st_mode)
        except FileNotFoundError:
            return False
    finally:
        for fd in reversed(opened):
            os.close(fd)
        os.close(root_fd)


def secure_listdir_beneath(root, relative: str) -> list[str]:
    parts = _parts(relative)
    root_fd = _open_root_fd(root)
    current = root_fd
    opened = []
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW, dir_fd=current)
            opened.append(child)
            current = child
        return sorted(os.listdir(current))
    finally:
        for fd in reversed(opened):
            os.close(fd)
        os.close(root_fd)


def secure_unlink_beneath(root, relative: str) -> None:
    parts = _parts(relative)
    root_fd = _open_root_fd(root)
    parent_fd, opened = _walk_parent(root_fd, parts)
    try:
        os.unlink(parts[-1], dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        for fd in reversed(opened):
            os.close(fd)
        os.close(root_fd)


def _remove_tree_at(parent_fd: int, name: str) -> None:
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        for child in os.listdir(fd):
            st = os.stat(child, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                _remove_tree_at(fd, child)
            else:
                os.unlink(child, dir_fd=fd)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent_fd)


def secure_rmtree_beneath(root, relative: str) -> None:
    parts = _parts(relative)
    root_fd = _open_root_fd(root)
    parent_fd, opened = _walk_parent(root_fd, parts)
    try:
        try:
            st = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISDIR(st.st_mode):
            _remove_tree_at(parent_fd, parts[-1])
        else:
            os.unlink(parts[-1], dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        for fd in reversed(opened):
            os.close(fd)
        os.close(root_fd)


def secure_open_lock_beneath(root, relative: str):
    parts = _parts(relative)
    if len(parts) != 1:
        raise SecureWriteError("lock file must be directly beneath state root")
    root_fd = _open_root_fd(root)
    try:
        return os.open(parts[0], os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=root_fd)
    finally:
        os.close(root_fd)
