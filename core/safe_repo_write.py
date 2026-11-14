"""Race-resistant repository writes using directory file descriptors.

Mutation is supported only where dir_fd operations and O_NOFOLLOW are available.
Unsupported platforms fail closed rather than falling back to path-based writes.
"""
from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path


_REQUIRED_DIR_FD = (os.open, os.mkdir, os.stat, os.unlink, os.rename)
_SUPPORTED = (
    os.name == "posix"
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "O_DIRECTORY")
    and all(fn in os.supports_dir_fd for fn in _REQUIRED_DIR_FD)
)


def atomic_write_beneath(root: str | os.PathLike[str], relative_path: str, content: str) -> None:
    """Atomically replace one regular file without following mutable path links."""
    if not _SUPPORTED:
        raise OSError("race-resistant dir_fd/O_NOFOLLOW writes are unavailable; mutation blocked")
    if not isinstance(relative_path, str) or not relative_path or relative_path.startswith("/"):
        raise ValueError("repository path must be relative")
    parts = relative_path.replace("\\", "/").split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("repository path contains an unsafe component")
    if not isinstance(content, str):
        raise TypeError("repository content must be text")

    # Resolve the root itself component-by-component from / and retain its
    # directory descriptor. This prevents a swapped root/ancestor path from
    # redirecting the later relative operations.
    absolute_root = os.path.abspath(os.fspath(root))
    root_parts = Path(absolute_root).parts[1:]
    anchor_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    root_fd = anchor_fd
    root_chain = []
    try:
        for component in root_parts:
            next_fd = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=root_fd,
            )
            root_chain.append(next_fd)
            root_fd = next_fd
    except Exception:
        for fd in reversed(root_chain):
            os.close(fd)
        os.close(anchor_fd)
        raise
    parent_fd = root_fd
    owned_fds = []
    temp_name = None
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, mode=0o755, dir_fd=parent_fd)
            except FileExistsError:
                pass
            child_fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd
            )
            owned_fds.append(child_fd)
            parent_fd = child_fd

        leaf = parts[-1]
        try:
            current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None and not stat.S_ISREG(current.st_mode):
            raise OSError("refusing to replace a non-regular repository target")

        # Preserve the existing file's permission bits (including executable
        # bits). New files retain the restrictive 0o600 default.
        target_mode = stat.S_IMODE(current.st_mode) if current is not None else 0o600
        temp_name = f".{leaf}.repair-{secrets.token_hex(12)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        temp_fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
        try:
            os.fchmod(temp_fd, target_mode)
            data = content.encode("utf-8")
            with os.fdopen(temp_fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.rename(
                temp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd
            )
            temp_name = None
            os.fsync(parent_fd)
        finally:
            if temp_name is not None:
                try:
                    os.unlink(temp_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
    finally:
        for fd in reversed(owned_fds):
            os.close(fd)
        for fd in reversed(root_chain):
            os.close(fd)
        os.close(anchor_fd)
