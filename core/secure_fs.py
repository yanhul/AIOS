"""Descriptor-relative, no-follow filesystem operations beneath a root.

Trust boundary (what IS and IS NOT protected):

- The ANCESTORS of ``root`` (its parent chain) are TRUSTED. They are resolved
  by pathname (``Path.resolve``) and may be created with ``os.makedirs``. An
  attacker able to rename/replace a directory above ``root`` is outside this
  module's threat model; no protection is claimed against that.
- ``root`` itself is opened with ``O_NOFOLLOW | O_DIRECTORY`` relative to its
  resolved parent descriptor: a symlinked root is refused.
- Everything BENEATH ``root`` is untrusted. Each component is opened relative
  to the previously held directory descriptor with ``O_NOFOLLOW``; ``..``,
  ``.``, empty and absolute components are rejected lexically before any I/O,
  so neither ``..`` nor a symlink (intermediate or leaf) nor a rename race on
  an already-opened component can redirect an operation outside ``root``.
- Reads/locks verify the opened descriptor with ``fstat`` (regular file
  only), so FIFOs, devices, sockets and directories are refused, and open with
  ``O_NONBLOCK`` so a FIFO cannot block the open.

Platform: POSIX only (requires ``O_NOFOLLOW`` and ``dir_fd`` support). Every
public entry point fails closed with :class:`SecureWriteError` elsewhere
(including Windows); there is no pathname-based fallback.
"""
from __future__ import annotations

import errno
import os
import secrets
import stat
from pathlib import Path, PurePosixPath


class SecureWriteError(RuntimeError):
    pass


class UnsupportedPlatformError(SecureWriteError):
    """Secure descriptor-relative operations are unavailable on this platform."""


def _require_platform() -> None:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise UnsupportedPlatformError(
            "secure descriptor-relative operations are unsupported on this platform "
            "(POSIX with O_NOFOLLOW and dir_fd required)")


def atomic_write_beneath(root: str | os.PathLike[str], raw: str, content: str) -> None:
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise SecureWriteError("invalid repository write path")
    path = raw.replace("\\", "/")
    if len(path) >= 2 and path[1] == ":":
        raise SecureWriteError("repository write path must be relative")
    normalized = PurePosixPath(path)
    if normalized.is_absolute() or ".." in normalized.parts or not normalized.parts:
        raise SecureWriteError("repository write path escapes root")
    _require_platform()

    root_fd = _open_root_fd(root)
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
    """Open ``root`` (no-follow) relative to its trusted, resolved parent.

    Missing trusted ancestors are created (pathname-based; see module
    docstring). A missing root is created with mode 0700.
    """
    _require_platform()
    absolute = Path(os.path.abspath(os.fspath(root)))
    if not absolute.name:
        raise SecureWriteError("secure root must not be the filesystem root")
    os.makedirs(absolute.parent, exist_ok=True)
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
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise SecureWriteError("invalid relative path")
    value = raw.replace("\\", "/")
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
    except BaseException as exc:
        for fd in reversed(opened):
            os.close(fd)
        if isinstance(exc, OSError) and exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
            raise SecureWriteError("refusing symlinked or non-directory path component") from exc
        raise


def _walk_parent_or_close(root_fd: int, parts: tuple[str, ...], create: bool = False):
    """``_walk_parent`` that also closes ``root_fd`` if the walk fails."""
    try:
        return _walk_parent(root_fd, parts, create)
    except BaseException:
        os.close(root_fd)
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
    parent_fd, opened = _walk_parent_or_close(root_fd, parts, create=True)
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


_READ_FLAGS_EXTRA = getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)


def _open_regular_at(parent_fd: int, name: str, flags: int, mode: int = 0o600) -> int:
    """Open ``name`` beneath ``parent_fd`` no-follow; return fd only if regular.

    ``O_NONBLOCK`` keeps a FIFO from blocking the open; the type is then
    checked on the opened descriptor (no lstat/open race). On any rejection
    the descriptor is closed before raising.
    """
    try:
        fd = os.open(name, flags | os.O_NOFOLLOW | _READ_FLAGS_EXTRA, mode, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise SecureWriteError(f"refusing symlink: {name!r}") from exc
        if exc.errno == errno.ENXIO:  # e.g. socket / FIFO without peer
            raise SecureWriteError(f"refusing special file: {name!r}") from exc
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SecureWriteError(f"refusing non-regular file: {name!r}")
        os.set_blocking(fd, True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def secure_read_bytes_beneath(root, relative: str) -> bytes:
    """Read a REGULAR file beneath ``root``. Symlinks/special files raise
    :class:`SecureWriteError`; a genuinely missing file raises
    ``FileNotFoundError`` (never conflated with a security refusal)."""
    parts = _parts(relative)
    root_fd = _open_root_fd(root)
    try:
        parent_fd, opened = _walk_parent(root_fd, parts)
        try:
            fd = _open_regular_at(parent_fd, parts[-1], os.O_RDONLY)
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
    finally:
        os.close(root_fd)


def secure_regular_file_state_beneath(root, relative: str) -> bool:
    """Return True if ``relative`` is an existing regular file, False if it
    (or a parent directory) does not exist. Symlinks (leaf or intermediate),
    directories and special files raise :class:`SecureWriteError`."""
    parts = _parts(relative)
    root_fd = _open_root_fd(root)
    try:
        try:
            parent_fd, opened = _walk_parent(root_fd, parts)
        except FileNotFoundError:
            return False
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise SecureWriteError(f"refusing unsafe parent of {relative!r}") from exc
            raise
        try:
            try:
                st = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return False
            if not stat.S_ISREG(st.st_mode):
                raise SecureWriteError(f"refusing non-regular entry: {relative!r}")
            return True
        finally:
            for fd in reversed(opened):
                os.close(fd)
    finally:
        os.close(root_fd)


def secure_exists_beneath(root, relative: str) -> bool:
    parts = _parts(relative)
    root_fd = _open_root_fd(root)
    parent_fd, opened = _walk_parent_or_close(root_fd, parts)
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
    parent_fd, opened = _walk_parent_or_close(root_fd, parts)
    try:
        try:
            mode = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False).st_mode
            if stat.S_ISLNK(mode):
                raise SecureWriteError("refusing symlink directory")
            return stat.S_ISDIR(mode)
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
            try:
                child = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW, dir_fd=current)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
                    raise SecureWriteError(f"refusing symlinked or non-directory {part!r}") from exc
                raise
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
    parent_fd, opened = _walk_parent_or_close(root_fd, parts)
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
    parent_fd, opened = _walk_parent_or_close(root_fd, parts)
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


def secure_open_lock_beneath(root, relative: str) -> int:
    """Open (creating if absent, never truncating) a lock file directly
    beneath ``root``. Refuses symlinks, non-regular files and hard-linked
    files (``st_nlink != 1``). Caller owns the returned descriptor."""
    parts = _parts(relative)
    if len(parts) != 1:
        raise SecureWriteError("lock file must be directly beneath state root")
    root_fd = _open_root_fd(root)
    try:
        fd = _open_regular_at(root_fd, parts[0], os.O_RDWR | os.O_CREAT)
        try:
            if os.fstat(fd).st_nlink != 1:
                raise SecureWriteError("refusing hard-linked lock file")
        except BaseException:
            os.close(fd)
            raise
        return fd
    finally:
        os.close(root_fd)


def secure_fd_matches_beneath(root, relative: str, fd: int) -> bool:
    """True iff ``relative`` (no-follow) still names the inode held by ``fd``.

    Used after acquiring a lock to detect the lock file being unlinked or
    replaced between open and lock (which would split mutual exclusion)."""
    parts = _parts(relative)
    root_fd = _open_root_fd(root)
    try:
        parent_fd, opened = _walk_parent(root_fd, parts)
        try:
            try:
                st = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return False
            held = os.fstat(fd)
            return stat.S_ISREG(st.st_mode) and (st.st_dev, st.st_ino) == (held.st_dev, held.st_ino)
        finally:
            for fd_ in reversed(opened):
                os.close(fd_)
    finally:
        os.close(root_fd)
