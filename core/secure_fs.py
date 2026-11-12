"""Descriptor-relative, no-follow filesystem operations beneath a root.

Trust model (precise; see also docs in tests/test_secure_fs_batch2.py)
----------------------------------------------------------------------

1. ANCESTORS of ``root`` are TRUSTED. They are resolved by pathname
   (``Path.resolve``) and, only for creating operations, created with
   ``os.makedirs``. Renaming/replacing a directory above ``root`` is outside
   the threat model; no protection is claimed against it.

2. ``root`` and every directory traversed beneath it are opened with
   ``O_NOFOLLOW | O_DIRECTORY`` relative to the previously held descriptor.
   This is SYMLINK-TRAVERSAL protection only: a symlinked root, intermediate
   component or leaf is refused, and ``..``/``.``/empty/absolute components are
   rejected lexically before any I/O.

3. ``dir_fd``/``O_NOFOLLOW`` do NOT prevent NAMESPACE REPLACEMENT. A principal
   with write permission on a directory in the walked chain can rename an
   already-opened directory elsewhere (subsequent descriptor-relative
   operations then act on that moved directory, wherever it now lives) or
   swap a not-yet-opened component for another directory it controls.

4. Mitigation for (3), *state-tree mode* (``enforce_owner=True``, the default
   for every ``secure_*_beneath`` helper): ``root`` and every directory
   descriptor opened beneath it must be owned by the effective uid and must
   not be group- or world-writable (checked with ``fstat`` on the opened
   descriptor, so the check applies to the inode actually used). POSIX
   ``rename(2)``/``unlink(2)``/``link(2)`` inside a directory require write
   permission on it, so OTHER non-root uids cannot rename, replace or insert
   entries anywhere on the walked chain. Directories are created 0700.

   NOT covered: processes running as the same uid, root/CAP_FOWNER/
   CAP_DAC_OVERRIDE, and anyone controlling a trusted ancestor. Such a
   principal can still race renames or replace the lock file; they are
   equivalent to the AIOS process itself and are trusted by assumption.

5. Files are opened ``O_NOFOLLOW | O_NONBLOCK`` and verified as regular with
   ``fstat`` on the opened descriptor (FIFOs/devices/sockets/dirs refused).

6. Read-only helpers never create the root or any directory (``create=False``)
   and treat a missing root as missing.

``atomic_write_beneath`` (repository patch writes) defaults to
``enforce_owner=False``: repository checkouts commonly have 0775 directories,
so for that use only properties (2) and (5) hold.

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


_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_UNSAFE_COMPONENT_ERRNOS = (errno.ELOOP, errno.ENOTDIR, errno.EMLINK)


def _check_trusted_dir(fd: int, label: str) -> None:
    """Enforce the state-tree ownership invariant on an OPENED directory fd."""
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode):
        raise SecureWriteError(f"refusing non-directory: {label!r}")
    if st.st_uid != os.geteuid():
        raise SecureWriteError(
            f"refusing directory not owned by effective uid: {label!r} "
            f"(uid {st.st_uid} != {os.geteuid()})")
    if st.st_mode & 0o022:
        raise SecureWriteError(
            f"refusing group/world-writable directory: {label!r} "
            f"(mode {stat.S_IMODE(st.st_mode):04o})")


def _open_dir_at(parent_fd: int, name: str, *, create: bool, enforce_owner: bool) -> int:
    try:
        fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            raise
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        try:
            fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno in _UNSAFE_COMPONENT_ERRNOS:
                raise SecureWriteError(f"refusing symlinked or non-directory component {name!r}") from exc
            raise
    except OSError as exc:
        if exc.errno in _UNSAFE_COMPONENT_ERRNOS:
            raise SecureWriteError(f"refusing symlinked or non-directory component {name!r}") from exc
        raise
    if enforce_owner:
        try:
            _check_trusted_dir(fd, name)
        except BaseException:
            os.close(fd)
            raise
    return fd


def atomic_write_beneath(root: str | os.PathLike[str], raw: str, content: str, *,
                         enforce_owner: bool = False) -> None:
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise SecureWriteError("invalid repository write path")
    path = raw.replace("\\", "/")
    if len(path) >= 2 and path[1] == ":":
        raise SecureWriteError("repository write path must be relative")
    normalized = PurePosixPath(path)
    if normalized.is_absolute() or ".." in normalized.parts or not normalized.parts:
        raise SecureWriteError("repository write path escapes root")
    _require_platform()

    root_fd = _open_root_fd(root, create=True, enforce_owner=enforce_owner)
    parent_fd = root_fd
    opened = []
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
        for part in normalized.parts[:-1]:
            if enforce_owner:
                child_fd = _open_dir_at(parent_fd, part, create=True, enforce_owner=True)
            else:
                # Repository mode: unchanged batch-1 semantics (raw OSError).
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


def _open_root_fd(root: str | os.PathLike[str], *, create: bool = True,
                  enforce_owner: bool = True) -> int:
    """Open ``root`` (no-follow) relative to its trusted, resolved parent.

    ``create=True``: missing trusted ancestors are created (pathname-based;
    trusted by assumption, see module docstring) and a missing root is
    created 0700. ``create=False``: nothing is created; a missing root or
    ancestor raises ``FileNotFoundError``.
    """
    _require_platform()
    absolute = Path(os.path.abspath(os.fspath(root)))
    if not absolute.name:
        raise SecureWriteError("secure root must not be the filesystem root")
    if create:
        os.makedirs(absolute.parent, exist_ok=True)
    parent = absolute.parent.resolve(strict=True)
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        if create:
            try:
                os.mkdir(absolute.name, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                pass
        try:
            fd = os.open(absolute.name, _DIR_FLAGS, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno in _UNSAFE_COMPONENT_ERRNOS:
                raise SecureWriteError(f"refusing symlinked or non-directory root: {os.fspath(root)!r}") from exc
            raise
    finally:
        os.close(parent_fd)
    if enforce_owner:
        try:
            _check_trusted_dir(fd, os.fspath(root))
        except BaseException:
            os.close(fd)
            raise
    return fd


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
            child = _open_dir_at(current, part, create=create, enforce_owner=True)
            opened.append(child)
            current = child
        return current, opened
    except BaseException:
        for fd in reversed(opened):
            os.close(fd)
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
    root_fd = _open_root_fd(root, create=True)
    opened = []
    try:
        current = root_fd
        for part in parts:
            child = _open_dir_at(current, part, create=True, enforce_owner=True)
            opened.append(child)
            current = child
    finally:
        for fd in reversed(opened):
            os.close(fd)
        os.close(root_fd)


def secure_write_bytes_beneath(root, relative: str, payload: bytes) -> None:
    parts = _parts(relative)
    root_fd = _open_root_fd(root, create=True)
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
        if exc.errno in (errno.ENXIO, errno.EISDIR):  # socket/FIFO w/o peer; directory
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
    :class:`SecureWriteError`; a genuinely missing file (or root) raises
    ``FileNotFoundError`` (never conflated with a security refusal).
    Never creates anything."""
    parts = _parts(relative)
    root_fd = _open_root_fd(root, create=False)
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


def secure_lstat_beneath(root, relative: str):
    """No-follow ``lstat`` of ``relative`` beneath ``root`` via a secure walk.

    Returns ``None`` if the root, a parent or the leaf is missing. Unsafe
    parents (symlink, non-directory, untrusted owner/mode) raise
    :class:`SecureWriteError`. The leaf itself is NOT followed; callers decide
    what an ``S_ISLNK``/special result means. Never creates anything."""
    parts = _parts(relative)
    try:
        root_fd = _open_root_fd(root, create=False)
    except FileNotFoundError:
        return None
    try:
        try:
            parent_fd, opened = _walk_parent(root_fd, parts)
        except FileNotFoundError:
            return None
        try:
            try:
                return os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
        finally:
            for fd in reversed(opened):
                os.close(fd)
    finally:
        os.close(root_fd)


def secure_regular_file_state_beneath(root, relative: str) -> bool:
    """Return True if ``relative`` is an existing regular file, False if it
    (or a parent directory, or the root) does not exist. Symlinks (leaf or
    intermediate), directories and special files raise
    :class:`SecureWriteError`."""
    st = secure_lstat_beneath(root, relative)
    if st is None:
        return False
    if not stat.S_ISREG(st.st_mode):
        raise SecureWriteError(f"refusing non-regular entry: {relative!r}")
    return True


def secure_exists_beneath(root, relative: str) -> bool:
    return secure_lstat_beneath(root, relative) is not None


def secure_is_dir_beneath(root, relative: str) -> bool:
    st = secure_lstat_beneath(root, relative)
    if st is None:
        return False
    if stat.S_ISLNK(st.st_mode):
        raise SecureWriteError("refusing symlink directory")
    return stat.S_ISDIR(st.st_mode)


def secure_listdir_beneath(root, relative: str | None) -> list[str]:
    """List a directory beneath ``root`` (``relative=None`` lists the root).
    Missing -> ``FileNotFoundError``; never creates anything."""
    parts = () if relative is None else _parts(relative)
    root_fd = _open_root_fd(root, create=False)
    current = root_fd
    opened = []
    try:
        for part in parts:
            child = _open_dir_at(current, part, create=False, enforce_owner=True)
            opened.append(child)
            current = child
        return sorted(os.listdir(current))
    finally:
        for fd in reversed(opened):
            os.close(fd)
        os.close(root_fd)


def secure_unlink_beneath(root, relative: str) -> None:
    parts = _parts(relative)
    root_fd = _open_root_fd(root, create=False)
    parent_fd, opened = _walk_parent_or_close(root_fd, parts)
    try:
        os.unlink(parts[-1], dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        for fd in reversed(opened):
            os.close(fd)
        os.close(root_fd)


def _remove_tree_at(parent_fd: int, name: str) -> None:
    fd = _open_dir_at(parent_fd, name, create=False, enforce_owner=True)
    try:
        for child in os.listdir(fd):
            st = os.stat(child, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                _remove_tree_at(fd, child)
            else:
                # Symlinks/special files are unlinked as entries, never followed.
                os.unlink(child, dir_fd=fd)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent_fd)


def secure_rmtree_beneath(root, relative: str) -> None:
    parts = _parts(relative)
    try:
        root_fd = _open_root_fd(root, create=False)
    except FileNotFoundError:
        return
    try:
        parent_fd, opened = _walk_parent(root_fd, parts)
    except FileNotFoundError:
        os.close(root_fd)
        return
    except BaseException:
        os.close(root_fd)
        raise
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


def secure_open_lock_beneath(root, relative: str, *, create: bool = True) -> int:
    """Open (never truncating) a lock file directly beneath ``root``.

    ``create=True`` creates the lock (and root) if absent; ``create=False``
    raises ``FileNotFoundError`` instead and creates nothing. Refuses
    symlinks, non-regular files and hard-linked files (``st_nlink != 1``).
    Caller owns the returned descriptor."""
    parts = _parts(relative)
    if len(parts) != 1:
        raise SecureWriteError("lock file must be directly beneath state root")
    root_fd = _open_root_fd(root, create=create)
    try:
        flags = os.O_RDWR | (os.O_CREAT if create else 0)
        fd = _open_regular_at(root_fd, parts[0], flags)
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
    st = secure_lstat_beneath(root, relative)
    if st is None:
        return False
    held = os.fstat(fd)
    return stat.S_ISREG(st.st_mode) and (st.st_dev, st.st_ino) == (held.st_dev, held.st_ino)
