"""Crash-safe append-only transition WAL for AIOS.

Adapted from the verified OmniGet WAL pattern. This module provides durable
transition logging and replay only; a WAL record is never an execution receipt.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Mapping

from .secure_fs import (
    SecureWriteError, fd_matches_entry_at, open_regular_at, read_all_fd,
    relative_beneath, require_secure_platform, secure_parent_dir_beneath,
    write_all_fd,
)

try:  # POSIX only; non-POSIX fails closed in require_secure_platform().
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None


def _fsync_dir(dir_fd: int, label: str) -> None:
    """Persist directory-entry changes for the directory held by ``dir_fd``.

    ``label`` is informational (the WAL path); the fsync always targets the
    descriptor that was actually used for the file operation."""
    os.fsync(dir_fd)


_LOCK_MAX_ATTEMPTS = 16


def _acquire_lock_at(dir_fd: int, name: str) -> int:
    """Exclusive ``flock`` on ``name`` beneath ``dir_fd``.

    The lock file is opened no-follow, never truncated, must be a regular,
    singly-linked file, and after ``flock`` it must still be the inode named
    by ``name`` (otherwise it was replaced/unlinked and mutual exclusion would
    be split between inodes): retry, then fail closed."""
    for _ in range(_LOCK_MAX_ATTEMPTS):
        fd = open_regular_at(dir_fd, name, os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            if fd_matches_entry_at(dir_fd, name, fd):
                return fd
        except BaseException:
            os.close(fd)
            raise
        os.close(fd)
    raise DurableWalSecurityError("WAL lock file keeps being replaced; refusing")


def _release_lock(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


class DurableWalError(RuntimeError):
    """Base error for durable WAL failures."""


class DurableWalIntegrityError(DurableWalError):
    """Raised when committed WAL data fails integrity validation."""


class DurableWalSecurityError(DurableWalError):
    """Raised when the WAL, its lock or a parent is unsafe (symlink, special
    file, hard link, escape from the trusted root, untrusted owner/mode) or
    secure descriptor-relative I/O is unavailable. Never downgraded to an
    empty WAL."""


@dataclass(frozen=True)
class WalReplay:
    records: tuple[Mapping[str, Any], ...]
    dropped_tail_records: int


class DurableTransitionLog:
    """Append-only, fsynced JSONL journal with deterministic replay.

    Filesystem model (Batch 3): every operation opens the trusted ``root``
    (default: the WAL's parent directory) no-follow and owner/mode-checked,
    walks to the WAL's parent with descriptor-relative no-follow opens, and
    then works ONLY through that parent descriptor: the ``<wal>.lock`` file
    and the WAL itself are opened no-follow/non-blocking, ``fstat``-verified
    regular and singly linked. Append, replay, tail repair and fsync all use
    the same validated WAL descriptor; nothing is reopened by pathname.
    See core.secure_fs for the precise trust model and residual risks.

    Lock ordering: the WAL lock is a leaf lock. No other AIOS lock (e.g. the
    state-tree ``.mutation.lock``) is acquired while it is held.
    """

    VERSION = 1

    def __init__(self, path: str, *, root: str | None = None):
        self.path = os.path.abspath(path)
        self.root = os.path.abspath(root) if root is not None else os.path.dirname(self.path)
        try:
            self._rel = relative_beneath(self.root, path)
        except SecureWriteError as exc:
            raise DurableWalSecurityError(str(exc)) from exc
        self._lock_rel = self._rel + ".lock"
        self._lock = threading.RLock()

    @property
    def relative_path(self) -> str:
        return self._rel

    @contextmanager
    def _locked(self):
        """Hold the thread lock and the cross-process WAL lock; yield the
        validated parent directory fd and the WAL leaf name."""
        with self._lock:
            try:
                require_secure_platform()
                with secure_parent_dir_beneath(self.root, self._rel, create=True) as (dir_fd, name):
                    lock_fd = _acquire_lock_at(dir_fd, name + ".lock")
                    try:
                        yield dir_fd, name
                    finally:
                        _release_lock(lock_fd)
            except SecureWriteError as exc:
                raise DurableWalSecurityError(f"unsafe WAL location {self.path!r}: {exc}") from exc

    def _open_wal(self, dir_fd: int, name: str, *, write: bool) -> int | None:
        flags = (os.O_RDWR | os.O_CREAT | os.O_APPEND) if write else os.O_RDONLY
        try:
            return open_regular_at(dir_fd, name, flags)
        except FileNotFoundError:
            if write:
                raise
            return None

    @staticmethod
    def _canonical(record: Mapping[str, Any]) -> bytes:
        return (
            json.dumps(
                dict(record),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n"
        ).encode("utf-8")

    @classmethod
    def _checksum(cls, record: Mapping[str, Any]) -> str:
        return hashlib.sha256(cls._canonical(record)).hexdigest()

    def _append_locked(self, dir_fd: int, name: str, transition: str,
                       payload: Mapping[str, Any], match=None):
        fd = self._open_wal(dir_fd, name, write=True)
        try:
            data = read_all_fd(fd)
            replay, valid_length = self._parse(data)
            if replay.dropped_tail_records:
                # Repair in place on the SAME validated descriptor: the
                # committed prefix is preserved (never rewritten).
                os.ftruncate(fd, valid_length)
                os.fsync(fd)
                _fsync_dir(dir_fd, self.path)
                replay, _ = self._parse(read_all_fd(fd))
            if match is not None:
                existing = match(replay.records)
                if existing is not None:
                    return dict(existing), False
            body = {
                "version": self.VERSION,
                "sequence": len(replay.records) + 1,
                "transition": transition,
                "payload": dict(payload),
            }
            record = {**body, "checksum": self._checksum(body)}
            write_all_fd(fd, self._canonical(record))
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_dir(dir_fd, self.path)
        return dict(record), True

    def append(
        self, *, transition: str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if not isinstance(transition, str) or not transition.strip():
            raise ValueError("transition must be a non-empty string")
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a mapping")
        with self._locked() as (dir_fd, name):
            record, _ = self._append_locked(dir_fd, name, transition, payload)
            return record

    def append_once(
        self, *, transition: str, payload: Mapping[str, Any],
        unique_path: tuple[str, ...], unique_value: Any,
        scope_path: tuple[str, ...] = (), scope_value: Any = None,
    ) -> tuple[Mapping[str, Any], bool]:
        """Atomically append only if no committed record has the same key.

        The key is resolved inside the WAL process lock, so concurrent writers
        cannot both commit the same idempotency key.
        """
        if not isinstance(transition, str) or not transition.strip():
            raise ValueError("transition must be a non-empty string")
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a mapping")
        if not unique_path or not all(isinstance(part, str) and part for part in unique_path):
            raise ValueError("unique_path must contain non-empty strings")
        if not all(isinstance(part, str) and part for part in scope_path):
            raise ValueError("scope_path must contain strings")

        def resolve(value, path):
            current = value
            for part in path:
                if not isinstance(current, Mapping) or part not in current:
                    return None
                current = current[part]
            return current

        def match(records):
            for existing in records:
                if existing.get("transition") != transition:
                    continue
                existing_payload = existing.get("payload")
                if scope_path and resolve(existing_payload, scope_path) != scope_value:
                    continue
                if resolve(existing_payload, unique_path) == unique_value:
                    return existing
            return None

        with self._locked() as (dir_fd, name):
            return self._append_locked(dir_fd, name, transition, payload, match)

    def replay(self) -> WalReplay:
        """Replay only while holding the cross-process WAL lock."""
        with self._locked() as (dir_fd, name):
            fd = self._open_wal(dir_fd, name, write=False)
            if fd is None:
                return WalReplay((), 0)
            try:
                return self._parse(read_all_fd(fd))[0]
            finally:
                os.close(fd)

    @staticmethod
    def _split_lines(data: bytes) -> list[bytes]:
        # Same semantics as binary readlines(): split on b"\n" only.
        if not data:
            return []
        pieces = data.split(b"\n")
        lines = [piece + b"\n" for piece in pieces[:-1]]
        if pieces[-1]:
            lines.append(pieces[-1])
        return lines

    def _parse(self, data: bytes) -> tuple[WalReplay, int]:
        """Validate WAL bytes. Returns (replay, committed_prefix_length)."""
        records = []
        dropped = 0
        lines = self._split_lines(data)
        valid_length = 0

        for index, raw in enumerate(lines):
            # A record is committed only with its terminating newline. Even
            # valid JSON without it is an incomplete tail and must be dropped
            # before the next append.
            if index == len(lines) - 1 and raw and not raw.endswith(b"\n"):
                dropped += 1
                break
            if not raw.strip():
                raise DurableWalIntegrityError(
                    f"blank committed WAL record at line {index + 1}"
                )

            try:
                record = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise DurableWalIntegrityError(
                    f"invalid committed WAL record at line {index + 1}"
                )

            if not isinstance(record, dict):
                raise DurableWalIntegrityError(
                    f"WAL record {index + 1} is not an object"
                )

            checksum = record.get("checksum")
            body = {k: v for k, v in record.items() if k != "checksum"}
            if checksum != self._checksum(body):
                raise DurableWalIntegrityError(
                    f"WAL checksum mismatch at line {index + 1}"
                )
            if body.get("version") != self.VERSION:
                raise DurableWalIntegrityError(
                    f"unsupported WAL version at line {index + 1}"
                )
            if body.get("sequence") != len(records) + 1:
                raise DurableWalIntegrityError(
                    f"WAL sequence mismatch at line {index + 1}"
                )
            if (
                not isinstance(body.get("transition"), str)
                or not body["transition"].strip()
            ):
                raise DurableWalIntegrityError(
                    f"WAL transition missing at line {index + 1}"
                )
            if not isinstance(body.get("payload"), dict):
                raise DurableWalIntegrityError(
                    f"WAL payload invalid at line {index + 1}"
                )
            records.append(record)
            valid_length += len(raw)

        return WalReplay(tuple(records), dropped), valid_length


__all__ = [
    "DurableWalError",
    "DurableWalIntegrityError",
    "DurableWalSecurityError",
    "WalReplay",
    "DurableTransitionLog",
]
