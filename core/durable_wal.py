"""Crash-safe append-only transition WAL for AIOS.

Adapted from the verified OmniGet WAL pattern. This module provides durable
transition logging and replay only; a WAL record is never an execution receipt.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from typing import Any, Mapping


class _ProcessFileLock:
    """Cross-process lock for one WAL file."""

    def __init__(self, path: str):
        self.path = path + ".lock"
        self.fh = None

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.fh = open(self.path, "a+b")
        if os.name == "nt":
            import msvcrt
            self.fh.seek(0)
            while True:
                try:
                    msvcrt.locking(self.fh.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    continue
        else:
            import fcntl
            fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if os.name == "nt":
                import msvcrt
                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
        finally:
            self.fh.close()
        return False


class DurableWalError(RuntimeError):
    """Base error for durable WAL failures."""


class DurableWalIntegrityError(DurableWalError):
    """Raised when committed WAL data fails integrity validation."""


@dataclass(frozen=True)
class WalReplay:
    records: tuple[Mapping[str, Any], ...]
    dropped_tail_records: int


class DurableTransitionLog:
    """Append-only, fsynced JSONL journal with deterministic replay."""

    VERSION = 1

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self._lock = threading.RLock()

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

    def append(
        self, *, transition: str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if not isinstance(transition, str) or not transition.strip():
            raise ValueError("transition must be a non-empty string")
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a mapping")

        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with self._lock, _ProcessFileLock(self.path):
            replay = self._replay_unlocked()
            if replay.dropped_tail_records:
                self._truncate_incomplete_tail()
                replay = self._replay_unlocked()

            body = {
                "version": self.VERSION,
                "sequence": len(replay.records) + 1,
                "transition": transition,
                "payload": dict(payload),
            }
            record = {**body, "checksum": self._checksum(body)}
            with open(self.path, "ab") as fh:
                fh.write(self._canonical(record))
                fh.flush()
                os.fsync(fh.fileno())
            return dict(record)

    def replay(self) -> WalReplay:
        """Replay only while holding the cross-process WAL lock."""
        with self._lock, _ProcessFileLock(self.path):
            return self._replay_unlocked()

    def _truncate_incomplete_tail(self) -> None:
        with open(self.path, "rb") as fh:
            lines = fh.readlines()
        if not lines:
            return
        with open(self.path, "wb") as fh:
            fh.writelines(lines[:-1])
            fh.flush()
            os.fsync(fh.fileno())

    def _replay_unlocked(self) -> WalReplay:
        if not os.path.exists(self.path):
            return WalReplay((), 0)

        records = []
        dropped = 0
        with open(self.path, "rb") as fh:
            lines = fh.readlines()

        for index, raw in enumerate(lines):
            if not raw.strip():
                if index == len(lines) - 1:
                    dropped += 1
                    break
                raise DurableWalIntegrityError(
                    "blank WAL record before final tail"
                )

            try:
                record = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                if index == len(lines) - 1:
                    dropped += 1
                    break
                raise DurableWalIntegrityError(
                    f"invalid non-tail WAL record at line {index + 1}"
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

        return WalReplay(tuple(records), dropped)


__all__ = [
    "DurableWalError",
    "DurableWalIntegrityError",
    "WalReplay",
    "DurableTransitionLog",
]
