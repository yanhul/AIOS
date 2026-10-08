"""Append-only durable transition log adapted from OmniGet's WAL pattern.

AIOS owns the semantics of the transitions written here. This primitive only
provides crash-safe append + replay: each record is fsynced before append()
returns, and a truncated final JSON record is treated as an incomplete tail,
not as a valid transition.

This is deliberately NOT an execution receipt and does not prove that an
external effect occurred. Callers must keep effect_id/attempt_id/receipt
semantics in the AIOS control plane.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from typing import Any, Mapping


class DurableWalError(RuntimeError):
    """Base error for durable transition-log failures."""


class DurableWalIntegrityError(DurableWalError):
    """Raised when a committed WAL record fails integrity validation."""


@dataclass(frozen=True)
class WalReplay:
    records: tuple[Mapping[str, Any], ...]
    dropped_tail_records: int


class DurableTransitionLog:
    """Small append-only, fsynced JSONL journal with deterministic replay."""

    VERSION = 1

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self._lock = threading.RLock()

    @staticmethod
    def _canonical(record: Mapping[str, Any]) -> bytes:
        return (json.dumps(dict(record), sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True) + "\n").encode("utf-8")

    @classmethod
    def _checksum(cls, record: Mapping[str, Any]) -> str:
        return hashlib.sha256(cls._canonical(record)).hexdigest()

    def append(self, *, transition: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(transition, str) or not transition.strip():
            raise ValueError("transition must be a non-empty string")
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a mapping")

        with self._lock:
            replay = self.replay()
            sequence = len(replay.records) + 1
            body = {
                "version": self.VERSION,
                "sequence": sequence,
                "transition": transition,
                "payload": dict(payload),
            }
            record = {**body, "checksum": self._checksum(body)}
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            data = self._canonical(record)
            with open(self.path, "ab") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            return dict(record)

    def replay(self) -> WalReplay:
        with self._lock:
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
                    raise DurableWalIntegrityError("blank WAL record before final tail")
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
                expected_sequence = len(records) + 1
                if body.get("sequence") != expected_sequence:
                    raise DurableWalIntegrityError(
                        f"WAL sequence mismatch at line {index + 1}"
                    )
                if not isinstance(body.get("transition"), str) or not body["transition"].strip():
                    raise DurableWalIntegrityError(
                        f"WAL transition missing at line {index + 1}"
                    )
                if not isinstance(body.get("payload"), dict):
                    raise DurableWalIntegrityError(
                        f"WAL payload invalid at line {index + 1}"
                    )
                records.append(record)

            return WalReplay(tuple(records), dropped)


__all__ = ["DurableWalError", "DurableWalIntegrityError", "WalReplay",
           "DurableTransitionLog"]
