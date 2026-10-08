"""WAL-backed durable state store.

The WAL is the recovery source for AIOS control-plane state. A WAL record is
only a persisted state transition; it is never an execution receipt and never
proves that an external effect occurred.
"""

from __future__ import annotations

import json
import os
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from .durable_wal import DurableTransitionLog


class WalStateStore:
    """StateStore implementation using append+fsync before snapshot commit.

    Save order is deliberately:
        WAL STATE_COMMITTED -> fsync -> atomic snapshot replace.

    If the process dies after the WAL commit and before snapshot replacement,
    load() replays the latest WAL state. A corrupt non-tail WAL record fails
    closed through DurableTransitionLog.
    """

    WAL_TRANSITION = "STATE_COMMITTED"

    def __init__(self, snapshot_path: str, wal_path: str | None = None) -> None:
        self.snapshot_path = Path(snapshot_path)
        self.wal_path = Path(wal_path) if wal_path else self.snapshot_path.with_suffix(
            self.snapshot_path.suffix + ".wal.jsonl"
        )
        self.snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        self.wal = DurableTransitionLog(str(self.wal_path))

    @staticmethod
    def _validate_state(value: Any) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise ValueError("durable state must be a mapping")
        return deepcopy(dict(value))

    def save(self, state: Mapping[str, Any]) -> None:
        candidate = self._validate_state(state)

        # The WAL is the durable commit point. DurableTransitionLog fsyncs
        # before append() returns.
        self.wal.append(
            transition=self.WAL_TRANSITION,
            payload={"state": candidate},
        )
        self._write_snapshot(candidate)

    def _write_snapshot(self, state: Mapping[str, Any]) -> None:
        parent = self.snapshot_path.parent
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{self.snapshot_path.name}.",
            suffix=".tmp",
            dir=str(parent),
            text=True,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(state, fh, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, self.snapshot_path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
            raise

    def load(self) -> Mapping[str, Any] | None:
        snapshot: dict[str, Any] | None = None
        if self.snapshot_path.exists():
            with self.snapshot_path.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)
            snapshot = self._validate_state(raw)

        replay = self.wal.replay()
        if not replay.records:
            return snapshot

        latest = replay.records[-1]
        if latest.get("transition") != self.WAL_TRANSITION:
            raise ValueError(
                f"unexpected durable state WAL transition: {latest.get('transition')!r}"
            )
        payload = latest.get("payload")
        if not isinstance(payload, Mapping) or "state" not in payload:
            raise ValueError("STATE_COMMITTED WAL payload is invalid")
        return self._validate_state(payload["state"])


__all__ = ["WalStateStore"]
