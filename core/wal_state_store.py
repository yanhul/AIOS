"""WAL-backed durable namespace store shared by AIOS state and memory.

The WAL is the recovery source. A WAL record is a persisted mutation, never
an execution receipt and never proof that an external effect occurred.
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
    """Shared durable WAL boundary with isolated logical namespaces."""

    WAL_TRANSITION = "STATE_COMMITTED"
    NAMESPACE_TRANSITION = "NAMESPACE_COMMITTED"

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

    @staticmethod
    def _validate_namespace(namespace: str) -> str:
        if not isinstance(namespace, str) or not namespace.strip():
            raise ValueError("namespace must be a non-empty string")
        if namespace not in {"state", "memory"}:
            raise ValueError("unauthorized durable namespace")
        return namespace

    def save(self, state: Mapping[str, Any]) -> None:
        candidate = self._validate_state(state)
        self.wal.append(
            transition=self.WAL_TRANSITION,
            payload={"namespace": "state", "state": candidate},
        )
        self._write_snapshot(candidate)

    def commit_namespace(self, namespace: str, value: Any) -> None:
        namespace = self._validate_namespace(namespace)
        candidate = deepcopy(value)
        self.wal.append(
            transition=self.NAMESPACE_TRANSITION,
            payload={"namespace": namespace, "value": candidate},
        )
        if namespace == "state":
            if not isinstance(candidate, Mapping):
                raise ValueError("state namespace must be a mapping")
            self._write_snapshot(candidate)

    def _write_snapshot(self, state: Mapping[str, Any]) -> None:
        parent = self.snapshot_path.parent
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{self.snapshot_path.name}.", suffix=".tmp",
            dir=str(parent), text=True,
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

    def _latest(self, namespace: str):
        replay = self.wal.replay()
        latest = None
        for record in replay.records:
            payload = record.get("payload")
            if not isinstance(payload, Mapping):
                raise ValueError("durable WAL payload is invalid")
            if payload.get("namespace") != namespace:
                continue
            if record.get("transition") == self.WAL_TRANSITION and namespace == "state":
                latest = payload.get("state")
            elif record.get("transition") == self.NAMESPACE_TRANSITION:
                latest = payload.get("value")
        return latest

    def load(self) -> Mapping[str, Any] | None:
        latest = self._latest("state")
        if latest is not None:
            return self._validate_state(latest)
        if not self.snapshot_path.exists():
            return None
        with self.snapshot_path.open("r", encoding="utf-8") as fh:
            return self._validate_state(json.load(fh))

    def load_namespace(self, namespace: str, default: Any = None) -> Any:
        namespace = self._validate_namespace(namespace)
        latest = self._latest(namespace)
        if latest is not None:
            return deepcopy(latest)
        return deepcopy(default)


__all__ = ["WalStateStore"]
