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

    @property
    def _memory_snapshot_path(self) -> Path:
        return self.snapshot_path.with_name(self.snapshot_path.stem + ".memory.json")

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
        if namespace == "state" and not isinstance(candidate, Mapping):
            raise ValueError("state namespace must be a mapping")
        self.wal.append(
            transition=self.NAMESPACE_TRANSITION,
            payload={"namespace": namespace, "value": candidate},
        )
        self._write_namespace_snapshot(namespace, candidate)

    def append_namespace(self, namespace: str, item: Any) -> None:
        """Append one namespace item as its own fsynced WAL record.

        Unlike read/modify/commit, this operation does not lose concurrent
        appends: the WAL's process lock serializes each append and replay folds
        the append records into the latest namespace projection.
        """
        namespace = self._validate_namespace(namespace)
        if namespace == "state":
            raise ValueError("append is not authorized for state namespace")
        self.wal.append(
            transition="NAMESPACE_APPENDED",
            payload={"namespace": namespace, "item": deepcopy(item)},
        )
        latest = self._latest(namespace)
        if latest is None:
            latest = []
        if not isinstance(latest, list):
            raise ValueError("append namespace projection must be a list")
        self._write_namespace_snapshot(namespace, latest)

    def append_namespace_once(
        self, namespace: str, item: Any, *, item_key: str, key_value: str
    ) -> tuple[Any, bool]:
        """Atomically append one item under a unique namespace key.

        Returns (committed_item, appended); an existing key is returned
        without writing a second WAL record.
        """
        namespace = self._validate_namespace(namespace)
        if namespace == "state":
            raise ValueError("append is not authorized for state namespace")
        if not isinstance(item, Mapping):
            raise ValueError("idempotent namespace item must be a mapping")
        if not isinstance(item_key, str) or not item_key.strip():
            raise ValueError("item_key must be a non-empty string")
        if not isinstance(key_value, str) or not key_value.strip():
            raise ValueError("key_value must be a non-empty string")
        if item.get(item_key) != key_value:
            raise ValueError("item does not contain the requested idempotency key")
        record, appended = self.wal.append_once(
            transition="NAMESPACE_APPENDED",
            payload={"namespace": namespace, "item": deepcopy(dict(item))},
            unique_path=("item", item_key),
            unique_value=key_value,
            scope_path=("namespace",),
            scope_value=namespace,
        )
        committed_payload = record.get("payload")
        if not isinstance(committed_payload, Mapping):
            raise ValueError("durable WAL payload is invalid")
        committed_item = committed_payload.get("item")
        if not isinstance(committed_item, Mapping):
            raise ValueError("durable WAL item is invalid")
        if appended:
            latest = self._latest(namespace)
            if latest is None:
                latest = []
            if not isinstance(latest, list):
                raise ValueError("append namespace projection must be a list")
            self._write_namespace_snapshot(namespace, latest)
        return deepcopy(dict(committed_item)), appended

    def _write_json_atomic(self, path: Path, value: Any) -> None:
        parent = path.parent
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(parent), text=True
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(value, fh, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
            raise

    def _write_snapshot(self, state: Mapping[str, Any]) -> None:
        self._write_json_atomic(self.snapshot_path, state)

    def _write_namespace_snapshot(self, namespace: str, value: Any) -> None:
        if namespace == "state":
            self._write_snapshot(value)
        elif namespace == "memory":
            self._write_json_atomic(self._memory_snapshot_path, value)

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
            elif record.get("transition") == "NAMESPACE_APPENDED":
                if latest is None:
                    latest = []
                if not isinstance(latest, list):
                    raise ValueError("appended namespace WAL state is not a list")
                latest = [*latest, deepcopy(payload.get("item"))]
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
        snapshot = self._memory_snapshot_path if namespace == "memory" else self.snapshot_path
        if snapshot.exists():
            with snapshot.open("r", encoding="utf-8") as fh:
                return deepcopy(json.load(fh))
        return deepcopy(default)


__all__ = ["WalStateStore"]
