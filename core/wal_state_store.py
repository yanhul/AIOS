"""WAL-backed durable namespace store shared by AIOS state and memory.

The WAL is the recovery source. A WAL record is a persisted mutation, never
an execution receipt and never proof that an external effect occurred.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from .durable_wal import DurableTransitionLog

_MEMORY_WRITE_TOKEN = object()
from .secure_fs import (
    SecureWriteError, open_regular_at, read_all_fd, relative_beneath,
    require_secure_platform, secure_parent_dir_beneath, write_all_fd,
)


def _fsync_dir(dir_fd: int, label: Path) -> None:
    """Persist atomic snapshot replacement for the directory held by
    ``dir_fd`` (``label`` is informational)."""
    os.fsync(dir_fd)


class StoreRootMismatchError(SecureWriteError):
    """A store's WAL/snapshot is not bound to the required trusted root."""


class WalStateStore:
    """Shared durable WAL boundary with isolated logical namespaces."""

    WAL_TRANSITION = "STATE_COMMITTED"
    NAMESPACE_TRANSITION = "NAMESPACE_COMMITTED"

    MEMORY_SUBDIR = "memory"

    def __init__(self, snapshot_path: str, wal_path: str | None = None, *,
                 root: str | None = None) -> None:
        """Bind snapshot and WAL to ONE trusted state root.

        ``root`` defaults to the snapshot's parent directory. Both paths must
        lie beneath ``root`` (no ``..``, no escape); every I/O operation then
        walks from a no-follow, owner/mode-checked descriptor for ``root``.
        A WAL outside the snapshot's root raises :class:`StoreRootMismatchError`.
        """
        snapshot = Path(snapshot_path)
        wal = Path(wal_path) if wal_path else snapshot.with_suffix(snapshot.suffix + ".wal.jsonl")
        self._root = os.path.abspath(root) if root is not None else os.path.dirname(
            os.path.abspath(snapshot))
        try:
            self._snapshot_rel = relative_beneath(self._root, snapshot)
            self._wal_rel = relative_beneath(self._root, wal)
        except SecureWriteError as exc:
            raise StoreRootMismatchError(
                f"snapshot and WAL must share trusted root {self._root!r}: {exc}") from exc
        stem, _, _ = self._snapshot_rel.rpartition("/")
        name = Path(self._snapshot_rel.rsplit("/", 1)[-1])
        self._memory_rel = (stem + "/" if stem else "") + name.stem + ".memory.json"
        self.snapshot_path = Path(self._root, *self._snapshot_rel.split("/"))
        self.wal_path = Path(self._root, *self._wal_rel.split("/"))
        self.wal = DurableTransitionLog(str(self.wal_path), root=self._root)
        # Create/validate the root and the snapshot's parent securely now so
        # an unsafe location fails at construction, not mid-transaction.
        require_secure_platform()
        with secure_parent_dir_beneath(self._root, self._snapshot_rel, create=True):
            pass

    @classmethod
    def for_aios_dir(cls, aios_dir: str, name: str = "state.json") -> "WalStateStore":
        """Store bound to the AIOS state root, under ``<aios_dir>/memory/``."""
        if not isinstance(name, str) or "/" in name or "\\" in name or name in ("", ".", ".."):
            raise ValueError("invalid store name")
        root = os.path.abspath(aios_dir)
        return cls(os.path.join(root, cls.MEMORY_SUBDIR, name), root=root)

    @property
    def root(self) -> str:
        return self._root

    def assert_bound_to(self, aios_dir: str) -> None:
        """Refuse unless this store (snapshot AND WAL) is rooted exactly at
        ``aios_dir``. Binding is to the root descriptor walk, not a path
        prefix: intermediate components beneath the root are opened no-follow
        on every operation."""
        expected = os.path.abspath(aios_dir)
        if self._root != expected:
            raise StoreRootMismatchError(
                f"store root {self._root!r} is not the trusted state root {expected!r}")
        wal = self.wal
        if (type(wal) is not DurableTransitionLog or wal.root != self._root
                or wal.relative_path != self._wal_rel):
            raise StoreRootMismatchError("store WAL is not bound to the trusted state root")

    @property
    def _memory_snapshot_path(self) -> Path:
        return Path(self._root, *self._memory_rel.split("/"))

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
        if namespace == "memory":
            raise PermissionError("memory writes require governed persist_memory")
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
        if namespace == "memory":
            raise PermissionError("memory writes require governed persist_memory")
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
        if namespace == "memory":
            raise PermissionError("memory writes require governed persist_memory")
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

    def _append_governed_memory(self, envelope: Mapping[str, Any], token: object) -> tuple[Any, bool]:
        if token is not _MEMORY_WRITE_TOKEN:
            raise PermissionError("memory writes require governed persist_memory")
        if not isinstance(envelope, Mapping):
            raise ValueError("memory envelope must be a mapping")
        mutation_id = envelope.get("mutation_id")
        if not isinstance(mutation_id, str) or not mutation_id.strip():
            raise ValueError("memory mutation_id is required")
        record, appended = self.wal.append_once(
            transition="NAMESPACE_APPENDED",
            payload={"namespace": "memory", "item": deepcopy(dict(envelope))},
            unique_path=("item", "mutation_id"), unique_value=mutation_id,
            scope_path=("namespace",), scope_value="memory",
        )
        payload = record.get("payload")
        item = payload.get("item") if isinstance(payload, Mapping) else None
        if not isinstance(item, Mapping):
            raise ValueError("durable memory WAL item is invalid")
        if appended:
            latest = self._latest("memory")
            if not isinstance(latest, list):
                raise ValueError("memory WAL projection must be a list")
            self._write_namespace_snapshot("memory", latest)
        return deepcopy(dict(item)), appended

    def _write_json_atomic(self, rel: str, value: Any) -> None:
        """Atomic snapshot replace, entirely descriptor-relative.

        The temp file is created O_EXCL|O_NOFOLLOW in the validated parent
        directory fd, written and fsynced, then renamed over the target with
        ``renameat`` on the same fd; the directory fd is fsynced. An existing
        target that is not a regular file (symlink, FIFO, dir, ...) is
        refused before anything is written. The temp entry is unlinked
        (descriptor-relative) on every failure path."""
        data = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False) + "\n").encode("utf-8")
        label = Path(self._root, *rel.split("/"))
        with secure_parent_dir_beneath(self._root, rel, create=True) as (dir_fd, name):
            try:
                st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                st = None
            if st is not None and not stat.S_ISREG(st.st_mode):
                raise SecureWriteError(f"refusing non-regular snapshot target: {rel!r}")
            tmp = f".{name}.{secrets.token_hex(12)}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=dir_fd)
            replaced = False
            try:
                try:
                    write_all_fd(fd, data)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                replaced = True
                _fsync_dir(dir_fd, label)
            finally:
                if not replaced:
                    try:
                        os.unlink(tmp, dir_fd=dir_fd)
                    except FileNotFoundError:
                        pass

    def _read_json(self, rel: str) -> tuple[bool, Any]:
        """(exists, value). Missing root/parent/file -> (False, None). Any
        unsafe entry raises SecureWriteError (never treated as missing)."""
        try:
            with secure_parent_dir_beneath(self._root, rel, create=False) as (dir_fd, name):
                try:
                    fd = open_regular_at(dir_fd, name, os.O_RDONLY)
                except FileNotFoundError:
                    return False, None
                try:
                    raw = read_all_fd(fd)
                finally:
                    os.close(fd)
        except FileNotFoundError:
            return False, None
        return True, json.loads(raw.decode("utf-8"))

    def _write_snapshot(self, state: Mapping[str, Any]) -> None:
        self._write_json_atomic(self._snapshot_rel, state)

    def _write_namespace_snapshot(self, namespace: str, value: Any) -> None:
        if namespace == "state":
            self._write_snapshot(value)
        elif namespace == "memory":
            self._write_json_atomic(self._memory_rel, value)

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
        exists, value = self._read_json(self._snapshot_rel)
        if not exists:
            return None
        return self._validate_state(value)

    def load_namespace(self, namespace: str, default: Any = None) -> Any:
        namespace = self._validate_namespace(namespace)
        latest = self._latest(namespace)
        if latest is not None:
            return deepcopy(latest)
        rel = self._memory_rel if namespace == "memory" else self._snapshot_rel
        exists, value = self._read_json(rel)
        if exists:
            return deepcopy(value)
        return deepcopy(default)


__all__ = ["WalStateStore", "StoreRootMismatchError"]
