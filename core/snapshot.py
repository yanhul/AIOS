"""Immutable AIOS state snapshots.

A snapshot is a directory ``SNAP-<unique-id>`` under a project's
``.aios/snapshots/``. Once created it is never overwritten: creating a
snapshot with an existing ID raises ``SnapshotExistsError``. The snapshot
records the inventory, imported entities, unresolved classifications and
contradictions, plus importer metadata, so provenance is preserved.
"""

import datetime
import json
import os
import uuid

from .secure_fs import (
    SecureWriteError, secure_exists_beneath, secure_makedirs_beneath,
    secure_write_bytes_beneath,
)


class SnapshotExistsError(Exception):
    """Raised when a snapshot ID already exists on disk."""


class SnapshotDirError(Exception):
    """Raised when the snapshot target location is invalid."""


def _utc_id() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("SNAP-%Y%m%dT%H%M%SZ")


def _write_json(root: str, rel: str, payload: dict) -> None:
    """Atomic, descriptor-relative, no-follow write beneath ``root``."""
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)
    secure_write_bytes_beneath(root, rel, text.encode("utf-8"))



def _write_meta(root: str, rel_dir: str, snapshot_id: str, metadata) -> None:
    _write_json(
        root, f"{rel_dir}/meta.json",
        {
            # Status is set exactly once here ("OBSERVED") and never
            # rewritten: commitment is derived from the audit log
            # (core.reconcile.snapshot_status), preserving immutability.
            "status": "OBSERVED",
            "snapshot_id": snapshot_id,
            "created_utc": datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "uuid": str(uuid.uuid4()),
            "immutable": True,
            "metadata": metadata,
        },
    )


def create_snapshot(
    snapshots_root: str,
    inventory,
    entities,
    contradictions,
    unresolved,
    metadata,
    snapshot_id: str = None,
) -> tuple:
    """Create a snapshot directory and write its contents.

    Returns (snapshot_id, snapshot_path).
    """
    snapshot_id = snapshot_id or _utc_id()
    if os.path.basename(snapshot_id) != snapshot_id or not snapshot_id.startswith("SNAP-"):
        raise SnapshotDirError(f"invalid snapshot id: {snapshot_id!r}")
    snapshot_path = os.path.join(snapshots_root, snapshot_id)
    # The parent of ``snapshots_root`` (normally ``.aios``) is the secure root;
    # ``snapshots/`` and the snapshot directory are walked no-follow and
    # owner/mode-checked (core.secure_fs). Symlinked components are refused
    # with SnapshotDirError; nothing is written through them.
    root = os.path.dirname(os.path.abspath(snapshots_root))
    base = os.path.basename(os.path.abspath(snapshots_root))
    rel_dir = f"{base}/{snapshot_id}"
    try:
        exists = secure_exists_beneath(root, rel_dir)
    except (OSError, SecureWriteError) as exc:
        raise SnapshotDirError(f"unsafe snapshot location: {snapshots_root!r}") from exc
    if exists:
        raise SnapshotExistsError(f"snapshot already exists: {snapshot_id}")

    try:
        secure_makedirs_beneath(root, rel_dir)
        _write_json(root, f"{rel_dir}/inventory.json", {"artifacts": inventory})
        _write_json(root, f"{rel_dir}/entities.json", {"entities": entities})
        _write_json(root, f"{rel_dir}/contradictions.json",
                    {"contradictions": contradictions})
        _write_json(root, f"{rel_dir}/unresolved.json",
                    {"unresolved_classifications": unresolved})
        _write_meta(root, rel_dir, snapshot_id, metadata)
    except SecureWriteError as exc:
        raise SnapshotDirError(f"unsafe snapshot location: {snapshots_root!r}: {exc}") from exc
    return snapshot_id, snapshot_path
