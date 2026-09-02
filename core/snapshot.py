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


class SnapshotExistsError(Exception):
    """Raised when a snapshot ID already exists on disk."""


class SnapshotDirError(Exception):
    """Raised when the snapshot target location is invalid."""


def _utc_id() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("SNAP-%Y%m%dT%H%M%SZ")


def _write_json(path: str, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False, sort_keys=True)


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
    if os.path.exists(snapshot_path):
        raise SnapshotExistsError(f"snapshot already exists: {snapshot_id}")

    os.makedirs(snapshot_path, exist_ok=True)
    _write_json(os.path.join(snapshot_path, "inventory.json"), {"artifacts": inventory})
    _write_json(os.path.join(snapshot_path, "entities.json"), {"entities": entities})
    _write_json(
        os.path.join(snapshot_path, "contradictions.json"),
        {"contradictions": contradictions},
    )
    _write_json(
        os.path.join(snapshot_path, "unresolved.json"),
        {"unresolved_classifications": unresolved},
    )
    _write_json(
        os.path.join(snapshot_path, "meta.json"),
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
    return snapshot_id, snapshot_path
