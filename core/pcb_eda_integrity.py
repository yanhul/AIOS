"""Integrity primitives adapted from ZiroEDA's lossless/content-addressed patterns.

AIOS does not import ZiroEDA code. This module only implements the architectural
invariants needed at the pcb.eda@1 boundary: exact input snapshots, deterministic
artifact manifests, and verify-before-commit evidence. Design semantics remain
owned by the external EDA Kit.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

INPUT_SUFFIXES = {".schdoc", ".pcbdoc", ".prjpcb", ".kicad_sch", ".kicad_pcb", ".kicad_pro"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot_inputs(root: Path) -> list[dict[str, Any]]:
    """Return a deterministic, content-addressed snapshot of EDA inputs."""
    if not root.is_dir():
        raise ValueError(f"input root is not a directory: {root}")
    items = []
    for p in sorted((x for x in root.rglob("*") if x.is_file()), key=lambda x: x.as_posix()):
        if p.suffix.lower() not in INPUT_SUFFIXES:
            continue
        items.append({
            "path": p.relative_to(root).as_posix(),
            "sha256": sha256_file(p),
            "size": p.stat().st_size,
        })
    if not items:
        raise ValueError("no supported EDA input files found")
    return items


def manifest_hash(manifest: list[Mapping[str, Any]]) -> str:
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def build_integrity_manifest(input_root: Path, output_root: Path) -> dict[str, Any]:
    inputs = snapshot_inputs(input_root)
    return {
        "schema": "aios-pcb-eda-integrity.v1",
        "algorithm": "sha256",
        "inputs": inputs,
        "input_manifest_sha256": manifest_hash(inputs),
        "output_root": str(output_root.resolve()),
        "verification": {
            "input_snapshot": "VERIFIED",
            "output_commit": "PENDING",
        },
    }


def verify_commit_manifest(manifest: Mapping[str, Any], receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Allow commit only when the Kit supplied an authoritative terminal receipt."""
    status = receipt.get("status")
    if status not in {"PASS", "BLOCKED", "INCONCLUSIVE"}:
        raise ValueError("invalid terminal receipt status")
    if receipt.get("schema") != "altium-audit-kit-result.v4":
        raise ValueError("unsupported Kit receipt schema")
    gates = receipt.get("gates")
    if status == "PASS" and not isinstance(gates, Mapping):
        raise ValueError("PASS requires gate evidence")
    result = dict(manifest)
    result["verification"] = {
        "input_snapshot": "VERIFIED",
        "output_commit": "VERIFIED" if status == "PASS" else "NOT_AUTHORIZED",
        "terminal_status": status,
        "receipt_schema": receipt["schema"],
    }
    return result
