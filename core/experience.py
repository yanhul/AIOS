"""AIOS experience ledger.

Experience is reusable history, never authority. Records bind a task to a
versioned capability, action, evidence and outcome. The ledger is append-only:
identical replay is idempotent, while identity collisions are rejected.

No record here can activate, promote, authorize, or redefine policy.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Iterable, Mapping

from .mutation import TransitionError, canonical_json, commit_batch

EXPERIENCE_DIR = "experience"
OUTCOMES = frozenset({"PASS", "BLOCKED", "INCONCLUSIVE"})
VERIFICATION_LEVELS = frozenset({
    "OBSERVED", "EVIDENCED", "VERIFIED_DIGITAL", "VERIFIED_PHYSICAL", "PROMOTED"
})


class ExperienceError(ValueError):
    pass


def _required_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExperienceError(f"{name} must be a non-empty string")
    return value


def _normalize_refs(refs: Iterable[str], name: str) -> tuple[str, ...]:
    if isinstance(refs, (str, bytes)):
        raise ExperienceError(f"{name} must be an iterable of references")
    out = []
    for ref in refs:
        out.append(_required_text(ref, f"{name} item"))
    return tuple(dict.fromkeys(out))


def experience_identity(record: Mapping[str, Any]) -> str:
    """Return the immutable logical identity of an experience event.

    Notes are intentionally excluded: they are annotations, not identity.
    This means an attempted rewrite of the same logical experience with
    different notes is detected as an identity collision rather than creating
    a second history entry.
    """
    logical = {
        k: v for k, v in record.items()
        if k not in {"experience_id", "notes"}
    }
    return hashlib.sha256(canonical_json(logical).encode("utf-8")).hexdigest()


def record_experience(
    aios_dir: str,
    *,
    task_id: str,
    capability_id: str,
    capability_version: str,
    action: str,
    outcome: str,
    evidence_refs: Iterable[str],
    verification_levels: Iterable[str],
    actor: str,
    notes: str = "",
) -> dict[str, Any]:
    """Persist one append-only experience record through the AIOS commit kernel."""
    for value, name in (
        (task_id, "task_id"), (capability_id, "capability_id"),
        (capability_version, "capability_version"), (action, "action"),
        (actor, "actor"),
    ):
        _required_text(value, name)
    if outcome not in OUTCOMES:
        raise ExperienceError(f"invalid outcome: {outcome}")
    if not isinstance(notes, str):
        raise ExperienceError("notes must be a string")
    refs = _normalize_refs(evidence_refs, "evidence_refs")
    levels = _normalize_refs(verification_levels, "verification_levels")
    unknown = set(levels) - VERIFICATION_LEVELS
    if unknown:
        raise ExperienceError(f"unsupported verification levels: {sorted(unknown)}")

    record: dict[str, Any] = {
        "record_type": "EXPERIENCE",
        "task_id": task_id,
        "capability_id": capability_id,
        "capability_version": capability_version,
        "action": action,
        "outcome": outcome,
        "evidence_refs": list(refs),
        "verification_levels": list(levels),
        "actor": actor,
        "notes": notes,
    }
    identity = experience_identity(record)
    record["experience_id"] = "XP-" + identity
    rel = os.path.join(EXPERIENCE_DIR, record["experience_id"] + ".json")
    path = os.path.join(aios_dir, rel)

    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            existing = json.load(fh)
        if canonical_json(existing) == canonical_json(record):
            return {**existing, "replayed": True}
        raise TransitionError("experience identity collision with different content")

    event = {
        "kind": "experience",
        "action": "experience.recorded",
        "experience_id": record["experience_id"],
        "task_id": task_id,
        "capability_id": capability_id,
        "capability_version": capability_version,
        "outcome": outcome,
        "actor": actor,
    }
    commit_batch(aios_dir, [
        (rel, record),
        (os.path.join("events", "experience-" + record["experience_id"] + ".json"), event),
    ])
    return {**record, "replayed": False}


def load_experience(aios_dir: str) -> list[dict[str, Any]]:
    directory = os.path.join(aios_dir, EXPERIENCE_DIR)
    if not os.path.isdir(directory):
        return []
    records = []
    for filename in sorted(os.listdir(directory)):
        if not filename.endswith(".json"):
            continue
        with open(os.path.join(directory, filename), "r", encoding="utf-8") as fh:
            record = json.load(fh)
        records.append(record)
    return records


__all__ = ["ExperienceError", "EXPERIENCE_DIR", "OUTCOMES", "VERIFICATION_LEVELS", "experience_identity", "record_experience", "load_experience"]
