"""Append-only experience memory for governed AIOS self-improvement (M10).

This store records positive AND negative outcomes with immutable provenance.
It does not infer truth from model memory: every record carries explicit
evidence references and execution lineage. Writes use core.mutation.commit_batch
so records and audit events are committed atomically on the local AIOS state
store. This module is not yet a Firestore persistence adapter.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
from typing import Any, Mapping

from .mutation import (
    MutationError,
    TransitionError,
    _require_actor,
    canonical_json,
    commit_batch,
    event_identity,
)

__all__ = ["ExperienceError", "record_experience", "load_experiences"]

_SHA = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_OUTCOMES = frozenset({"PASS", "BLOCKED", "INCONCLUSIVE"})
_VERIFICATION = frozenset({"VERIFIED_DIGITAL", "VERIFIED_PHYSICAL"})


class ExperienceError(MutationError):
    """Invalid experience or provenance."""


def _required(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExperienceError(f"{field} must be a non-empty string")
    return value.strip()


def _refs(values: Any) -> list[str]:
    if not isinstance(values, list) or not values:
        raise ExperienceError("evidence_refs must be a non-empty list")
    refs = [_required(value, "evidence_ref") for value in values]
    if len(set(refs)) != len(refs):
        raise ExperienceError("evidence_refs must be unique")
    return sorted(refs)


def _identity(record: Mapping[str, Any]) -> str:
    logical = {k: v for k, v in record.items() if k not in {"created_at", "record_id", "identity"}}
    return hashlib.sha256(canonical_json(logical).encode("utf-8")).hexdigest()


def _event(record: Mapping[str, Any], actor: str) -> dict[str, Any]:
    return {
        "kind": "mutation",
        "action": "experience.recorded",
        "actor": actor,
        "record_type": "EXPERIENCE",
        "record_id": record["record_id"],
        "record_identity": record["identity"],
        "capability_id": record["capability_id"],
        "task_id": record["task_id"],
        "outcome": record["outcome"],
        "effect_id": record["effect_id"],
        "attempt_id": record["attempt_id"],
        "receipt_id": record["receipt_id"],
    }


def _event_path(event_id: str) -> str:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return os.path.join("events", f"EVT-{stamp}-{event_id}.json")


def _require_event(aios_dir: str, record: Mapping[str, Any]) -> None:
    events_dir = os.path.join(aios_dir, "events")
    for filename in sorted(os.listdir(events_dir)) if os.path.isdir(events_dir) else []:
        if not filename.endswith(".json"):
            continue
        try:
            with open(os.path.join(events_dir, filename), "r", encoding="utf-8") as fh:
                stored = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        if stored.get("record_id") != record.get("record_id"):
            continue
        logical = {k: v for k, v in stored.items() if k not in {"timestamp_utc", "event_id"}}
        event_id = stored.get("event_id")
        if not isinstance(event_id, str) or event_identity(logical) != event_id:
            continue
        if filename != f"EVT-{filename.split('-', 2)[1]}-{event_id}.json":
            continue
        if logical != _event(record, stored.get("actor")):
            continue
        return
    raise TransitionError(
        f"experience {record.get('record_id')} has no matching integrity-bound audit event"
    )


def record_experience(
    aios_dir: str, *, capability_id: str, capability_version: str,
    task_id: str, outcome: str, contributor: str, evidence_refs: list[str],
    run_id: str, source_commit: str, artifact_digest: str, actor: str,
    effect_id: str | None = None, attempt_id: str | None = None,
    receipt_id: str | None = None, verifier: str | None = None,
    evaluation_id: str | None = None, verification_status: str | None = None,
    summary: str = "",
) -> dict[str, Any]:
    """Append an immutable task/capability/outcome record.

    PASS is accepted only with complete effect->attempt->receipt lineage,
    evidence, a different verifier identity, a linked evaluation, and a
    recognized digital/physical verification level. Non-PASS outcomes are
    preserved as negative experience, never converted into success.
    """
    _require_actor(actor)
    capability_id = _required(capability_id, "capability_id")
    capability_version = _required(capability_version, "capability_version")
    task_id = _required(task_id, "task_id")
    contributor = _required(contributor, "contributor")
    run_id = _required(run_id, "run_id")
    source_commit = _required(source_commit, "source_commit").lower()
    artifact_digest = _required(artifact_digest, "artifact_digest").lower()
    refs = _refs(evidence_refs)
    if not _COMMIT.fullmatch(source_commit):
        raise ExperienceError("source_commit must be a 40/64-character Git commit SHA")
    if not _SHA.fullmatch(artifact_digest):
        raise ExperienceError("artifact_digest must be a 64-character SHA-256 digest")
    if outcome not in _OUTCOMES:
        raise ExperienceError(f"outcome must be one of {sorted(_OUTCOMES)}")
    lineage = (effect_id, attempt_id, receipt_id)
    if any(v is not None for v in lineage) and not all(
        isinstance(v, str) and v.strip() for v in lineage
    ):
        raise ExperienceError("effect_id, attempt_id and receipt_id must be supplied together")
    if outcome == "PASS":
        if not all(lineage):
            raise ExperienceError("PASS requires exact effect_id -> attempt_id -> receipt_id lineage")
        verifier = _required(verifier, "verifier")
        evaluation_id = _required(evaluation_id, "evaluation_id")
        if verifier == contributor:
            raise ExperienceError("self-verification is forbidden")
        if verification_status not in _VERIFICATION:
            raise ExperienceError("PASS requires VERIFIED_DIGITAL or VERIFIED_PHYSICAL")
    elif verification_status is not None and verification_status not in _VERIFICATION:
        raise ExperienceError("verification_status is not a recognized verification level")
    if not isinstance(summary, str):
        raise ExperienceError("summary must be a string")

    record: dict[str, Any] = {
        "record_type": "EXPERIENCE",
        "capability_id": capability_id,
        "capability_version": capability_version,
        "task_id": task_id,
        "outcome": outcome,
        "contributor": contributor,
        "evidence_refs": refs,
        "run_id": run_id,
        "source_commit": source_commit,
        "artifact_digest": artifact_digest,
        "effect_id": effect_id,
        "attempt_id": attempt_id,
        "receipt_id": receipt_id,
        "verifier": verifier,
        "evaluation_id": evaluation_id,
        "verification_status": verification_status,
        "summary": summary,
    }
    identity = _identity(record)
    record.update({
        "record_id": "XP-" + identity,
        "identity": identity,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds"),
    })
    relative_path = os.path.join("experiences", record["record_id"] + ".json")
    destination = os.path.join(aios_dir, relative_path)

    if os.path.exists(destination):
        with open(destination, "r", encoding="utf-8") as fh:
            existing = json.load(fh)
        if canonical_json(existing) != canonical_json(record):
            raise TransitionError(f"immutable experience identity collision: {record['record_id']}")
        _require_event(aios_dir, record)
        return {"experience_id": record["record_id"], "outcome": outcome, "replayed": True}

    event = _event(record, actor)
    event_id = event_identity(event)
    event_path = _event_path(event_id)
    event_record = {
        **event,
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "event_id": event_id,
    }

    def precondition(root: str) -> None:
        if os.path.exists(os.path.join(root, relative_path)):
            raise TransitionError("concurrent append detected; reload experience state")
        if os.path.exists(os.path.join(root, event_path)):
            raise TransitionError("audit event path collision")

    commit_batch(aios_dir, [
        (relative_path, record),
        (event_path, event_record),
    ], precondition=precondition)
    return {
        "experience_id": record["record_id"],
        "outcome": outcome,
        "replayed": False,
        "event_file": os.path.basename(event_path),
    }


def load_experiences(aios_dir: str) -> dict[str, dict[str, Any]]:
    """Load only identity-valid experiences with matching immutable audit events."""
    root = os.path.join(aios_dir, "experiences")
    out: dict[str, dict[str, Any]] = {}
    if not os.path.isdir(root):
        return out
    for filename in sorted(os.listdir(root)):
        if not filename.endswith(".json"):
            continue
        try:
            with open(os.path.join(root, filename), "r", encoding="utf-8") as fh:
                record = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise TransitionError(f"invalid persisted experience {filename!r}") from exc
        if not isinstance(record, dict) or record.get("record_type") != "EXPERIENCE":
            raise TransitionError(f"invalid persisted experience {filename!r}: wrong record type")
        identity = record.get("identity")
        record_id = record.get("record_id")
        if not isinstance(identity, str) or record_id != "XP-" + identity or identity != _identity(record):
            raise TransitionError(f"experience {filename!r} has invalid content identity")
        if filename != record_id + ".json" or record_id in out:
            raise TransitionError(f"duplicate or non-canonical experience identity {record_id!r}")
        _require_event(aios_dir, record)
        out[record_id] = record
    return out
