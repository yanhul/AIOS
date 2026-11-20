"""Cloud Tasks transport envelope contract.

This module validates delivery references only. It does not authorize effects,
claim attempts, or call providers. Firestore records remain authoritative.
"""
from __future__ import annotations

from hashlib import sha256
import math
import re
from collections.abc import Mapping
from typing import Any

SCHEMA = "aios.effect.dispatch.v1"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_FIELDS = {
    "schema", "effect_id", "attempt_id", "expected_revision",
    "dispatch_event_digest", "issued_at", "expires_at",
}


class DispatchTaskRejected(ValueError):
    """A transport task is malformed, stale, expired, or not bound to Firestore."""


def deterministic_task_name(effect_id: str, attempt_id: str) -> str:
    """Stable Cloud Tasks task ID for enqueue reconciliation and deduplication."""
    if not isinstance(effect_id, str) or not effect_id.strip():
        raise ValueError("effect_id is required")
    if not isinstance(attempt_id, str) or not attempt_id.strip():
        raise ValueError("attempt_id is required")
    digest = sha256(f"{effect_id}\0{attempt_id}".encode("utf-8")).hexdigest()
    return "aios-" + digest


def dispatch_event_digest(effect_id: str, attempt_id: str) -> str:
    """Digest matching the immutable DISPATCHED event identity in Firestore."""
    import json

    raw = json.dumps(
        {"event": "DISPATCHED", "effect_id": effect_id, "attempt_id": attempt_id},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    )
    return sha256(raw.encode("utf-8")).hexdigest()


def validate_dispatch_task(
    payload: Mapping[str, Any], *, effect: Mapping[str, Any],
    attempt: Mapping[str, Any], now: float,
) -> str:
    """Validate a task against freshly read authoritative Firestore documents.

    Returns ACK_TERMINAL for duplicate delivery after terminal commit, otherwise
    RECONCILE_SAME_ATTEMPT. It intentionally never returns permission to execute.
    """
    if not isinstance(payload, Mapping) or set(payload) != _FIELDS:
        raise DispatchTaskRejected("task envelope schema mismatch")
    if payload.get("schema") != SCHEMA:
        raise DispatchTaskRejected("unsupported task schema")
    for key in ("effect_id", "attempt_id"):
        if not isinstance(payload.get(key), str) or not payload[key].strip():
            raise DispatchTaskRejected(f"{key} is required")
    revision = payload.get("expected_revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise DispatchTaskRejected("expected_revision must be a positive integer")
    digest = payload.get("dispatch_event_digest")
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        raise DispatchTaskRejected("dispatch_event_digest must be lowercase SHA-256 hex")
    issued, expires = payload.get("issued_at"), payload.get("expires_at")
    if (isinstance(issued, bool) or isinstance(expires, bool)
            or not isinstance(issued, (int, float)) or not isinstance(expires, (int, float))
            or not math.isfinite(issued) or not math.isfinite(expires)
            or expires <= issued or now < issued or now > expires):
        raise DispatchTaskRejected("task validity window is invalid or expired")

    effect_id, attempt_id = payload["effect_id"], payload["attempt_id"]
    if effect.get("effect_id") != effect_id or attempt.get("effect_id") != effect_id:
        raise DispatchTaskRejected("task effect binding mismatch")
    if effect.get("attempt_id") != attempt_id or attempt.get("attempt_id") != attempt_id:
        raise DispatchTaskRejected("task attempt binding mismatch")
    if (not isinstance(effect.get("revision"), int) or effect.get("revision") < revision
            or attempt.get("state") not in {
        "DISPATCHED", "UNKNOWN", "OBSERVED_SUCCESS", "OBSERVED_FAILURE"
    }):
        raise DispatchTaskRejected("task revision or attempt state is stale")
    if digest != dispatch_event_digest(effect_id, attempt_id):
        raise DispatchTaskRejected("task dispatch event binding mismatch")
    if effect.get("state") in {"OBSERVED_SUCCESS", "OBSERVED_FAILURE"}:
        return "ACK_TERMINAL"
    if effect.get("state") not in {"DISPATCHED", "UNKNOWN"}:
        raise DispatchTaskRejected("task effect state is not dispatchable/reconcilable")
    return "RECONCILE_SAME_ATTEMPT"


__all__ = [
    "SCHEMA", "DispatchTaskRejected", "deterministic_task_name",
    "dispatch_event_digest", "validate_dispatch_task",
]
