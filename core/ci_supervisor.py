"""Event-driven CI wake boundary for AIOS.

GitHub Actions is an event source only. This module validates and durably
records CI completion events; it does not grant authority, mutate receipts,
or declare PASS. Repair/execution remains behind injected AIOS providers.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from typing import Any, Mapping


class CIEventError(ValueError):
    pass


@dataclass(frozen=True)
class CIEvent:
    repository: str
    workflow: str
    run_id: int
    sha: str
    conclusion: str
    ref: str = ""
    pr_number: int | None = None

    @property
    def event_id(self) -> str:
        raw = f"{self.repository}|{self.run_id}|{self.sha}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class SupervisorState:
    event_id: str
    status: str
    next_action: str
    reason: str


ALLOWED_CONCLUSIONS = frozenset(
    {"success", "failure", "cancelled", "timed_out", "action_required", "neutral", "skipped"}
)


def validate_event(event: CIEvent, expected_repository: str) -> None:
    if event.repository != expected_repository:
        raise CIEventError("repository mismatch")
    if not event.workflow:
        raise CIEventError("workflow is required")
    if event.run_id <= 0:
        raise CIEventError("run_id must be positive")
    if len(event.sha) != 40 or any(c not in "0123456789abcdef" for c in event.sha.lower()):
        raise CIEventError("sha must be a 40-character hexadecimal commit")
    if event.conclusion not in ALLOWED_CONCLUSIONS:
        raise CIEventError("unsupported conclusion")
    if event.pr_number is not None and event.pr_number <= 0:
        raise CIEventError("invalid pr_number")


class DurableCIInbox:
    """Append-only, crash-safe inbox keyed by CIEvent.event_id."""

    def __init__(self, root: str):
        self.root = root

    def _path(self, event_id: str) -> str:
        return os.path.join(self.root, f"{event_id}.json")

    def receive(self, event: CIEvent, expected_repository: str) -> SupervisorState:
        validate_event(event, expected_repository)
        path = self._path(event.event_id)
        os.makedirs(self.root, exist_ok=True)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                existing = json.load(fh)
            return SupervisorState(**existing["state"])

        if event.conclusion == "success":
            state = SupervisorState(
                event.event_id, "RECEIVED", "VERIFY", "CI completed successfully"
            )
        elif event.conclusion in {"failure", "cancelled", "timed_out", "action_required"}:
            state = SupervisorState(
                event.event_id, "RECEIVED", "REPAIR_OR_DIAGNOSE", "CI did not produce a successful result"
            )
        else:
            state = SupervisorState(
                event.event_id, "RECEIVED", "REVIEW", f"CI conclusion={event.conclusion}"
            )

        payload: Mapping[str, Any] = {"event": asdict(event), "state": asdict(state)}
        fd, tmp = tempfile.mkstemp(prefix=".ci-event-", dir=self.root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, sort_keys=True, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return state


def event_from_mapping(payload: Mapping[str, Any]) -> CIEvent:
    required = ("repository", "workflow", "run_id", "sha", "conclusion")
    missing = [key for key in required if key not in payload]
    if missing:
        raise CIEventError(f"missing event fields: {','.join(missing)}")
    return CIEvent(
        repository=str(payload["repository"]),
        workflow=str(payload["workflow"]),
        run_id=int(payload["run_id"]),
        sha=str(payload["sha"]),
        conclusion=str(payload["conclusion"]),
        ref=str(payload.get("ref", "")),
        pr_number=(int(payload["pr_number"]) if payload.get("pr_number") is not None else None),
    )


__all__ = ["CIEvent", "CIEventError", "DurableCIInbox", "SupervisorState",
           "event_from_mapping", "validate_event"]
