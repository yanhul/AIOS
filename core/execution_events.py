"""Typed execution lifecycle events adapted from production event-driven execution engines.

AIOS keeps authority/state ownership in the control plane. Adapters may emit
observations, but only the governed loop can advance lifecycle state.
Events are immutable, deterministic, and suitable for lineage receipts.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Callable, Mapping

LIFECYCLE = (
    "PERMITTED",
    "DISPATCHED",
    "EXECUTE_ATTEMPTED",
    "ACKNOWLEDGED",
    "OBSERVED",
    "UNKNOWN",
    "VERIFIED",
    "RECONCILED",
    "COMMITTED",
)

_ALLOWED_NEXT = {
    "PERMITTED": {"DISPATCHED", "UNKNOWN"},
    "DISPATCHED": {"EXECUTE_ATTEMPTED", "UNKNOWN"},
    "EXECUTE_ATTEMPTED": {"ACKNOWLEDGED", "OBSERVED", "UNKNOWN"},
    "ACKNOWLEDGED": {"OBSERVED", "UNKNOWN"},
    "OBSERVED": {"VERIFIED", "RECONCILED", "UNKNOWN"},
    "UNKNOWN": {"RECONCILED", "UNKNOWN"},
    "VERIFIED": {"RECONCILED", "COMMITTED"},
    "RECONCILED": {"COMMITTED", "UNKNOWN"},
    "COMMITTED": set(),
}

@dataclass(frozen=True)
class ExecutionEvent:
    effect_id: str
    attempt_id: str
    status: str
    sequence: int
    evidence: Mapping[str, Any]
    parent_status: str | None = None

    def __post_init__(self) -> None:
        for name in ("effect_id", "attempt_id", "status"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if self.status not in LIFECYCLE:
            raise ValueError(f"unsupported execution lifecycle status: {self.status}")
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool) or self.sequence < 0:
            raise ValueError("sequence must be a non-negative integer")
        if not isinstance(self.evidence, Mapping) or not self.evidence:
            raise ValueError("execution event requires evidence")
        if self.parent_status is not None and self.parent_status not in LIFECYCLE:
            raise ValueError("invalid parent_status")
        if self.parent_status is not None and self.status not in _ALLOWED_NEXT[self.parent_status]:
            raise ValueError(f"illegal lifecycle transition: {self.parent_status} -> {self.status}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_type": "execution.lifecycle",
            "effect_id": self.effect_id,
            "attempt_id": self.attempt_id,
            "status": self.status,
            "sequence": self.sequence,
            "evidence": dict(self.evidence),
            "parent_status": self.parent_status,
        }

    @property
    def identity(self) -> str:
        payload = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"), default=str)
        return sha256(payload.encode("utf-8")).hexdigest()

class ExecutionEventStream:
    """In-memory event stream with strict monotonic lifecycle validation."""

    def __init__(self, sink: Callable[[Mapping[str, Any]], None] | None = None) -> None:
        self._events: list[ExecutionEvent] = []
        self._last_by_lineage: dict[tuple[str, str], ExecutionEvent] = {}
        self._sink = sink

    def emit(
        self,
        *,
        effect_id: str,
        attempt_id: str,
        status: str,
        evidence: Mapping[str, Any],
    ) -> ExecutionEvent:
        key = (effect_id, attempt_id)
        prior = self._last_by_lineage.get(key)
        sequence = prior.sequence + 1 if prior is not None else 0
        event = ExecutionEvent(
            effect_id=effect_id,
            attempt_id=attempt_id,
            status=status,
            sequence=sequence,
            evidence=dict(evidence),
            parent_status=prior.status if prior else None,
        )
        self._events.append(event)
        self._last_by_lineage[key] = event
        if self._sink is not None:
            self._sink(event.as_dict() | {"identity": event.identity})
        return event

    def events(self) -> tuple[ExecutionEvent, ...]:
        return tuple(self._events)

__all__ = ["LIFECYCLE", "ExecutionEvent", "ExecutionEventStream"]
