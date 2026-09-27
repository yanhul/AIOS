"""Execution supervision primitives absorbed from KENSAT-style fault containment.

These helpers keep authority outside the worker: attempts are durably recorded
before a side effect, receipts are bound to the current execution generation,
and stale completions are rejected.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class AttemptRecord:
    effect_id: str
    attempt_id: str
    generation: str

    def as_dict(self) -> dict[str, str]:
        return {
            "effect_id": self.effect_id,
            "attempt_id": self.attempt_id,
            "generation": self.generation,
        }


def validate_attempt_record(record: Mapping[str, Any]) -> AttemptRecord:
    if not isinstance(record, Mapping):
        raise ValueError("attempt record is missing")
    values = {key: record.get(key) for key in ("effect_id", "attempt_id", "generation")}
    if any(not isinstance(value, str) or not value.strip() for value in values.values()):
        raise ValueError("attempt record lineage is incomplete")
    return AttemptRecord(**values)


def validate_receipt_fence(
    receipt: Mapping[str, Any],
    *,
    expected: AttemptRecord,
) -> None:
    actual = validate_attempt_record(receipt)
    if actual != expected:
        raise ValueError("execution receipt does not match active attempt fence")
    if receipt.get("attempt_started_before_effect") is not True:
        raise ValueError("receipt does not prove attempt was durable before side effect")
