"""Deterministic trajectory-level verification for the common AIOS harness.

Final outcome is not sufficient when the execution contract requires trajectory
integrity. This module validates the persisted control-loop shape without using a
model judge as authority.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping


REQUIRED_RECORD_FIELDS = frozenset({"step", "observation", "decision", "action", "verification"})


def verify_trajectory(
    records: Iterable[Mapping[str, Any]],
    *,
    max_steps: int,
    required_verification_fields: Iterable[str] = (),
) -> dict[str, Any]:
    """Validate a complete trajectory and return a deterministic audit result.

    The function is intentionally structural: it checks step continuity, required
    records and verification fields. It never upgrades an observation or decides a
    terminal state on behalf of the control plane.
    """
    if not isinstance(max_steps, int) or isinstance(max_steps, bool) or max_steps < 1:
        raise ValueError("max_steps must be an integer >= 1")
    required = tuple(required_verification_fields)
    if any(not isinstance(name, str) or not name.strip() for name in required):
        raise ValueError("required verification fields must be non-empty strings")

    materialized = list(records)
    if len(materialized) > max_steps:
        raise ValueError("trajectory exceeds immutable step budget")

    expected_step = 1
    for index, record in enumerate(materialized):
        if not isinstance(record, Mapping):
            raise ValueError(f"trajectory record {index} is not a mapping")
        missing = REQUIRED_RECORD_FIELDS - set(record)
        if missing:
            raise ValueError(f"trajectory record {index} missing fields: {sorted(missing)}")
        step = record["step"]
        if not isinstance(step, int) or isinstance(step, bool) or step != expected_step:
            raise ValueError(f"trajectory step discontinuity at record {index}")
        verification = record["verification"]
        if not isinstance(verification, Mapping):
            raise ValueError(f"trajectory verification {index} is not a mapping")
        for field in required:
            if field not in verification:
                raise ValueError(f"trajectory verification {index} missing required field: {field}")
        expected_step += 1

    return {
        "verified": True,
        "record_count": len(materialized),
        "last_step": len(materialized),
        "max_steps": max_steps,
        "required_verification_fields": list(required),
    }


__all__ = ["REQUIRED_RECORD_FIELDS", "verify_trajectory"]
