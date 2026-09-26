"""Strict execution lineage primitives absorbed from agentic-RL execution patterns.

This module is AIOS-native. It records the immutable execution context that must
survive the full contract -> permit -> effect -> attempt -> trajectory -> receipt
-> evidence -> evaluation -> decision chain.

The fields are descriptive provenance, never authority. Missing or mismatched
context fails closed when strict validation is requested.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Mapping


_REQUIRED = (
    "policy_revision",
    "environment_revision",
    "capability_snapshot",
    "provider_revision",
    "attempt_id",
    "trajectory_id",
)


def _s(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError(f"{name} must be a non-empty mapping")
    return dict(value)


@dataclass(frozen=True)
class ExecutionLineage:
    policy_revision: str
    environment_revision: str
    capability_snapshot: Mapping[str, Any]
    provider_revision: str
    attempt_id: str
    trajectory_id: str
    raw_output_digest: str | None = None

    def __post_init__(self) -> None:
        for value, name in (
            (self.policy_revision, "policy_revision"),
            (self.environment_revision, "environment_revision"),
            (self.provider_revision, "provider_revision"),
            (self.attempt_id, "attempt_id"),
            (self.trajectory_id, "trajectory_id"),
        ):
            _s(value, name)
        object.__setattr__(
            self, "capability_snapshot",
            _mapping(self.capability_snapshot, "capability_snapshot"),
        )
        if self.raw_output_digest is not None:
            _s(self.raw_output_digest, "raw_output_digest")

    @property
    def digest(self) -> str:
        payload = self.as_record(include_digest=False)
        return sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()

    def as_record(self, *, include_digest: bool = True) -> dict[str, Any]:
        record = {
            "policy_revision": self.policy_revision,
            "environment_revision": self.environment_revision,
            "capability_snapshot": dict(self.capability_snapshot),
            "provider_revision": self.provider_revision,
            "attempt_id": self.attempt_id,
            "trajectory_id": self.trajectory_id,
            "raw_output_digest": self.raw_output_digest,
        }
        if include_digest:
            record["lineage_digest"] = self.digest
        return record


def validate_lineage(record: Mapping[str, Any]) -> ExecutionLineage:
    if not isinstance(record, Mapping):
        raise ValueError("execution lineage must be a mapping")
    if any(key not in record for key in _REQUIRED):
        raise ValueError("execution lineage is incomplete")
    obj = ExecutionLineage(
        policy_revision=record["policy_revision"],
        environment_revision=record["environment_revision"],
        capability_snapshot=record["capability_snapshot"],
        provider_revision=record["provider_revision"],
        attempt_id=record["attempt_id"],
        trajectory_id=record["trajectory_id"],
        raw_output_digest=record.get("raw_output_digest"),
    )
    if record.get("lineage_digest") != obj.digest:
        raise ValueError("execution lineage digest mismatch")
    return obj


def require_lineage_fields(record: Mapping[str, Any]) -> None:
    validate_lineage(record)


__all__ = ["ExecutionLineage", "validate_lineage", "require_lineage_fields"]
