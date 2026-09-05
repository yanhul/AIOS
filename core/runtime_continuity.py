"""Runtime-independent continuity boundary for durable AIOS executions.

Execution identity, policy identity, capability identity, and durable effect
identity belong to AIOS. A runtime/provider may be replaced without creating a
new execution or re-authorizing an already governed effect.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


class ContinuityError(ValueError):
    pass


@dataclass(frozen=True)
class RuntimeIdentity:
    runtime_id: str
    provider: str
    version: str

    def __post_init__(self) -> None:
        for name in ("runtime_id", "provider", "version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ContinuityError(f"{name} must be non-empty")


@dataclass(frozen=True)
class ContinuityCheckpoint:
    execution_id: str
    policy_digest: str
    capability_id: str
    capability_version: str
    step: int
    attempt: int
    pending_effect_id: str | None
    runtime: RuntimeIdentity


def validate_runtime_replacement(
    checkpoint: ContinuityCheckpoint,
    *,
    execution_id: str,
    policy_digest: str,
    capability_id: str,
    capability_version: str,
    replacement: RuntimeIdentity,
    effect: Mapping[str, object] | None = None,
) -> None:
    """Validate migration without allowing provider replacement to alter authority."""
    if checkpoint.execution_id != execution_id:
        raise ContinuityError("execution identity mismatch")
    if checkpoint.policy_digest != policy_digest:
        raise ContinuityError("policy digest mismatch")
    if checkpoint.capability_id != capability_id or checkpoint.capability_version != capability_version:
        raise ContinuityError("capability identity/version mismatch")
    if replacement.runtime_id == checkpoint.runtime.runtime_id and replacement.provider == checkpoint.runtime.provider:
        raise ContinuityError("replacement must identify a distinct runtime/provider")
    if checkpoint.pending_effect_id is not None:
        if effect is None or effect.get("effect_id") != checkpoint.pending_effect_id:
            raise ContinuityError("pending effect must be explicitly reconciled during migration")
    if checkpoint.step < 0 or checkpoint.attempt < 0:
        raise ContinuityError("checkpoint counters must be non-negative")


__all__ = ["ContinuityCheckpoint", "ContinuityError", "RuntimeIdentity", "validate_runtime_replacement"]
