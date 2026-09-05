"""Machine-checkable primitives for the AIOS common durable harness.

This module deliberately contains no model/provider logic. It defines the
state and authority boundary that any runtime adapter must preserve.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

TERMINAL = frozenset({"PASS", "BLOCKED", "INCONCLUSIVE"})
PHASES = frozenset({
    "OBSERVE",
    "DECIDE",
    "AUTHORIZE",
    "ACT",
    "VERIFY",
    "RECONCILE",
    "PERSIST",
    "RESUME",
})


@dataclass(frozen=True)
class EvidenceRef:
    """Provenance-bearing reference to evidence; not the evidence itself."""

    ref: str
    source: str
    claim: str
    verification_level: str
    digest: str | None = None

    def __post_init__(self) -> None:
        for name in ("ref", "source", "claim", "verification_level"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if self.digest is not None and (not isinstance(self.digest, str) or not self.digest.strip()):
            raise ValueError("digest must be a non-empty string when supplied")


@dataclass(frozen=True)
class HarnessPolicy:
    """Immutable control-plane boundary supplied to a workload executor."""

    execution_id: str
    contract_id: str
    contract_version: str
    policy_digest: str
    capability_id: str
    capability_version: str
    max_steps: int
    max_retries: int = 0
    allowed_effects: frozenset[str] = frozenset()
    terminal_states: frozenset[str] = TERMINAL

    def __post_init__(self) -> None:
        for name in (
            "execution_id",
            "contract_id",
            "contract_version",
            "policy_digest",
            "capability_id",
            "capability_version",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.max_steps, int) or isinstance(self.max_steps, bool) or self.max_steps < 1:
            raise ValueError("max_steps must be an integer >= 1")
        if not isinstance(self.max_retries, int) or isinstance(self.max_retries, bool) or self.max_retries < 0:
            raise ValueError("max_retries must be an integer >= 0")
        if self.terminal_states != TERMINAL:
            raise ValueError("AIOS terminal states are fixed")
        if any(not isinstance(effect, str) or not effect.strip() for effect in self.allowed_effects):
            raise ValueError("allowed_effects must contain only non-empty strings")


@dataclass
class HarnessState:
    """Authoritative durable state; conversation history is not authoritative."""

    execution_id: str
    policy_digest: str
    capability_id: str
    capability_version: str
    step: int = 0
    attempt: int = 0
    phase: str = "RESUME"
    status: str = "RUNNING"
    budget_remaining: int = 0
    retry_budget_remaining: int = 0
    pending_effect_id: str | None = None
    last_checkpoint_id: str | None = None
    records: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[EvidenceRef] = field(default_factory=list)
    terminal_reason: str | None = None

    def validate(self, policy: HarnessPolicy) -> None:
        if self.execution_id != policy.execution_id:
            raise ValueError("execution identity mismatch")
        if self.policy_digest != policy.policy_digest:
            raise ValueError("policy digest mismatch")
        if self.capability_id != policy.capability_id:
            raise ValueError("capability identity mismatch")
        if self.capability_version != policy.capability_version:
            raise ValueError("capability version mismatch")
        if not isinstance(self.step, int) or isinstance(self.step, bool) or self.step < 0 or self.step > policy.max_steps:
            raise ValueError("invalid step/budget state")
        if not isinstance(self.attempt, int) or isinstance(self.attempt, bool) or self.attempt < 0:
            raise ValueError("invalid attempt")
        if self.phase not in PHASES:
            raise ValueError("invalid phase")
        if self.status not in {"RUNNING", *TERMINAL}:
            raise ValueError("invalid status")
        if not isinstance(self.budget_remaining, int) or isinstance(self.budget_remaining, bool) or self.budget_remaining < 0:
            raise ValueError("invalid remaining step budget")
        if self.budget_remaining > policy.max_steps - self.step:
            raise ValueError("remaining step budget exceeds immutable policy budget")
        if not isinstance(self.retry_budget_remaining, int) or isinstance(self.retry_budget_remaining, bool) or self.retry_budget_remaining < 0:
            raise ValueError("invalid remaining retry budget")
        if self.retry_budget_remaining > policy.max_retries:
            raise ValueError("remaining retry budget exceeds immutable policy budget")
        if self.pending_effect_id is not None and (not isinstance(self.pending_effect_id, str) or not self.pending_effect_id.strip()):
            raise ValueError("pending_effect_id must be a non-empty string when supplied")
        if self.status in TERMINAL and self.terminal_reason is None:
            raise ValueError("terminal state requires a reason")
        if self.status == "RUNNING" and self.terminal_reason is not None:
            raise ValueError("running state cannot have a terminal reason")

    def snapshot(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "policy_digest": self.policy_digest,
            "capability_id": self.capability_id,
            "capability_version": self.capability_version,
            "step": self.step,
            "attempt": self.attempt,
            "phase": self.phase,
            "status": self.status,
            "budget_remaining": self.budget_remaining,
            "retry_budget_remaining": self.retry_budget_remaining,
            "pending_effect_id": self.pending_effect_id,
            "last_checkpoint_id": self.last_checkpoint_id,
            "records": [dict(r) for r in self.records],
            "evidence": [e.__dict__.copy() for e in self.evidence],
            "terminal_reason": self.terminal_reason,
        }


def authorize_effect(policy: HarnessPolicy, effect: Mapping[str, Any]) -> None:
    """Fail closed when an action requests an undeclared effect."""
    effect_type = effect.get("effect_type")
    if not isinstance(effect_type, str) or not effect_type:
        raise ValueError("effect_type is required")
    if effect_type not in policy.allowed_effects:
        raise PermissionError(f"effect not authorized: {effect_type}")
    effect_id = effect.get("effect_id")
    if not isinstance(effect_id, str) or not effect_id.strip():
        raise ValueError("effect_id is required before dispatch")


def terminal_from_control_plane(policy: HarnessPolicy, proposed: str | None) -> str | None:
    """Validate a control-plane terminal decision; agents cannot redefine the set."""
    if proposed is None:
        return None
    if proposed not in policy.terminal_states:
        raise ValueError(f"invalid terminal state: {proposed}")
    return proposed


__all__ = [
    "EvidenceRef",
    "HarnessPolicy",
    "HarnessState",
    "PHASES",
    "TERMINAL",
    "authorize_effect",
    "terminal_from_control_plane",
]
