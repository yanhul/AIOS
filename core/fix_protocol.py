"""Evidence-gated protocol for autonomous software fixes.

The protocol exists so an agent cannot substitute "tests passed" or a state
mutation for proof that the broken lifecycle boundary was actually repaired.
Governing criteria live outside the agent and are supplied as immutable input.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


class FixProtocolError(ValueError):
    """Raised when a proposed fix is missing required governance evidence."""


@dataclass(frozen=True)
class FixPlan:
    """Immutable root-cause/fix plan required before an autonomous patch."""

    violated_invariant: str
    lifecycle: str
    broken_boundary: str
    root_cause: str
    proposed_fix: str
    regression_proof: str
    runtime_proof: str
    terminal_condition: str

    def validate(self) -> None:
        fields = (
            "violated_invariant",
            "lifecycle",
            "broken_boundary",
            "root_cause",
            "proposed_fix",
            "regression_proof",
            "runtime_proof",
            "terminal_condition",
        )
        for field_name in fields:
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise FixProtocolError(f"missing fix-plan field: {field_name}")


@dataclass(frozen=True)
class FixProof:
    """Runtime evidence required before a fix may be promoted to VERIFIED."""

    boundary_before: str
    boundary_after: str
    runtime_transition_observed: bool
    evidence_refs: tuple[str, ...]
    regression_passed: bool

    def validate(self) -> None:
        if not self.boundary_before.strip() or not self.boundary_after.strip():
            raise FixProtocolError("fix proof boundary is incomplete")
        if not self.runtime_transition_observed:
            raise FixProtocolError("runtime has not crossed the broken boundary")
        if not self.regression_passed:
            raise FixProtocolError("regression proof has not passed")
        if not self.evidence_refs or any(not isinstance(v, str) or not v.strip() for v in self.evidence_refs):
            raise FixProtocolError("runtime evidence references are missing")


def require_fix_plan(plan: FixPlan) -> FixPlan:
    """Fail closed before a patch when the root-cause plan is incomplete."""
    plan.validate()
    return plan


def require_fix_proof(proof: FixProof) -> FixProof:
    """Fail closed unless runtime evidence proves the broken boundary was crossed."""
    proof.validate()
    return proof


def verify_fix_result(result: Mapping[str, Any]) -> None:
    """Reject self-attested FIXED results without externally supplied proof.

    A result may carry ``status=FIXED`` only when the immutable proof object
    records a real runtime transition and concrete evidence references.
    """
    if not isinstance(result, Mapping):
        raise FixProtocolError("fix result is not a mapping")
    if result.get("status") != "FIXED":
        return
    proof = result.get("fix_proof")
    if not isinstance(proof, FixProof):
        raise FixProtocolError("FIXED result requires FixProof from the verifier")
    require_fix_proof(proof)


__all__ = [
    "FixPlan",
    "FixProof",
    "FixProtocolError",
    "require_fix_plan",
    "require_fix_proof",
    "verify_fix_result",
]
