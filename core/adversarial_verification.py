"""Independent verification primitives: verify/repair/re-verify, never self-promote."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable, Mapping

VERIFIED = frozenset({"PASS", "FAIL", "INCONCLUSIVE"})

@dataclass(frozen=True)
class VerificationResult:
    status: str
    verifier_id: str
    evidence_refs: tuple[str, ...] = ()
    findings: tuple[str, ...] = ()
    repair_required: bool = False

    def __post_init__(self) -> None:
        if self.status not in VERIFIED:
            raise ValueError("invalid verification status")
        if not self.verifier_id.strip():
            raise ValueError("verifier_id is required")


def verify_repair_reverify(subject: Any, verifier: Callable[[Any], VerificationResult],
                           repairer: Callable[[Any, VerificationResult], Any] | None = None,
                           max_repairs: int = 1) -> tuple[Any, tuple[VerificationResult, ...]]:
    """Run an independent verification rail. Repair is bounded; PASS is never self-issued."""
    if max_repairs < 0:
        raise ValueError("max_repairs must be >= 0")
    current = subject
    results: list[VerificationResult] = []
    for attempt in range(max_repairs + 1):
        result = verifier(current)
        results.append(result)
        if result.status == "PASS":
            return current, tuple(results)
        if result.status == "INCONCLUSIVE" or not result.repair_required or repairer is None or attempt >= max_repairs:
            return current, tuple(results)
        current = repairer(current, result)
    return current, tuple(results)


def require_independent_verifier(executor_id: str, verifier_id: str) -> None:
    if not executor_id or not verifier_id:
        raise ValueError("executor and verifier identities are required")
    if executor_id == verifier_id:
        raise PermissionError("executor cannot self-approve through the adversarial verification rail")

__all__ = ["VerificationResult", "verify_repair_reverify", "require_independent_verifier"]
