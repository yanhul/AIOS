"""Governed promotion and terminal gate.

Promotion is a control-plane decision, never an agent decision. This module
accepts already-produced verification summaries and checks immutable policy
requirements before allowing a capability/artifact to become PROMOTED.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

TERMINAL = frozenset({"PASS", "BLOCKED", "INCONCLUSIVE"})
VERIFICATION_LEVELS = frozenset({
    "OBSERVED", "EVIDENCED", "VERIFIED_DIGITAL", "VERIFIED_PHYSICAL", "PROMOTED"
})


class PromotionError(ValueError):
    pass


@dataclass(frozen=True)
class PromotionPolicy:
    policy_digest: str
    required_evidence: tuple[str, ...] = ()
    required_verification_levels: tuple[str, ...] = ()
    require_no_unresolved_contradictions: bool = True
    require_independent_evaluation: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.policy_digest, str) or not self.policy_digest.strip():
            raise PromotionError("policy_digest must be non-empty")
        unknown = set(self.required_verification_levels) - VERIFICATION_LEVELS
        if unknown:
            raise PromotionError(f"unsupported verification levels: {sorted(unknown)}")


def evaluate_promotion(
    *,
    policy: PromotionPolicy,
    policy_digest: str,
    terminal: str,
    evidence: Iterable[Mapping[str, object]],
    contradictions: Iterable[Mapping[str, object]] = (),
    independent_evaluation: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Return a deterministic promotion decision; fail closed on gaps."""
    if policy_digest != policy.policy_digest:
        return {"decision": "BLOCKED", "reason": "policy digest mismatch"}
    if terminal not in TERMINAL:
        return {"decision": "BLOCKED", "reason": "invalid terminal state"}
    if terminal != "PASS":
        return {"decision": terminal, "reason": "promotion requires PASS terminal"}
    if policy.require_independent_evaluation:
        if independent_evaluation is None or independent_evaluation.get("decision") != "PASS":
            return {"decision": "BLOCKED", "reason": "independent evaluation gate not satisfied"}

    records = list(evidence)
    refs: set[str] = set()
    levels: set[str] = set()
    for record in records:
        ref = record.get("ref")
        level = record.get("verification_level")
        if isinstance(ref, str) and ref.strip():
            refs.add(ref)
        if isinstance(level, str):
            levels.add(level)

    missing_evidence = sorted(set(policy.required_evidence) - refs)
    missing_levels = sorted(set(policy.required_verification_levels) - levels)
    unresolved = [c for c in contradictions if c.get("status") == "unresolved"]

    if missing_evidence:
        return {"decision": "BLOCKED", "reason": "required evidence missing", "missing_evidence": missing_evidence}
    if missing_levels:
        return {"decision": "BLOCKED", "reason": "required verification level missing", "missing_verification_levels": missing_levels}
    if policy.require_no_unresolved_contradictions and unresolved:
        return {"decision": "BLOCKED", "reason": "unresolved contradictions remain", "contradiction_count": len(unresolved)}
    return {"decision": "PROMOTED", "reason": "all immutable promotion gates satisfied"}


__all__ = ["PromotionError", "PromotionPolicy", "evaluate_promotion", "TERMINAL", "VERIFICATION_LEVELS"]
