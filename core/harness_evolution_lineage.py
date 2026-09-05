"""Immutable lineage records for harness evolution and rollback."""
from __future__ import annotations

from dataclasses import dataclass


_TERMINAL = {"PASS", "BLOCKED", "INCONCLUSIVE"}


def _text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")
    return value


@dataclass(frozen=True)
class EvolutionLineage:
    change_id: str
    parent_digest: str
    candidate_digest: str
    prediction: str
    policy_digest: str
    holdout_digest: str
    observed_prediction: str
    decision: str
    evidence_refs: tuple[str, ...]
    verification_refs: tuple[str, ...]
    rollback_target: str | None

    def __post_init__(self) -> None:
        for name in (
            "change_id", "parent_digest", "candidate_digest", "prediction",
            "policy_digest", "holdout_digest", "observed_prediction", "decision",
        ):
            _text(getattr(self, name), name)
        if self.parent_digest == self.candidate_digest:
            raise ValueError("candidate must differ from parent")
        if self.decision not in _TERMINAL:
            raise ValueError("decision must be PASS, BLOCKED, or INCONCLUSIVE")
        if not isinstance(self.evidence_refs, tuple) or not all(isinstance(x, str) and x.strip() for x in self.evidence_refs):
            raise ValueError("evidence_refs must contain non-empty strings")
        if not isinstance(self.verification_refs, tuple) or not all(isinstance(x, str) and x.strip() for x in self.verification_refs):
            raise ValueError("verification_refs must contain non-empty strings")
        if self.decision == "PASS" and self.rollback_target != self.parent_digest:
            raise ValueError("PASS evolution requires parent rollback target")
        if self.rollback_target is not None:
            _text(self.rollback_target, "rollback_target")

    @property
    def promotable(self) -> bool:
        return self.decision == "PASS" and bool(self.evidence_refs) and bool(self.verification_refs)

    def artifact(self) -> dict[str, object]:
        return {
            "change_id": self.change_id,
            "parent_digest": self.parent_digest,
            "candidate_digest": self.candidate_digest,
            "prediction": self.prediction,
            "policy_digest": self.policy_digest,
            "holdout_digest": self.holdout_digest,
            "observed_prediction": self.observed_prediction,
            "decision": self.decision,
            "evidence_refs": list(self.evidence_refs),
            "verification_refs": list(self.verification_refs),
            "rollback_target": self.rollback_target,
            "promotable": self.promotable,
        }


def make_lineage(*, change_id: str, parent_digest: str, candidate_digest: str,
                 prediction: str, policy_digest: str, holdout_digest: str,
                 observed_prediction: str, decision: str,
                 evidence_refs: tuple[str, ...] = (),
                 verification_refs: tuple[str, ...] = ()) -> EvolutionLineage:
    """Create a non-authoritative experiment artifact; promotion remains external."""
    rollback_target = parent_digest if decision == "PASS" else None
    return EvolutionLineage(
        change_id=_text(change_id, "change_id"),
        parent_digest=_text(parent_digest, "parent_digest"),
        candidate_digest=_text(candidate_digest, "candidate_digest"),
        prediction=_text(prediction, "prediction"),
        policy_digest=_text(policy_digest, "policy_digest"),
        holdout_digest=_text(holdout_digest, "holdout_digest"),
        observed_prediction=_text(observed_prediction, "observed_prediction"),
        decision=_text(decision, "decision"),
        evidence_refs=tuple(evidence_refs),
        verification_refs=tuple(verification_refs),
        rollback_target=rollback_target,
    )


__all__ = ["EvolutionLineage", "make_lineage"]
