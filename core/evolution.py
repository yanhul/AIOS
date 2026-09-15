"""Governed candidate/evolution state machine.

The evolution plane may propose and evaluate candidates, but promotion remains
an authority-bearing operation outside the candidate itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol


CANDIDATE_STATES = frozenset(
    {
        "DISCOVERED",
        "CANDIDATE",
        "CHALLENGER",
        "EVALUATED",
        "PROMOTABLE",
        "ACTIVE",
        "REJECTED",
        "BLOCKED",
    }
)

TERMINAL_CANDIDATE_STATES = frozenset({"ACTIVE", "REJECTED", "BLOCKED"})

_ALLOWED_TRANSITIONS = {
    "DISCOVERED": frozenset({"CANDIDATE", "REJECTED", "BLOCKED"}),
    "CANDIDATE": frozenset({"CHALLENGER", "REJECTED", "BLOCKED"}),
    "CHALLENGER": frozenset({"EVALUATED", "REJECTED", "BLOCKED"}),
    "EVALUATED": frozenset({"PROMOTABLE", "REJECTED", "BLOCKED"}),
    "PROMOTABLE": frozenset({"ACTIVE", "REJECTED", "BLOCKED"}),
    "ACTIVE": frozenset(),
    "REJECTED": frozenset(),
    "BLOCKED": frozenset(),
}


class CandidateStore(Protocol):
    def save(self, candidate: "Candidate") -> None: ...
    def load(self, candidate_id: str) -> "Candidate | None": ...


@dataclass(frozen=True)
class EvaluationEvidence:
    """Independent evaluation result; empty or mutable evidence is rejected."""

    evaluator_digest: str
    held_in: Mapping[str, Any]
    held_out: Mapping[str, Any]
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.evaluator_digest.strip():
            raise ValueError("evaluator_digest must be non-empty")
        if not isinstance(self.held_in, Mapping) or not self.held_in:
            raise ValueError("held_in evidence is required")
        if not isinstance(self.held_out, Mapping) or not self.held_out:
            raise ValueError("held_out evidence is required")
        if not self.evidence_refs or any(not isinstance(v, str) or not v.strip() for v in self.evidence_refs):
            raise ValueError("evidence_refs must contain at least one non-empty reference")


@dataclass(frozen=True)
class Candidate:
    candidate_id: str
    parent_id: str | None
    artifact_ref: str
    state: str = "DISCOVERED"
    lineage_depth: int = 0
    evaluation: EvaluationEvidence | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.candidate_id.strip():
            raise ValueError("candidate_id must be non-empty")
        if not self.artifact_ref.strip():
            raise ValueError("artifact_ref must be non-empty")
        if self.state not in CANDIDATE_STATES:
            raise ValueError(f"unknown candidate state: {self.state}")
        if self.lineage_depth < 0:
            raise ValueError("lineage_depth must be >= 0")
        if self.parent_id == self.candidate_id:
            raise ValueError("candidate cannot be its own parent")
        if self.state in {"EVALUATED", "PROMOTABLE", "ACTIVE"} and self.evaluation is None:
            raise ValueError(f"state={self.state} requires evaluation evidence")


@dataclass
class MemoryCandidateStore:
    candidates: dict[str, Candidate] = field(default_factory=dict)

    def save(self, candidate: Candidate) -> None:
        previous = self.candidates.get(candidate.candidate_id)
        if previous is not None and candidate.lineage_depth < previous.lineage_depth:
            raise ValueError("candidate lineage depth cannot move backwards")
        self.candidates[candidate.candidate_id] = candidate

    def load(self, candidate_id: str) -> Candidate | None:
        return self.candidates.get(candidate_id)


def transition(candidate: Candidate, new_state: str) -> Candidate:
    """Apply one explicit state transition; never mutate the candidate in place."""
    if new_state not in CANDIDATE_STATES:
        raise ValueError(f"unknown candidate state: {new_state}")
    if new_state not in _ALLOWED_TRANSITIONS[candidate.state]:
        raise ValueError(f"unauthorized transition {candidate.state} -> {new_state}")
    return Candidate(
        candidate_id=candidate.candidate_id,
        parent_id=candidate.parent_id,
        artifact_ref=candidate.artifact_ref,
        state=new_state,
        lineage_depth=candidate.lineage_depth,
        evaluation=candidate.evaluation,
        metadata=dict(candidate.metadata),
    )


def record_evaluation(
    candidate: Candidate,
    evidence: EvaluationEvidence,
    *,
    evaluator_digest: str,
) -> Candidate:
    """Attach evaluation only when the supplied evaluator matches the contract."""
    if candidate.state != "CHALLENGER":
        raise ValueError("only CHALLENGER candidates can be evaluated")
    if evidence.evaluator_digest != evaluator_digest:
        raise ValueError("evaluation used an unauthorized evaluator")
    evaluated = Candidate(
        candidate_id=candidate.candidate_id,
        parent_id=candidate.parent_id,
        artifact_ref=candidate.artifact_ref,
        state="EVALUATED",
        lineage_depth=candidate.lineage_depth,
        evaluation=evidence,
        metadata=dict(candidate.metadata),
    )
    return evaluated


def promote(
    candidate: Candidate,
    *,
    authorize: Callable[[Candidate], None],
) -> Candidate:
    """Promote only a fully evaluated candidate through an external authority gate."""
    if candidate.state != "PROMOTABLE":
        raise ValueError("only PROMOTABLE candidates can be activated")
    if candidate.evaluation is None:
        raise ValueError("promotion requires evaluation evidence")
    authorize(candidate)
    return transition(candidate, "ACTIVE")


__all__ = [
    "CANDIDATE_STATES",
    "TERMINAL_CANDIDATE_STATES",
    "Candidate",
    "CandidateStore",
    "EvaluationEvidence",
    "MemoryCandidateStore",
    "promote",
    "record_evaluation",
    "transition",
]
