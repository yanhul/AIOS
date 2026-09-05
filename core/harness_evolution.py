"""Falsifiable, non-self-promoting harness evolution gate."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .independent_evaluation import EvaluationPolicy, evaluate_candidate


@dataclass(frozen=True)
class EvolutionProposal:
    parent_digest: str
    candidate_digest: str
    prediction: str
    policy_digest: str
    holdout_digest: str

    def __post_init__(self) -> None:
        for name in (
            "parent_digest",
            "candidate_digest",
            "prediction",
            "policy_digest",
            "holdout_digest",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty")
        if self.parent_digest == self.candidate_digest:
            raise ValueError("candidate must differ from parent")


def evaluate_evolution(
    *,
    proposal: EvolutionProposal,
    policy: EvaluationPolicy,
    baseline: Mapping[str, float],
    candidate: Mapping[str, float],
    observed_prediction: str,
    agent_proposed_verdict: str | None = None,
) -> dict[str, object]:
    """Gate a harness edit on observed prediction + frozen holdout evaluation.

    The proposal is only a hypothesis. Promotion remains the responsibility of
    an independent control-plane gate; the candidate cannot self-promote.
    """
    if proposal.policy_digest != policy.policy_digest:
        return {"decision": "BLOCKED", "reason": "proposal policy digest mismatch"}
    if proposal.holdout_digest != policy.holdout_digest:
        return {"decision": "BLOCKED", "reason": "proposal holdout digest mismatch"}
    prediction_verified = observed_prediction == proposal.prediction
    evaluation = evaluate_candidate(
        policy=policy,
        policy_digest=proposal.policy_digest,
        holdout_digest=proposal.holdout_digest,
        baseline=baseline,
        candidate=candidate,
        agent_proposed_verdict=agent_proposed_verdict,
    )
    if evaluation.get("decision") != "PASS":
        return {
            **evaluation,
            "prediction_verified": prediction_verified,
            "candidate_digest": proposal.candidate_digest,
            "parent_digest": proposal.parent_digest,
            "promotable": False,
        }
    if not prediction_verified:
        return {
            **evaluation,
            "decision": "BLOCKED",
            "reason": "falsifiable prediction not reproduced",
            "prediction_verified": False,
            "candidate_digest": proposal.candidate_digest,
            "parent_digest": proposal.parent_digest,
            "promotable": False,
        }
    return {
        **evaluation,
        "prediction_verified": True,
        "candidate_digest": proposal.candidate_digest,
        "parent_digest": proposal.parent_digest,
        "promotable": True,
    }


__all__ = ["EvolutionProposal", "evaluate_evolution"]
