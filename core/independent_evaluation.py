"""Independent, frozen evaluation boundary for governed harness evolution.

Candidate generation and promotion are intentionally outside this module. The
caller supplies immutable baseline/candidate scorecards and a frozen holdout
contract; the evaluator only compares them and returns an auditable decision.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


class EvaluationError(ValueError):
    pass


@dataclass(frozen=True)
class EvaluationPolicy:
    policy_digest: str
    holdout_digest: str
    metric: str
    min_improvement: float = 0.0
    max_regression: float = 0.0

    def __post_init__(self) -> None:
        for name in ("policy_digest", "holdout_digest", "metric"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise EvaluationError(f"{name} must be non-empty")
        if self.min_improvement < 0 or self.max_regression < 0:
            raise EvaluationError("evaluation thresholds must be non-negative")


def evaluate_candidate(
    *,
    policy: EvaluationPolicy,
    policy_digest: str,
    holdout_digest: str,
    baseline: Mapping[str, float],
    candidate: Mapping[str, float],
    agent_proposed_verdict: str | None = None,
) -> dict[str, object]:
    """Compare pinned baseline/candidate scores without accepting agent verdicts."""
    if policy_digest != policy.policy_digest:
        return {"decision": "BLOCKED", "reason": "evaluation policy digest mismatch"}
    if holdout_digest != policy.holdout_digest:
        return {"decision": "BLOCKED", "reason": "holdout digest mismatch"}
    if policy.metric not in baseline or policy.metric not in candidate:
        return {"decision": "BLOCKED", "reason": "required evaluation metric missing"}
    if not isinstance(baseline[policy.metric], (int, float)) or not isinstance(candidate[policy.metric], (int, float)):
        return {"decision": "BLOCKED", "reason": "evaluation metric is not numeric"}

    delta = float(candidate[policy.metric]) - float(baseline[policy.metric])
    accepted = delta >= policy.min_improvement and delta >= -policy.max_regression
    decision = "PASS" if accepted else "BLOCKED"
    result = {
        "decision": decision,
        "metric": policy.metric,
        "baseline": float(baseline[policy.metric]),
        "candidate": float(candidate[policy.metric]),
        "delta": delta,
        "holdout_digest": policy.holdout_digest,
        "policy_digest": policy.policy_digest,
    }
    if agent_proposed_verdict is not None:
        result["agent_proposed_verdict"] = agent_proposed_verdict
        result["agent_verdict_ignored"] = True
    return result


__all__ = ["EvaluationError", "EvaluationPolicy", "evaluate_candidate"]
