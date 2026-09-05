import pytest

from core.independent_evaluation import EvaluationPolicy, evaluate_candidate


def _policy():
    return EvaluationPolicy(
        policy_digest="sha256:eval-policy",
        holdout_digest="sha256:holdout",
        metric="score",
        min_improvement=0.05,
    )


def test_candidate_must_beat_frozen_baseline_on_holdout():
    result = evaluate_candidate(
        policy=_policy(),
        policy_digest="sha256:eval-policy",
        holdout_digest="sha256:holdout",
        baseline={"score": 0.80},
        candidate={"score": 0.86},
    )
    assert result["decision"] == "PASS"
    assert result["delta"] == pytest.approx(0.06)


def test_agent_verdict_cannot_self_promote_candidate():
    result = evaluate_candidate(
        policy=_policy(),
        policy_digest="sha256:eval-policy",
        holdout_digest="sha256:holdout",
        baseline={"score": 0.80},
        candidate={"score": 0.81},
        agent_proposed_verdict="PASS",
    )
    assert result["decision"] == "BLOCKED"
    assert result["agent_verdict_ignored"] is True


def test_holdout_or_policy_drift_blocks_evaluation():
    policy = _policy()
    stale_policy = evaluate_candidate(
        policy=policy,
        policy_digest="sha256:old",
        holdout_digest="sha256:holdout",
        baseline={"score": 0.8},
        candidate={"score": 0.9},
    )
    stale_holdout = evaluate_candidate(
        policy=policy,
        policy_digest="sha256:eval-policy",
        holdout_digest="sha256:old",
        baseline={"score": 0.8},
        candidate={"score": 0.9},
    )
    assert stale_policy["decision"] == "BLOCKED"
    assert stale_holdout["decision"] == "BLOCKED"


def test_missing_metric_blocks_evaluation():
    result = evaluate_candidate(
        policy=_policy(),
        policy_digest="sha256:eval-policy",
        holdout_digest="sha256:holdout",
        baseline={"other": 1.0},
        candidate={"score": 1.0},
    )
    assert result["decision"] == "BLOCKED"
