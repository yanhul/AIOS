import pytest

from core.harness_evolution import EvolutionProposal, evaluate_evolution
from core.independent_evaluation import EvaluationPolicy


POLICY = EvaluationPolicy(
    policy_digest="policy-v1",
    holdout_digest="holdout-v1",
    metric="score",
    min_improvement=0.05,
)


def proposal():
    return EvolutionProposal(
        parent_digest="parent-a",
        candidate_digest="candidate-b",
        prediction="score improves",
        policy_digest="policy-v1",
        holdout_digest="holdout-v1",
    )


def test_evolution_requires_frozen_holdout_and_reproduced_prediction():
    result = evaluate_evolution(
        proposal=proposal(),
        policy=POLICY,
        baseline={"score": 0.70},
        candidate={"score": 0.80},
        observed_prediction="score improves",
    )
    assert result["decision"] == "PASS"
    assert result["promotable"] is True
    assert result["prediction_verified"] is True


def test_unreproduced_prediction_blocks_even_when_score_improves():
    result = evaluate_evolution(
        proposal=proposal(),
        policy=POLICY,
        baseline={"score": 0.70},
        candidate={"score": 0.80},
        observed_prediction="score regresses",
    )
    assert result["decision"] == "BLOCKED"
    assert result["promotable"] is False


def test_agent_verdict_never_controls_promotion():
    result = evaluate_evolution(
        proposal=proposal(),
        policy=POLICY,
        baseline={"score": 0.70},
        candidate={"score": 0.80},
        observed_prediction="score improves",
        agent_proposed_verdict="PASS",
    )
    assert result["decision"] == "PASS"
    assert result["agent_verdict_ignored"] is True


def test_policy_drift_blocks():
    drifted = EvolutionProposal(
        parent_digest="parent-a",
        candidate_digest="candidate-b",
        prediction="score improves",
        policy_digest="policy-v2",
        holdout_digest="holdout-v1",
    )
    result = evaluate_evolution(
        proposal=drifted,
        policy=POLICY,
        baseline={"score": 0.70},
        candidate={"score": 0.80},
        observed_prediction="score improves",
    )
    assert result["decision"] == "BLOCKED"
    assert result["promotable"] is False


def test_candidate_must_have_distinct_parent():
    with pytest.raises(ValueError):
        EvolutionProposal(
            parent_digest="same",
            candidate_digest="same",
            prediction="x",
            policy_digest="policy-v1",
            holdout_digest="holdout-v1",
        )
