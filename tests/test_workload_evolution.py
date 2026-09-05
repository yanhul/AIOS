from core.harness_evolution import EvolutionProposal
from core.independent_evaluation import EvaluationPolicy
from core.workload_evolution import WorkloadEvolution, evaluate_workload_evolution


def test_workload_evolution_uses_independent_holdout_gate():
    policy = EvaluationPolicy(policy_digest="p1", holdout_digest="h1", metric="score", min_improvement=0.05)
    evolution = WorkloadEvolution(
        workload_id="try.research@1",
        change_contract="adapter-change-v1",
        proposal=EvolutionProposal(
            parent_digest="parent",
            candidate_digest="candidate",
            prediction="score improves",
            policy_digest="p1",
            holdout_digest="h1",
        ),
    )
    result = evaluate_workload_evolution(
        evolution=evolution,
        policy=policy,
        baseline={"score": 0.70},
        candidate={"score": 0.80},
        observed_prediction="score improves",
        agent_proposed_verdict="PASS",
    )
    assert result["decision"] == "PASS"
    assert result["workload_id"] == "try.research@1"
    assert result["agent_verdict_ignored"] is True


def test_workload_evolution_blocks_unreproduced_prediction():
    policy = EvaluationPolicy(policy_digest="p1", holdout_digest="h1", metric="score", min_improvement=0.05)
    evolution = WorkloadEvolution(
        workload_id="rx50.engineering@1",
        change_contract="adapter-change-v1",
        proposal=EvolutionProposal("parent", "candidate", "improves", "p1", "h1"),
    )
    result = evaluate_workload_evolution(
        evolution=evolution, policy=policy,
        baseline={"score": 0.70}, candidate={"score": 0.80},
        observed_prediction="regresses",
    )
    assert result["decision"] == "BLOCKED"
    assert result["promotable"] is False
