"""Governed evolution of workload adapters, reusing the independent gate."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .harness_evolution import EvolutionProposal, evaluate_evolution
from .independent_evaluation import EvaluationPolicy


@dataclass(frozen=True)
class WorkloadEvolution:
    workload_id: str
    proposal: EvolutionProposal
    change_contract: str

    def __post_init__(self) -> None:
        if not isinstance(self.workload_id, str) or not self.workload_id.strip():
            raise ValueError("workload_id must be non-empty")
        if not isinstance(self.change_contract, str) or not self.change_contract.strip():
            raise ValueError("change_contract must be non-empty")


def evaluate_workload_evolution(*, evolution: WorkloadEvolution,
                                 policy: EvaluationPolicy,
                                 baseline: Mapping[str, float],
                                 candidate: Mapping[str, float],
                                 observed_prediction: str,
                                 agent_proposed_verdict: str | None = None) -> dict[str, object]:
    """Evaluate a workload adapter change without allowing the workload to self-promote."""
    result = evaluate_evolution(
        proposal=evolution.proposal,
        policy=policy,
        baseline=baseline,
        candidate=candidate,
        observed_prediction=observed_prediction,
        agent_proposed_verdict=agent_proposed_verdict,
    )
    return {**result, "workload_id": evolution.workload_id, "change_contract": evolution.change_contract}


__all__ = ["WorkloadEvolution", "evaluate_workload_evolution"]
