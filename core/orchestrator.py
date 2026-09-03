"""Central governed execution bridge.

This module composes the AIOS durable loop with the existing authority and runtime
layers. It is an adapter/composition boundary, not a second control plane.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .authority import authorize
from .durable_loop import Executor, LoopPolicy, StateStore, run_durable_loop
from .runtime import ProviderAdapter, execute


@dataclass(frozen=True)
class GovernedRuntimeExecutor(Executor):
    """Route ACT through the existing AIOS runtime after authority checks."""

    aios_dir: str
    contract_id: str
    permit_id: str
    actor: str
    adapter: ProviderAdapter
    observer: Callable[[Mapping[str, Any]], Any]
    decider: Callable[[Any, Mapping[str, Any]], Any]
    verifier: Callable[[Any, Mapping[str, Any]], Any]

    def observe(self, state: Mapping[str, Any]) -> Any:
        return self.observer(deepcopy(state))

    def decide(self, observation: Any, state: Mapping[str, Any]) -> Any:
        return self.decider(deepcopy(observation), deepcopy(state))

    def act(self, decision: Any, state: Mapping[str, Any]) -> Any:
        if not isinstance(decision, Mapping):
            raise ValueError("runtime decision must be a mapping")
        operation_id = decision.get("logical_operation_id")
        if not isinstance(operation_id, str) or not operation_id.strip():
            raise ValueError("runtime decision must contain logical_operation_id")
        return execute(
            self.aios_dir,
            self.contract_id,
            self.permit_id,
            operation_id,
            self.actor,
            self.adapter,
        )

    def verify(self, action_result: Any, state: Mapping[str, Any]) -> Any:
        return self.verifier(deepcopy(action_result), deepcopy(state))


def run_governed_execution(
    *,
    executor: GovernedRuntimeExecutor,
    store: StateStore,
    policy: LoopPolicy,
) -> Mapping[str, Any]:
    """Run the single AIOS durable loop after resolving contract/permit authority."""
    authorize(executor.aios_dir, executor.contract_id, executor.permit_id)
    return run_durable_loop(executor, store, policy)


__all__ = ["GovernedRuntimeExecutor", "run_governed_execution"]
