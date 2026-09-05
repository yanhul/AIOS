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
    """Run/resume the single AIOS durable loop with authority-bound state."""
    authorize(executor.aios_dir, executor.contract_id, executor.permit_id)

    def validate_resume(state: Mapping[str, Any]) -> None:
        if state.get("contract_id") != executor.contract_id:
            raise ValueError("persisted contract binding does not match execution context")
        if state.get("permit_id") != executor.permit_id:
            raise ValueError("persisted permit binding does not match execution context")
        authorize(executor.aios_dir, executor.contract_id, executor.permit_id)

    bound_policy = LoopPolicy(
        max_steps=policy.max_steps,
        terminal_evaluator=policy.terminal_evaluator,
        action_authorizer=policy.action_authorizer,
        resume_validator=validate_resume,
        policy_digest=policy.policy_digest,
    )

    loaded = store.load()
    if loaded is None:
        initial_state = {
            "contract_id": executor.contract_id,
            "permit_id": executor.permit_id,
            "policy_digest": bound_policy.policy_digest,
        }
        store.save(initial_state)
    else:
        state = deepcopy(dict(loaded))
        if state.get("contract_id") != executor.contract_id or state.get("permit_id") != executor.permit_id:
            state["status"] = "BLOCKED"
            state["block_reason"] = "persisted execution binding does not match current authority context"
            store.save(state)
            return state

    return run_durable_loop(executor, store, bound_policy)


__all__ = ["GovernedRuntimeExecutor", "run_governed_execution"]