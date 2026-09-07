"""Central governed execution bridge."""
from __future__ import annotations
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from .authority import authorize, load_contract
from .durable_loop import Executor, LoopPolicy, StateStore, run_durable_loop
from .runtime import ProviderAdapter, execute

@dataclass(frozen=True)
class GovernedRuntimeExecutor(Executor):
    aios_dir: str
    contract_id: str
    permit_id: str
    actor: str
    adapter: ProviderAdapter
    observer: Callable[[Mapping[str, Any]], Any]
    decider: Callable[[Any, Mapping[str, Any]], Any]
    verifier: Callable[[Any, Mapping[str, Any]], Any]
    def observe(self, state: Mapping[str, Any]) -> Any: return self.observer(deepcopy(state))
    def decide(self, observation: Any, state: Mapping[str, Any]) -> Any: return self.decider(deepcopy(observation), deepcopy(state))
    def act(self, decision: Any, state: Mapping[str, Any]) -> Any:
        if not isinstance(decision, Mapping): raise ValueError("runtime decision must be a mapping")
        operation_id = decision.get("logical_operation_id")
        if not isinstance(operation_id, str) or not operation_id.strip(): raise ValueError("runtime decision must contain logical_operation_id")
        result = execute(self.aios_dir, self.contract_id, self.permit_id, operation_id, self.actor, self.adapter)
        if isinstance(result, Mapping) and "provider_observation" in result:
            return {**deepcopy(dict(result)), "evidence": deepcopy(result["provider_observation"])}
        return result
    def verify(self, action_result: Any, state: Mapping[str, Any]) -> Any: return self.verifier(deepcopy(action_result), deepcopy(state))

def run_governed_execution(*, executor: GovernedRuntimeExecutor, store: StateStore, policy: LoopPolicy) -> Mapping[str, Any]:
    """Run/resume the single AIOS durable loop with authority-bound state."""
    authorize(executor.aios_dir, executor.contract_id, executor.permit_id)
    contract = load_contract(executor.aios_dir, executor.contract_id)
    if policy.policy_digest != contract["policy_digest"]:
        raise PermissionError("execution policy digest does not match governing contract")
    if policy.max_steps > contract["max_attempts"]:
        raise PermissionError("execution budget exceeds governing contract max_attempts")
    governing_terminal_states = frozenset(contract["terminal_states"])
    if not governing_terminal_states:
        raise PermissionError("governing execution must define terminal states")
    if policy.terminal_states != governing_terminal_states:
        raise PermissionError("execution terminal states do not match governing contract")
    if policy.failure_state not in governing_terminal_states:
        raise PermissionError("execution failure state is not authorized by governing contract")
    if policy.budget_exhaustion_state not in governing_terminal_states:
        raise PermissionError("budget exhaustion state is not authorized by governing contract")

    def validate_resume(state: Mapping[str, Any]) -> None:
        if state.get("contract_id") != executor.contract_id: raise ValueError("persisted contract binding does not match execution context")
        if state.get("permit_id") != executor.permit_id: raise ValueError("persisted permit binding does not match execution context")
        authorize(executor.aios_dir, executor.contract_id, executor.permit_id)

    bound_policy = LoopPolicy(
        max_steps=policy.max_steps,
        terminal_evaluator=policy.terminal_evaluator,
        action_authorizer=policy.action_authorizer,
        resume_validator=validate_resume,
        policy_digest=contract["policy_digest"],
        terminal_states=governing_terminal_states,
        budget_exhaustion_state=policy.budget_exhaustion_state,
        failure_state=policy.failure_state,
    )
    loaded = store.load()
    if loaded is None:
        store.save({"contract_id": executor.contract_id, "permit_id": executor.permit_id, "policy_digest": bound_policy.policy_digest})
    else:
        state = deepcopy(dict(loaded))
        if state.get("contract_id") != executor.contract_id or state.get("permit_id") != executor.permit_id:
            state["status"] = bound_policy.failure_state
            state["block_reason"] = "persisted execution binding does not match current authority context"
            store.save(state)
            return state
    return run_durable_loop(executor, store, bound_policy)

__all__ = ["GovernedRuntimeExecutor", "run_governed_execution"]
