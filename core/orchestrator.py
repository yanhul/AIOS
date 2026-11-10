"""Central governed execution bridge."""
from __future__ import annotations
from copy import deepcopy
from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping
from .authority import authorize, load_contract
from .durable_loop import Executor, LoopPolicy, StateStore, run_durable_loop
from .effect_authority import _id as _effect_id_for, _load_current, load_receipt
from .runtime import ProviderAdapter, execute

_OBSERVED_OUTCOMES = ("OBSERVED_SUCCESS", "OBSERVED_FAILURE")
_EFFECT_IDENTITY_FIELDS = ("effect_id", "contract_id", "actor", "provider", "attempt", "attempt_id",
                           "state", "receipt_id")


def _authoritative_effect_outcome(executor: "GovernedRuntimeExecutor", action_result: Any,
                                  logical_operation_id: str | None = None) -> str:
    """Return the effect-authority outcome behind a governed action, or raise.

    The governed loop may only verify/terminate on an external effect that the
    effect authority itself holds as OBSERVED_* with a sealed, re-verified
    receipt of record. The action result is a caller-visible copy, so it is
    re-bound to the persisted effect; UNKNOWN/DISPATCHED (provider ambiguity),
    a missing/unsealed receipt, or another contract/actor/provider is refused
    (PR #126 independent audit, finding 1).
    """
    if not isinstance(action_result, Mapping):
        raise PermissionError("governed action did not return an external-effect record")
    effect_id = action_result.get("effect_id")
    if not isinstance(effect_id, str) or not effect_id.strip():
        raise PermissionError("governed action result carries no effect_id")
    if logical_operation_id is not None and effect_id != _effect_id_for(
            executor.contract_id, logical_operation_id, executor.actor):
        # An older observed effect must not stand in for the operation that was decided.
        raise PermissionError("governed action effect is not the effect of the decided operation")
    persisted = _load_current(executor.aios_dir, effect_id)  # validated loader: contract/permit/provider/receipt
    for field in _EFFECT_IDENTITY_FIELDS:
        if action_result.get(field) != persisted.get(field):
            raise PermissionError(f"governed action result {field} differs from the persisted effect")
    if persisted.get("contract_id") != executor.contract_id or persisted.get("actor") != executor.actor:
        raise PermissionError("governed effect is bound to another contract or actor")
    if persisted.get("provider") != getattr(executor.adapter, "name", None):
        raise PermissionError("governed effect was executed by another provider")
    state = persisted.get("state")
    if state not in _OBSERVED_OUTCOMES:
        raise PermissionError(
            f"governed effect is {state}, not an observed outcome; explicit reconciliation required")
    receipt = load_receipt(executor.aios_dir, persisted["receipt_id"])  # sealed + attestation re-verified
    if receipt.get("outcome") != state or receipt.get("effect_id") != effect_id:
        raise PermissionError("governed effect receipt of record does not match the effect outcome")
    return state

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
        if not isinstance(result, Mapping) or result.get("effect_id") != _effect_id_for(
                self.contract_id, operation_id, self.actor):
            raise PermissionError("runtime returned an effect that is not bound to the decided operation")
        if isinstance(result, Mapping) and "provider_observation" in result:
            return {**deepcopy(dict(result)), "evidence": deepcopy(result["provider_observation"])}
        return result
    def verify(self, action_result: Any, state: Mapping[str, Any]) -> Any:
        # Authority gate before the caller verifier runs, so an UNKNOWN effect can
        # neither be reported verified nor contribute a state patch.
        _authoritative_effect_outcome(self, action_result)
        return self.verifier(deepcopy(action_result), deepcopy(state))

def run_governed_execution(*, executor: GovernedRuntimeExecutor, store: StateStore, policy: LoopPolicy) -> Mapping[str, Any]:
    """Run/resume the single AIOS durable loop with authority-bound state."""
    if not isinstance(executor, GovernedRuntimeExecutor):
        raise PermissionError("governed execution requires a GovernedRuntimeExecutor")
    # The generic durable-loop receipt contract (uuid write-ahead intent, generic
    # receipt status, reconcile_in_flight_attempt) is not mapped to effect-authority
    # EF-/attempt identities. Accepting it would let a real provider effect happen
    # and only then fail to satisfy or reconcile the loop receipt. Refuse it before
    # any state write or provider call; this bridge enforces receipts through the
    # effect authority gate instead (sealed receipt of record, reconciliation in
    # core.runtime) (PR #126 review comment 6761666720, disposition b).
    unsupported = [name for name, value in (
        ("require_execution_receipt", policy.require_execution_receipt),
        ("execution_receipt_validator", policy.execution_receipt_validator),
        ("state_patch_validator", policy.state_patch_validator),
    ) if value not in (None, False)]
    if unsupported:
        raise PermissionError(
            "governed bridge does not support durable-loop receipt mode "
            f"({', '.join(unsupported)}); effect-authority receipts are enforced instead")
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

    caller_resume_validator = policy.resume_validator

    def validate_resume(state: Mapping[str, Any]) -> None:
        if state.get("contract_id") != executor.contract_id: raise ValueError("persisted contract binding does not match execution context")
        if state.get("permit_id") != executor.permit_id: raise ValueError("persisted permit binding does not match execution context")
        authorize(executor.aios_dir, executor.contract_id, executor.permit_id)
        if caller_resume_validator is not None:
            caller_resume_validator(state)

    caller_terminal_evaluator = policy.terminal_evaluator
    non_success_terminals = {policy.failure_state, policy.budget_exhaustion_state}

    def governed_terminal(verification: Any, state: Mapping[str, Any]) -> str | None:
        # Defence in depth behind GovernedRuntimeExecutor.verify: no verdict is
        # evaluated for an action whose effect is not authoritatively observed,
        # and only OBSERVED_SUCCESS may reach a success-type terminal state.
        history = state.get("history")
        entry = history[-1] if isinstance(history, list) and history else None
        if not isinstance(entry, Mapping):
            raise PermissionError("governed terminal evaluation has no executed action")
        decision = entry.get("decision")
        operation_id = decision.get("logical_operation_id") if isinstance(decision, Mapping) else None
        if not isinstance(operation_id, str) or not operation_id.strip():
            raise PermissionError("governed terminal evaluation has no decided operation")
        outcome = _authoritative_effect_outcome(executor, entry.get("action"), operation_id)
        terminal = caller_terminal_evaluator(verification, state)
        if outcome != "OBSERVED_SUCCESS" and terminal is not None and terminal not in non_success_terminals:
            raise PermissionError(f"terminal verdict {terminal} requires an authoritative OBSERVED_SUCCESS effect")
        return terminal

    # Derive from the caller policy so no governance field (receipt enforcement,
    # validators, acceptance predicates, fix proof, continue contract) is
    # silently dropped; only authority-owned fields are overridden.
    bound_policy = replace(
        policy,
        terminal_evaluator=governed_terminal,
        resume_validator=validate_resume,
        policy_digest=contract["policy_digest"],
        terminal_states=governing_terminal_states,
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
        if state.get("in_flight_attempt") is not None and state.get("status") not in governing_terminal_states:
            # A loop intent from a receipt-mode run cannot be reconciled through this
            # bridge; never resume past it (that could re-decide an operation).
            reason = "unresolved durable-loop in-flight attempt; reconcile through effect authority before resuming"
            state["status"] = bound_policy.failure_state
            state["block_reason"] = reason
            state["terminal_evidence"] = {"step": state.get("step", 0), "status": bound_policy.failure_state,
                                          "verification": {"reason": reason}}
            store.save(state)
            return state
    return run_durable_loop(executor, store, bound_policy)

__all__ = ["GovernedRuntimeExecutor", "run_governed_execution"]
