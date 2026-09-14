"""Governed durable execution loop."""
from __future__ import annotations
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol

from .fix_protocol import FixPlan, require_fix_plan, require_fix_proof, FixProof

TERMINAL = frozenset({"PASS", "BLOCKED", "INCONCLUSIVE"})

class StateStore(Protocol):
    def load(self) -> Mapping[str, Any] | None: ...
    def save(self, state: Mapping[str, Any]) -> None: ...

class Executor(Protocol):
    def observe(self, state: Mapping[str, Any]) -> Any: ...
    def decide(self, observation: Any, state: Mapping[str, Any]) -> Any: ...
    def act(self, decision: Any, state: Mapping[str, Any]) -> Any: ...
    def verify(self, action_result: Any, state: Mapping[str, Any]) -> Any: ...

@dataclass(frozen=True)
class LoopPolicy:
    max_steps: int
    terminal_evaluator: Callable[[Any, Mapping[str, Any]], str | None]
    action_authorizer: Callable[[Any, Mapping[str, Any]], None]
    resume_validator: Callable[[Mapping[str, Any]], None] | None = None
    policy_digest: str | None = None
    terminal_states: frozenset[str] = TERMINAL
    budget_exhaustion_state: str = "INCONCLUSIVE"
    failure_state: str = "BLOCKED"
    require_execution_receipt: bool = False
    execution_receipt_validator: Callable[[Mapping[str, Any], Mapping[str, Any]], None] | None = None
    # Fix workflows opt into the normative fix protocol. The plan is external
    # governance; the executor cannot replace or weaken it.
    fix_plan: FixPlan | None = None
    fix_success_state: str = "PASS"

    def __post_init__(self) -> None:
        if self.max_steps < 1:
            raise ValueError("max_steps must be >= 1")
        if self.policy_digest is not None and (not isinstance(self.policy_digest, str) or not self.policy_digest.strip()):
            raise ValueError("policy_digest must be a non-empty string when supplied")
        if not self.terminal_states or not all(isinstance(v, str) and v.strip() for v in self.terminal_states):
            raise ValueError("terminal_states must be a non-empty set of strings")
        if not isinstance(self.budget_exhaustion_state, str) or not self.budget_exhaustion_state.strip():
            raise ValueError("budget_exhaustion_state must be a non-empty string")
        if self.budget_exhaustion_state not in self.terminal_states:
            raise ValueError("budget_exhaustion_state must be an authorized terminal state")
        if not isinstance(self.failure_state, str) or not self.failure_state.strip():
            raise ValueError("failure_state must be a non-empty string")
        if self.failure_state not in self.terminal_states:
            raise ValueError("failure_state must be an authorized terminal state")
        if not isinstance(self.require_execution_receipt, bool):
            raise ValueError("require_execution_receipt must be boolean")
        if self.execution_receipt_validator is not None and not callable(self.execution_receipt_validator):
            raise ValueError("execution_receipt_validator must be callable")
        if not isinstance(self.fix_success_state, str) or not self.fix_success_state.strip():
            raise ValueError("fix_success_state must be a non-empty string")
        if self.fix_success_state not in self.terminal_states:
            raise ValueError("fix_success_state must be an authorized terminal state")
        if self.fix_plan is not None:
            require_fix_plan(self.fix_plan)

def _validate_execution_receipt(verification: Any) -> Mapping[str, Any]:
    """Fail closed unless verification contains a complete execution receipt."""
    if not isinstance(verification, Mapping):
        raise ValueError("execution receipt missing from verification")
    receipt = verification.get("receipt")
    if not isinstance(receipt, Mapping):
        raise ValueError("execution receipt missing from verification")
    required = ("effect_id", "attempt_id", "status")
    if any(not isinstance(receipt.get(key), str) or not receipt[key].strip() for key in required):
        raise ValueError("execution receipt lineage is incomplete")
    status = receipt.get("status")
    if status not in {"OBSERVED", "UNKNOWN"}:
        raise ValueError("execution receipt has unauthorized status")
    evidence = receipt.get("evidence")
    if not isinstance(evidence, Mapping) or not evidence:
        raise ValueError("execution receipt evidence is missing or empty")
    return receipt

@dataclass
class MemoryStateStore:
    state: dict[str, Any] = field(default_factory=dict)
    def load(self) -> Mapping[str, Any] | None:
        return deepcopy(self.state) if self.state else None
    def save(self, state: Mapping[str, Any]) -> None:
        self.state = deepcopy(dict(state))

def _validate_loaded_state(state: Mapping[str, Any], policy: LoopPolicy) -> None:
    if not isinstance(state.get("step"), int) or isinstance(state.get("step"), bool):
        raise ValueError("persisted step is invalid")
    if state["step"] < 0 or state["step"] > policy.max_steps:
        raise ValueError("persisted step exceeds immutable execution budget")
    if state.get("status") not in {"RUNNING", *policy.terminal_states}:
        raise ValueError("persisted status is invalid")
    if not isinstance(state.get("history"), list):
        raise ValueError("persisted history is invalid")
    if policy.policy_digest is not None and state.get("policy_digest") != policy.policy_digest:
        raise ValueError("persisted policy digest does not match current policy")
    if policy.resume_validator is not None:
        policy.resume_validator(state)

def _validate_fix_success(verification: Any, expected_state: str) -> None:
    """Require externally verifiable runtime proof before fix promotion."""
    if expected_state == "PASS":
        if not isinstance(verification, Mapping) or verification.get("status") != "FIXED":
            raise ValueError("PASS in a governed fix workflow requires status=FIXED")
        proof = verification.get("fix_proof")
        if not isinstance(proof, FixProof):
            raise ValueError("FIXED requires verifier-supplied FixProof")
        require_fix_proof(proof)

def run_durable_loop(executor: Executor, store: StateStore, policy: LoopPolicy) -> Mapping[str, Any]:
    """Run/resume OBSERVE -> DECIDE -> ACT -> VERIFY -> PERSIST with governed receipt/fix enforcement."""
    loaded = store.load()
    state: dict[str, Any] = deepcopy(dict(loaded or {}))
    state.setdefault("step", 0)
    state.setdefault("status", "RUNNING")
    state.setdefault("history", [])
    if policy.policy_digest is not None:
        state.setdefault("policy_digest", policy.policy_digest)
    try:
        _validate_loaded_state(state, policy)
    except Exception as exc:
        state["status"] = policy.failure_state
        state["block_reason"] = f"invalid durable state: {type(exc).__name__}: {exc}"
        store.save(state)
        return state
    if state["status"] in policy.terminal_states:
        return state
    while state["step"] < policy.max_steps:
        try:
            observation = executor.observe(deepcopy(state))
            decision = executor.decide(deepcopy(observation), deepcopy(state))
        except Exception as exc:
            state["status"] = policy.failure_state
            state["block_reason"] = f"execution failed before authorization: {type(exc).__name__}: {exc}"
            store.save(state)
            return state
        try:
            policy.action_authorizer(deepcopy(decision), deepcopy(state))
        except Exception as exc:
            state["status"] = policy.failure_state
            state["block_reason"] = f"action authorization failed: {type(exc).__name__}: {exc}"
            store.save(state)
            return state
        try:
            action_result = executor.act(deepcopy(decision), deepcopy(state))
            verification = executor.verify(deepcopy(action_result), deepcopy(state))
            receipt = None
            if policy.require_execution_receipt:
                receipt = _validate_execution_receipt(verification)
                if policy.execution_receipt_validator is not None:
                    policy.execution_receipt_validator(deepcopy(receipt), deepcopy(state))
        except Exception as exc:
            state["status"] = policy.failure_state
            state["block_reason"] = f"execution failed after authorization: {type(exc).__name__}: {exc}"
            store.save(state)
            return state
        state["step"] += 1
        state["history"].append({"step": state["step"], "observation": deepcopy(observation), "decision": deepcopy(decision), "action": deepcopy(action_result), "verification": deepcopy(verification)})
        try:
            terminal = policy.terminal_evaluator(deepcopy(verification), deepcopy(state))
            if terminal is not None and terminal not in policy.terminal_states:
                raise ValueError(f"invalid terminal status: {terminal}")
            if policy.require_execution_receipt and receipt is not None and receipt["status"] == "UNKNOWN" and terminal is not None:
                raise ValueError("UNKNOWN execution receipt cannot authorize a terminal verdict")
            if policy.fix_plan is not None and terminal == policy.fix_success_state:
                _validate_fix_success(verification, terminal)
        except Exception as exc:
            state["status"] = policy.failure_state
            state["block_reason"] = f"terminal evaluation failed: {type(exc).__name__}: {exc}"
            store.save(state)
            return state
        if terminal is not None:
            state["status"] = terminal
            store.save(state)
            return state
        state["status"] = "RUNNING"
        store.save(state)
    state["status"] = policy.budget_exhaustion_state
    store.save(state)
    return state

__all__ = ["TERMINAL", "LoopPolicy", "MemoryStateStore", "run_durable_loop"]
