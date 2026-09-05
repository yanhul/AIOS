"""Governed durable execution loop.

The loop is the AIOS control-loop primitive. Governing policy remains outside the
agent/model, and every action must pass the control-plane authorization hook.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol

from .harness_contract import HarnessPolicy, HarnessState, EvidenceRef


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
    """Immutable execution policy owned by the AIOS control plane."""

    max_steps: int
    terminal_evaluator: Callable[[Any, Mapping[str, Any]], str | None]
    action_authorizer: Callable[[Any, Mapping[str, Any]], None]
    resume_validator: Callable[[Mapping[str, Any]], None] | None = None
    policy_digest: str | None = None
    harness_policy: HarnessPolicy | None = None
    trajectory_verifier: Callable[[list[Mapping[str, Any]], int], Any] | None = None

    def __post_init__(self) -> None:
        if self.max_steps < 1:
            raise ValueError("max_steps must be >= 1")
        if self.policy_digest is not None and (
            not isinstance(self.policy_digest, str) or not self.policy_digest.strip()
        ):
            raise ValueError("policy_digest must be a non-empty string when supplied")
        if self.harness_policy is not None and self.harness_policy.max_steps != self.max_steps:
            raise ValueError("harness policy max_steps must match loop policy")


@dataclass
class MemoryStateStore:
    state: dict[str, Any] = field(default_factory=dict)

    def load(self) -> Mapping[str, Any] | None:
        return deepcopy(self.state) if self.state else None

    def save(self, state: Mapping[str, Any]) -> None:
        self.state = deepcopy(dict(state))


def _harness_from_state(state: Mapping[str, Any], policy: HarnessPolicy) -> HarnessState:
    evidence = []
    for item in state.get("evidence", []):
        if not isinstance(item, Mapping):
            raise ValueError("persisted evidence entry is invalid")
        evidence.append(EvidenceRef(**dict(item)))
    return HarnessState(
        execution_id=state.get("execution_id", ""),
        policy_digest=state.get("policy_digest", ""),
        capability_id=state.get("capability_id", ""),
        capability_version=state.get("capability_version", ""),
        step=state.get("step", 0),
        attempt=state.get("attempt", 0),
        phase=state.get("phase", "RESUME"),
        status=state.get("status", "RUNNING"),
        budget_remaining=state.get("budget_remaining", 0),
        retry_budget_remaining=state.get("retry_budget_remaining", 0),
        pending_effect_id=state.get("pending_effect_id"),
        last_checkpoint_id=state.get("last_checkpoint_id"),
        records=state.get("records", []),
        evidence=evidence,
        terminal_reason=state.get("terminal_reason"),
    )


def _sync_harness_state(state: dict[str, Any], policy: HarnessPolicy) -> None:
    harness = _harness_from_state(state, policy)
    harness.validate(policy)
    state.update(harness.snapshot())
    state["history"] = deepcopy(state.get("records", state.get("history", [])))


def _initialize_harness_state(state: dict[str, Any], policy: HarnessPolicy) -> None:
    state.setdefault("execution_id", policy.execution_id)
    state.setdefault("policy_digest", policy.policy_digest)
    state.setdefault("capability_id", policy.capability_id)
    state.setdefault("capability_version", policy.capability_version)
    state.setdefault("step", 0)
    state.setdefault("attempt", 0)
    state.setdefault("phase", "RESUME")
    state.setdefault("status", "RUNNING")
    state.setdefault("budget_remaining", policy.max_steps)
    state.setdefault("retry_budget_remaining", policy.max_retries)
    state.setdefault("pending_effect_id", None)
    state.setdefault("last_checkpoint_id", None)
    state.setdefault("records", deepcopy(state.get("history", [])))
    state.setdefault("evidence", [])
    state.setdefault("terminal_reason", None)
    state["history"] = deepcopy(state["records"])


def _validate_loaded_state(state: Mapping[str, Any], policy: LoopPolicy) -> None:
    if not isinstance(state.get("step"), int) or isinstance(state.get("step"), bool):
        raise ValueError("persisted step is invalid")
    if state["step"] < 0 or state["step"] > policy.max_steps:
        raise ValueError("persisted step exceeds immutable execution budget")
    if state.get("status") not in {"RUNNING", *TERMINAL}:
        raise ValueError("persisted status is invalid")
    if not isinstance(state.get("history"), list):
        raise ValueError("persisted history is invalid")
    if policy.policy_digest is not None and state.get("policy_digest") != policy.policy_digest:
        raise ValueError("persisted policy digest does not match current policy")
    if policy.harness_policy is not None:
        _harness_from_state(state, policy.harness_policy).validate(policy.harness_policy)
    if policy.resume_validator is not None:
        policy.resume_validator(state)


def _checkpoint(state: dict[str, Any], store: StateStore, *, phase: str | None = None) -> None:
    if phase is not None:
        state["phase"] = phase
    if "records" in state:
        state["history"] = deepcopy(state["records"])
    if "budget_remaining" in state and "step" in state:
        state["budget_remaining"] = max(0, state.get("budget_remaining", 0))
    store.save(state)


def run_durable_loop(executor: Executor, store: StateStore, policy: LoopPolicy) -> Mapping[str, Any]:
    """Run/resume the governed loop, optionally backed by HarnessState authority."""
    loaded = store.load()
    state: dict[str, Any] = deepcopy(dict(loaded or {}))
    state.setdefault("step", 0)
    state.setdefault("status", "RUNNING")
    state.setdefault("history", [])
    if policy.policy_digest is not None:
        state.setdefault("policy_digest", policy.policy_digest)
    if policy.harness_policy is not None:
        _initialize_harness_state(state, policy.harness_policy)

    try:
        _validate_loaded_state(state, policy)
    except Exception as exc:
        state["status"] = "BLOCKED"
        state["block_reason"] = f"invalid durable state: {type(exc).__name__}: {exc}"
        if policy.harness_policy is not None:
            state["terminal_reason"] = state["block_reason"]
            state["phase"] = "PERSIST"
        _checkpoint(state, store)
        return state

    if state["status"] in TERMINAL:
        return state

    while state["step"] < policy.max_steps:
        try:
            state["phase"] = "OBSERVE"
            observation = executor.observe(deepcopy(state))
            state["phase"] = "DECIDE"
            decision = executor.decide(deepcopy(observation), deepcopy(state))
        except Exception as exc:
            state["status"] = "BLOCKED"
            state["block_reason"] = f"execution failed before authorization: {type(exc).__name__}: {exc}"
            if policy.harness_policy is not None:
                state["terminal_reason"] = state["block_reason"]
            _checkpoint(state, store, phase="PERSIST")
            return state

        try:
            state["phase"] = "AUTHORIZE"
            policy.action_authorizer(deepcopy(decision), deepcopy(state))
        except Exception as exc:
            state["status"] = "BLOCKED"
            state["block_reason"] = f"action authorization failed: {type(exc).__name__}: {exc}"
            if policy.harness_policy is not None:
                state["terminal_reason"] = state["block_reason"]
            _checkpoint(state, store, phase="PERSIST")
            return state

        try:
            state["phase"] = "ACT"
            action_result = executor.act(deepcopy(decision), deepcopy(state))
            state["phase"] = "VERIFY"
            verification = executor.verify(deepcopy(action_result), deepcopy(state))
        except Exception as exc:
            state["status"] = "BLOCKED"
            state["block_reason"] = f"execution failed after authorization: {type(exc).__name__}: {exc}"
            if policy.harness_policy is not None:
                state["terminal_reason"] = state["block_reason"]
            _checkpoint(state, store, phase="PERSIST")
            return state

        state["step"] += 1
        state["attempt"] = state.get("attempt", 0) + 1
        record = {
            "step": state["step"],
            "observation": deepcopy(observation),
            "decision": deepcopy(decision),
            "action": deepcopy(action_result),
            "verification": deepcopy(verification),
        }
        state["history"].append(record)
        state["records"] = deepcopy(state["history"])
        state["budget_remaining"] = max(0, policy.max_steps - state["step"])

        try:
            if policy.trajectory_verifier is not None:
                policy.trajectory_verifier(deepcopy(state["history"]), policy.max_steps)
            state["phase"] = "RECONCILE"
            terminal = policy.terminal_evaluator(deepcopy(verification), deepcopy(state))
            if terminal is not None and terminal not in TERMINAL:
                raise ValueError(f"invalid terminal status: {terminal}")
        except Exception as exc:
            state["status"] = "BLOCKED"
            state["block_reason"] = f"verification/terminal evaluation failed: {type(exc).__name__}: {exc}"
            if policy.harness_policy is not None:
                state["terminal_reason"] = state["block_reason"]
            _checkpoint(state, store, phase="PERSIST")
            return state

        if terminal is not None:
            state["status"] = terminal
            if policy.harness_policy is not None:
                state["terminal_reason"] = f"terminal evaluator returned {terminal}"
            _checkpoint(state, store, phase="PERSIST")
            return state

        state["status"] = "RUNNING"
        state["terminal_reason"] = None
        _checkpoint(state, store, phase="PERSIST")
        if policy.harness_policy is not None:
            _validate_loaded_state(state, policy)

    state["status"] = "INCONCLUSIVE"
    state["terminal_reason"] = "immutable step budget exhausted" if policy.harness_policy is not None else state.get("terminal_reason")
    _checkpoint(state, store, phase="PERSIST")
    if policy.harness_policy is not None:
        _validate_loaded_state(state, policy)
    return state
