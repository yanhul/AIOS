"""Governed durable execution loop.

The loop is the AIOS control-loop primitive. Governing policy remains outside the
agent/model, and every action must pass the control-plane authorization hook.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol


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

    def __post_init__(self) -> None:
        if self.max_steps < 1:
            raise ValueError("max_steps must be >= 1")
        if self.policy_digest is not None and (
            not isinstance(self.policy_digest, str) or not self.policy_digest.strip()
        ):
            raise ValueError("policy_digest must be a non-empty string when supplied")


@dataclass
class MemoryStateStore:
    state: dict[str, Any] = field(default_factory=dict)

    def load(self) -> Mapping[str, Any] | None:
        return deepcopy(self.state) if self.state else None

    def save(self, state: Mapping[str, Any]) -> None:
        self.state = deepcopy(dict(state))


def _validate_loaded_state(
    state: Mapping[str, Any], policy: LoopPolicy
) -> None:
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
    if policy.resume_validator is not None:
        policy.resume_validator(state)


def run_durable_loop(
    executor: Executor,
    store: StateStore,
    policy: LoopPolicy,
) -> Mapping[str, Any]:
    """Run/resume OBSERVE -> DECIDE -> ACT -> VERIFY -> PERSIST.

    The executor receives isolated snapshots and cannot mutate authoritative state.
    It cannot bypass authorization, extend the budget, redefine terminal conditions,
    or make a stale persisted state authoritative.
    """
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
        state["status"] = "BLOCKED"
        state["block_reason"] = f"invalid durable state: {type(exc).__name__}: {exc}"
        store.save(state)
        return state

    if state["status"] in TERMINAL:
        return state

    while state["step"] < policy.max_steps:
        observation = executor.observe(deepcopy(state))
        decision = executor.decide(deepcopy(observation), deepcopy(state))
        try:
            policy.action_authorizer(deepcopy(decision), deepcopy(state))
        except Exception as exc:
            state["status"] = "BLOCKED"
            state["block_reason"] = f"action authorization failed: {type(exc).__name__}: {exc}"
            store.save(state)
            return state
        action_result = executor.act(deepcopy(decision), deepcopy(state))
        verification = executor.verify(deepcopy(action_result), deepcopy(state))

        state["step"] += 1
        state["history"].append(
            {
                "step": state["step"],
                "observation": deepcopy(observation),
                "decision": deepcopy(decision),
                "action": deepcopy(action_result),
                "verification": deepcopy(verification),
            }
        )

        terminal = policy.terminal_evaluator(deepcopy(verification), deepcopy(state))
        if terminal is not None:
            if terminal not in TERMINAL:
                raise ValueError(f"invalid terminal status: {terminal}")
            state["status"] = terminal
            store.save(state)
            return state

        state["status"] = "RUNNING"
        store.save(state)

    state["status"] = "INCONCLUSIVE"
    store.save(state)
    return state
