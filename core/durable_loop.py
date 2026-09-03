"""Governed durable execution loop.

The loop deliberately keeps governing policy outside the agent/model. A workload may
observe, plan, act, verify and request the next step, but it cannot mutate policy,
terminal conditions, evidence requirements, or retry budgets.
"""
from __future__ import annotations

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
    """Immutable execution policy owned by the control plane."""

    max_steps: int
    terminal_evaluator: Callable[[Any, Mapping[str, Any]], str | None]
    allow_retry: bool = True

    def __post_init__(self) -> None:
        if self.max_steps < 1:
            raise ValueError("max_steps must be >= 1")


@dataclass
class MemoryStateStore:
    state: dict[str, Any] = field(default_factory=dict)

    def load(self) -> Mapping[str, Any] | None:
        return dict(self.state) if self.state else None

    def save(self, state: Mapping[str, Any]) -> None:
        self.state = dict(state)


def run_durable_loop(
    executor: Executor,
    store: StateStore,
    policy: LoopPolicy,
) -> Mapping[str, Any]:
    """Run or resume OBSERVE -> DECIDE -> ACT -> VERIFY -> PERSIST.

    Terminal status is selected only by the externally supplied policy. The executor
    cannot alter the policy object or extend the step budget.
    """
    loaded = store.load()
    state: dict[str, Any] = dict(loaded or {})
    state.setdefault("step", 0)
    state.setdefault("status", "RUNNING")
    state.setdefault("history", [])

    if state["status"] in TERMINAL:
        return state

    while state["step"] < policy.max_steps:
        observation = executor.observe(state)
        decision = executor.decide(observation, state)
        action_result = executor.act(decision, state)
        verification = executor.verify(action_result, state)

        state["step"] += 1
        state["history"].append(
            {
                "step": state["step"],
                "observation": observation,
                "decision": decision,
                "action": action_result,
                "verification": verification,
            }
        )

        terminal = policy.terminal_evaluator(verification, state)
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
