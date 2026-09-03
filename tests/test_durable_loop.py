import pytest

from core.durable_loop import LoopPolicy, MemoryStateStore, run_durable_loop


class FakeExecutor:
    def observe(self, state):
        return {"n": state["step"]}

    def decide(self, observation, state):
        return {"next": observation["n"] + 1}

    def act(self, decision, state):
        return decision["next"]

    def verify(self, action_result, state):
        return {"value": action_result}


def _policy(max_steps=5, terminal_evaluator=None, **kwargs):
    return LoopPolicy(
        max_steps=max_steps,
        terminal_evaluator=terminal_evaluator or (
            lambda verification, state: "PASS" if verification["value"] >= 3 else None
        ),
        action_authorizer=lambda decision, state: None,
        **kwargs,
    )


def test_loop_persists_and_passes_under_external_terminal_policy():
    store = MemoryStateStore()
    result = run_durable_loop(FakeExecutor(), store, _policy())

    assert result["status"] == "PASS"
    assert result["step"] == 3
    assert len(result["history"]) == 3
    assert store.load() == result


def test_budget_is_external_and_ends_inconclusive():
    store = MemoryStateStore()
    result = run_durable_loop(
        FakeExecutor(), store, _policy(max_steps=2, terminal_evaluator=lambda verification, state: None)
    )

    assert result["status"] == "INCONCLUSIVE"
    assert result["step"] == 2


def test_loop_resumes_from_persisted_state():
    store = MemoryStateStore({
        "step": 1,
        "status": "RUNNING",
        "history": [{"step": 1}],
        "policy_digest": "p1",
    })
    result = run_durable_loop(
        FakeExecutor(),
        store,
        _policy(max_steps=3, policy_digest="p1", terminal_evaluator=lambda verification, state: "PASS" if state["step"] >= 3 else None),
    )

    assert result["status"] == "PASS"
    assert result["step"] == 3
    assert len(result["history"]) == 3


def test_action_requires_control_plane_authorization():
    calls = []

    def deny(decision, state):
        calls.append(decision)
        raise PermissionError("denied by authority")

    policy = LoopPolicy(
        max_steps=3,
        terminal_evaluator=lambda verification, state: "PASS",
        action_authorizer=deny,
    )
    with pytest.raises(PermissionError):
        run_durable_loop(FakeExecutor(), MemoryStateStore(), policy)
    assert calls == [{"next": 1}]


def test_resume_with_stale_policy_is_blocked():
    store = MemoryStateStore({
        "step": 1,
        "status": "RUNNING",
        "history": [],
        "policy_digest": "old",
    })
    result = run_durable_loop(
        FakeExecutor(),
        store,
        _policy(policy_digest="new"),
    )
    assert result["status"] == "BLOCKED"
    assert "policy digest" in result["block_reason"]


def test_persisted_budget_tampering_is_blocked():
    store = MemoryStateStore({
        "step": 99,
        "status": "RUNNING",
        "history": [],
    })
    result = run_durable_loop(FakeExecutor(), store, _policy(max_steps=2))
    assert result["status"] == "BLOCKED"
    assert "budget" in result["block_reason"]


def test_agent_cannot_forge_terminal_state():
    class ForgingExecutor(FakeExecutor):
        def decide(self, observation, state):
            state["status"] = "PASS"
            return {"next": observation["n"] + 1}

    result = run_durable_loop(
        ForgingExecutor(),
        MemoryStateStore(),
        _policy(max_steps=1, terminal_evaluator=lambda verification, state: None),
    )
    assert result["status"] == "INCONCLUSIVE"
