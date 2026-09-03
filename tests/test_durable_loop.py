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


def test_loop_persists_and_passes_under_external_terminal_policy():
    store = MemoryStateStore()
    policy = LoopPolicy(
        max_steps=5,
        terminal_evaluator=lambda verification, state: (
            "PASS" if verification["value"] >= 3 else None
        ),
    )

    result = run_durable_loop(FakeExecutor(), store, policy)

    assert result["status"] == "PASS"
    assert result["step"] == 3
    assert len(result["history"]) == 3
    assert store.load() == result


def test_budget_is_external_and_ends_inconclusive():
    store = MemoryStateStore()
    policy = LoopPolicy(max_steps=2, terminal_evaluator=lambda verification, state: None)

    result = run_durable_loop(FakeExecutor(), store, policy)

    assert result["status"] == "INCONCLUSIVE"
    assert result["step"] == 2


def test_loop_resumes_from_persisted_state():
    store = MemoryStateStore({
        "step": 1,
        "status": "RUNNING",
        "history": [{"step": 1}],
    })
    policy = LoopPolicy(
        max_steps=3,
        terminal_evaluator=lambda verification, state: (
            "PASS" if state["step"] >= 3 else None
        ),
    )

    result = run_durable_loop(FakeExecutor(), store, policy)

    assert result["status"] == "PASS"
    assert result["step"] == 3
    assert len(result["history"]) == 3
