import pytest

from core.durable_loop import LoopPolicy, MemoryStateStore, run_durable_loop


class FencedExecutor:
    def observe(self, state):
        return {"n": state["step"]}

    def decide(self, observation, state):
        return {"effect_id": "effect-1"}

    def act(self, decision, state):
        assert state["active_attempt"]["effect_id"] == "effect-1"
        assert state["attempt_started_before_effect"] is True
        return "ok"

    def verify(self, action_result, state):
        attempt = state["active_attempt"]
        return {
            "receipt": {
                **attempt,
                "status": "OBSERVED",
                "attempt_started_before_effect": True,
                "evidence": {"result": action_result},
            }
        }


def fenced_policy():
    return LoopPolicy(
        max_steps=1,
        terminal_evaluator=lambda verification, state: "PASS",
        action_authorizer=lambda decision, state: None,
        require_execution_receipt=True,
        require_execution_fence=True,
        attempt_recorder=lambda decision, state: {
            "effect_id": decision["effect_id"],
            "attempt_id": "attempt-1",
            "generation": "gen-1",
        },
    )


def test_fence_persists_attempt_before_side_effect():
    store = MemoryStateStore()
    result = run_durable_loop(FencedExecutor(), store, fenced_policy())
    assert result["status"] == "PASS"
    assert result["active_attempt"] == {
        "effect_id": "effect-1",
        "attempt_id": "attempt-1",
        "generation": "gen-1",
    }
    assert result["attempt_started_before_effect"] is True


def test_fence_rejects_stale_generation():
    class StaleExecutor(FencedExecutor):
        def verify(self, action_result, state):
            return {
                "receipt": {
                    "effect_id": "effect-1",
                    "attempt_id": "attempt-1",
                    "generation": "old-generation",
                    "status": "OBSERVED",
                    "attempt_started_before_effect": True,
                    "evidence": {"result": action_result},
                }
            }

    result = run_durable_loop(StaleExecutor(), MemoryStateStore(), fenced_policy())
    assert result["status"] == "BLOCKED"
    assert "fence" in result["block_reason"]


def test_fence_rejects_receipt_without_pre_effect_proof():
    class LateAttemptExecutor(FencedExecutor):
        def verify(self, action_result, state):
            attempt = state["active_attempt"]
            return {
                "receipt": {
                    **attempt,
                    "status": "OBSERVED",
                    "attempt_started_before_effect": False,
                    "evidence": {"result": action_result},
                }
            }

    result = run_durable_loop(LateAttemptExecutor(), MemoryStateStore(), fenced_policy())
    assert result["status"] == "BLOCKED"
    assert "before side effect" in result["block_reason"]


def test_fence_requires_attempt_recorder():
    with pytest.raises(ValueError, match="attempt_recorder"):
        LoopPolicy(
            max_steps=1,
            terminal_evaluator=lambda verification, state: "PASS",
            action_authorizer=lambda decision, state: None,
            require_execution_fence=True,
        )
