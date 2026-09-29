# AIOS-CONTRACT: governed execution lifecycle transitions are typed and evidence-bearing
# AIOS-REGRESSION: UNKNOWN execution receipts cannot become terminal PASS
# AIOS-OWNER: AIOS control plane owns lifecycle sequencing and durable commit
# AIOS-COVERAGE-GAP: covers new event lifecycle and lineage isolation not covered by existing durable-loop tests
# AIOS-BASELINE: main durable_loop receipt/lineage contract
from core.durable_loop import LoopPolicy, MemoryStateStore, run_durable_loop
from core.execution_events import ExecutionEventStream


class Executor:
    def observe(self, state):
        return {"ok": True}

    def decide(self, observation, state):
        return {"effect_id": "effect-1", "attempt_id": "attempt-1"}

    def act(self, decision, state):
        return {"provider": "test-provider"}

    def verify(self, action_result, state):
        return {
            "status": "FIXED",
            "receipt": {
                "effect_id": "effect-1",
                "attempt_id": "attempt-1",
                "status": "OBSERVED",
                "evidence": {"provider": action_result["provider"], "observed": True},
            },
        }


def test_nautilus_adapted_execution_lifecycle_is_governed():
    stream = ExecutionEventStream()
    policy = LoopPolicy(
        max_steps=1,
        terminal_evaluator=lambda verification, state: "PASS",
        action_authorizer=lambda decision, state: None,
        require_execution_receipt=True,
        execution_events=stream,
    )
    state = run_durable_loop(Executor(), MemoryStateStore(), policy)

    assert state["status"] == "PASS"
    assert [event.status for event in stream.events()] == [
        "PERMITTED",
        "DISPATCHED",
        "EXECUTE_ATTEMPTED",
        "OBSERVED",
        "VERIFIED",
        "COMMITTED",
    ]
    assert all(event.effect_id == "effect-1" for event in stream.events())
    assert all(event.attempt_id == "attempt-1" for event in stream.events())
    assert [event.sequence for event in stream.events()] == list(range(6))


def test_unknown_cannot_be_promoted_to_terminal():
    class UnknownExecutor(Executor):
        def verify(self, action_result, state):
            return {
                "receipt": {
                    "effect_id": "effect-unknown",
                    "attempt_id": "attempt-unknown",
                    "status": "UNKNOWN",
                    "evidence": {"provider": "test-provider"},
                }
            }

    stream = ExecutionEventStream()
    policy = LoopPolicy(
        max_steps=1,
        terminal_evaluator=lambda verification, state: "PASS",
        action_authorizer=lambda decision, state: None,
        require_execution_receipt=True,
        execution_events=stream,
    )
    state = run_durable_loop(UnknownExecutor(), MemoryStateStore(), policy)

    assert state["status"] == "BLOCKED"
    assert [event.status for event in stream.events()] == [
        "PERMITTED",
        "DISPATCHED",
        "EXECUTE_ATTEMPTED",
        "UNKNOWN",
    ]


def test_event_stream_scopes_sequence_per_lineage():
    stream = ExecutionEventStream()
    stream.emit(effect_id="e1", attempt_id="a1", status="PERMITTED", evidence={"source": "test"})
    stream.emit(effect_id="e2", attempt_id="a2", status="PERMITTED", evidence={"source": "test"})
    stream.emit(effect_id="e1", attempt_id="a1", status="DISPATCHED", evidence={"source": "test"})

    events = stream.events()
    assert [event.sequence for event in events] == [0, 0, 1]
    assert [(event.effect_id, event.attempt_id) for event in events] == [
        ("e1", "a1"), ("e2", "a2"), ("e1", "a1")
    ]


def test_observed_receipt_cannot_claim_different_authorized_lineage():
    class MismatchExecutor(Executor):
        def verify(self, action_result, state):
            return {
                "receipt": {
                    "effect_id": "effect-other",
                    "attempt_id": "attempt-other",
                    "status": "OBSERVED",
                    "evidence": {"provider": "test-provider"},
                }
            }

    stream = ExecutionEventStream()
    policy = LoopPolicy(
        max_steps=1,
        terminal_evaluator=lambda verification, state: "PASS",
        action_authorizer=lambda decision, state: None,
        require_execution_receipt=True,
        execution_events=stream,
    )
    state = run_durable_loop(MismatchExecutor(), MemoryStateStore(), policy)

    assert state["status"] == "BLOCKED"
    assert "lineage" in state["block_reason"]
    assert [event.status for event in stream.events()] == [
        "PERMITTED", "DISPATCHED", "EXECUTE_ATTEMPTED"
    ]


def test_blocked_terminal_does_not_emit_verified():
    stream = ExecutionEventStream()
    policy = LoopPolicy(
        max_steps=1,
        terminal_evaluator=lambda verification, state: "BLOCKED",
        action_authorizer=lambda decision, state: None,
        require_execution_receipt=True,
        execution_events=stream,
    )
    state = run_durable_loop(Executor(), MemoryStateStore(), policy)

    assert state["status"] == "BLOCKED"
    assert [event.status for event in stream.events()] == [
        "PERMITTED", "DISPATCHED", "EXECUTE_ATTEMPTED", "OBSERVED"
    ]
