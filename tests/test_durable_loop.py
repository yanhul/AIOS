import pytest

from core.durable_loop import LoopPolicy, MemoryStateStore, run_durable_loop
from core.harness_contract import HarnessPolicy
from core.trajectory import verify_trajectory


class FakeExecutor:
    def observe(self, state):
        return {"n": state["step"]}

    def decide(self, observation, state):
        return {"next": observation["n"] + 1}

    def act(self, decision, state):
        return decision["next"]

    def verify(self, action_result, state):
        return {"value": action_result, "evidence_ref": f"e-{action_result}"}


def _policy(max_steps=5, terminal_evaluator=None, **kwargs):
    return LoopPolicy(
        max_steps=max_steps,
        terminal_evaluator=terminal_evaluator or (
            lambda verification, state: "PASS" if verification["value"] >= 3 else None
        ),
        action_authorizer=lambda decision, state: None,
        **kwargs,
    )


def _harness(max_steps=5, **overrides):
    values = dict(
        execution_id="exec-1", contract_id="contract-1", contract_version="1",
        policy_digest="sha256:policy", capability_id="cap.research",
        capability_version="1.0.0", max_steps=max_steps, max_retries=2,
        allowed_effects=frozenset({"filesystem.write", "process.exec"}),
    )
    values.update(overrides)
    return HarnessPolicy(**values)


def test_loop_persists_and_passes_under_external_terminal_policy():
    store = MemoryStateStore()
    result = run_durable_loop(FakeExecutor(), store, _policy())
    assert result["status"] == "PASS"
    assert result["step"] == 3
    assert len(result["history"]) == 3
    assert store.load() == result


def test_budget_is_external_and_ends_inconclusive():
    store = MemoryStateStore()
    result = run_durable_loop(FakeExecutor(), store, _policy(max_steps=2, terminal_evaluator=lambda verification, state: None))
    assert result["status"] == "INCONCLUSIVE"
    assert result["step"] == 2


def test_loop_resumes_from_persisted_state():
    store = MemoryStateStore({"step": 1, "status": "RUNNING", "history": [{"step": 1}], "policy_digest": "p1"})
    result = run_durable_loop(FakeExecutor(), store, _policy(max_steps=3, policy_digest="p1", terminal_evaluator=lambda verification, state: "PASS" if state["step"] >= 3 else None))
    assert result["status"] == "PASS"
    assert result["step"] == 3
    assert len(result["history"]) == 3


def test_action_requires_control_plane_authorization():
    calls = []
    def deny(decision, state):
        calls.append(decision)
        raise PermissionError("denied by authority")
    policy = LoopPolicy(max_steps=3, terminal_evaluator=lambda verification, state: "PASS", action_authorizer=deny)
    result = run_durable_loop(FakeExecutor(), MemoryStateStore(), policy)
    assert result["status"] == "BLOCKED"
    assert "authorization" in result["block_reason"]
    assert calls == [{"next": 1}]


def test_resume_with_stale_policy_is_blocked():
    store = MemoryStateStore({"step": 1, "status": "RUNNING", "history": [], "policy_digest": "old"})
    result = run_durable_loop(FakeExecutor(), store, _policy(policy_digest="new"))
    assert result["status"] == "BLOCKED"
    assert "policy digest" in result["block_reason"]


def test_persisted_budget_tampering_is_blocked():
    store = MemoryStateStore({"step": 99, "status": "RUNNING", "history": []})
    result = run_durable_loop(FakeExecutor(), store, _policy(max_steps=2))
    assert result["status"] == "BLOCKED"
    assert "budget" in result["block_reason"]


def test_agent_cannot_forge_terminal_state():
    class ForgingExecutor(FakeExecutor):
        def decide(self, observation, state):
            state["status"] = "PASS"
            return {"next": observation["n"] + 1}
    result = run_durable_loop(ForgingExecutor(), MemoryStateStore(), _policy(max_steps=1, terminal_evaluator=lambda verification, state: None))
    assert result["status"] == "INCONCLUSIVE"


def test_agent_cannot_mutate_authoritative_history_through_snapshot():
    class MutatingExecutor(FakeExecutor):
        def observe(self, state):
            state["history"].append({"forged": True})
            return {"n": state["step"]}
    store = MemoryStateStore()
    result = run_durable_loop(MutatingExecutor(), store, _policy(max_steps=1, terminal_evaluator=lambda verification, state: None))
    assert result["status"] == "INCONCLUSIVE"
    assert result["history"] == [{"step": 1, "observation": {"n": 0}, "decision": {"next": 1}, "action": 1, "verification": {"value": 1, "evidence_ref": "e-1"}}]


def test_execution_failure_is_persisted_as_blocked():
    class FailingExecutor(FakeExecutor):
        def act(self, decision, state):
            raise RuntimeError("provider crashed")
    store = MemoryStateStore()
    result = run_durable_loop(FailingExecutor(), store, _policy(max_steps=3))
    assert result["status"] == "BLOCKED"
    assert "provider crashed" in result["block_reason"]
    assert store.load() == result
    assert result["step"] == 0
    assert result["history"] == []


def test_verification_failure_is_persisted_as_blocked():
    class FailingVerifier(FakeExecutor):
        def verify(self, action_result, state):
            raise RuntimeError("verification unavailable")
    store = MemoryStateStore()
    result = run_durable_loop(FailingVerifier(), store, _policy(max_steps=1))
    assert result["status"] == "BLOCKED"
    assert "verification unavailable" in result["block_reason"]
    assert store.load() == result


def test_terminal_evaluation_failure_is_persisted_as_blocked():
    store = MemoryStateStore()
    result = run_durable_loop(FakeExecutor(), store, _policy(max_steps=1, terminal_evaluator=lambda verification, state: (_ for _ in ()).throw(RuntimeError("gate unavailable"))))
    assert result["status"] == "BLOCKED"
    assert "gate unavailable" in result["block_reason"]
    assert store.load() == result


def test_harness_policy_is_authoritative_inside_durable_loop():
    harness = _harness(max_steps=3)
    policy = _policy(max_steps=3, policy_digest=harness.policy_digest, harness_policy=harness,
                     terminal_evaluator=lambda verification, state: "PASS" if state["step"] >= 2 else None,
                     trajectory_verifier=lambda records, max_steps: verify_trajectory(records, max_steps=max_steps))
    store = MemoryStateStore()
    result = run_durable_loop(FakeExecutor(), store, policy)
    assert result["status"] == "PASS"
    assert result["execution_id"] == "exec-1"
    assert result["capability_version"] == "1.0.0"
    assert result["budget_remaining"] == 1
    assert result["phase"] == "PERSIST"
    assert result["terminal_reason"] == "terminal evaluator returned PASS"
    assert result["records"] == result["history"]


def test_harness_resume_rejects_capability_or_budget_tampering():
    harness = _harness(max_steps=3)
    policy = _policy(max_steps=3, policy_digest=harness.policy_digest, harness_policy=harness,
                     terminal_evaluator=lambda verification, state: None)
    store = MemoryStateStore({
        "execution_id": "exec-1", "policy_digest": "sha256:policy", "capability_id": "cap.research",
        "capability_version": "0.9.0", "step": 1, "attempt": 1, "phase": "RESUME",
        "status": "RUNNING", "budget_remaining": 3, "retry_budget_remaining": 2,
        "pending_effect_id": None, "last_checkpoint_id": None, "records": [], "evidence": [],
        "terminal_reason": None, "history": [],
    })
    result = run_durable_loop(FakeExecutor(), store, policy)
    assert result["status"] == "BLOCKED"
    assert "capability version" in result["block_reason"]
