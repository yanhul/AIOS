# AIOS-CONTRACT: durable loop state persistence and continuation boundary
# AIOS-REGRESSION: Prevent state loss across durable save/resume
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Covers persisted state patches and continuation tamper rejection
# AIOS-BASELINE: Tests target the existing durable-loop contract baseline

import pytest

from core.durable_loop import LoopPolicy, MemoryStateStore, run_durable_loop, _persist_state
from core.continue_contract import build_continue_contract


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
    store = MemoryStateStore({"step": 1, "status": "RUNNING", "history": [{"step": 1}], "policy_digest": "p1"})
    result = run_durable_loop(
        FakeExecutor(), store,
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
    assert result["history"] == [{"step": 1, "observation": {"n": 0}, "decision": {"next": 1}, "action": 1, "verification": {"value": 1}}]


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
    result = run_durable_loop(
        FakeExecutor(), store,
        _policy(max_steps=1, terminal_evaluator=lambda verification, state: (_ for _ in ()).throw(RuntimeError("gate unavailable"))),
    )
    assert result["status"] == "BLOCKED"
    assert "gate unavailable" in result["block_reason"]
    assert store.load() == result


def test_custom_terminal_states_are_authoritative():
    store = MemoryStateStore()
    policy = _policy(
        max_steps=1,
        terminal_states=frozenset({"PROMOTE", "REJECT", "INCONCLUSIVE", "BLOCKED"}),
        terminal_evaluator=lambda verification, state: "PROMOTE",
    )
    result = run_durable_loop(FakeExecutor(), store, policy)
    assert result["status"] == "PROMOTE"
    assert store.load() == result


def test_custom_terminal_state_cannot_be_forged_by_executor():
    class ForgingExecutor(FakeExecutor):
        def decide(self, observation, state):
            state["status"] = "PROMOTE"
            return {"next": observation["n"] + 1}

    result = run_durable_loop(
        ForgingExecutor(),
        MemoryStateStore(),
        _policy(
            max_steps=1,
            terminal_states=frozenset({"PROMOTE", "REJECT", "INCONCLUSIVE", "BLOCKED"}),
            terminal_evaluator=lambda verification, state: None,
        ),
    )
    assert result["status"] == "INCONCLUSIVE"


def test_budget_exhaustion_terminal_must_be_explicitly_authorized():
    with pytest.raises(ValueError, match="budget_exhaustion_state"):
        _policy(
            max_steps=1,
            terminal_states=frozenset({"PASS", "BLOCKED"}),
            terminal_evaluator=lambda verification, state: None,
        )


def test_budget_exhaustion_uses_governed_terminal_state():
    policy = _policy(
        max_steps=1,
        terminal_states=frozenset({"PASS", "REJECT", "INCONCLUSIVE", "BLOCKED"}),
        budget_exhaustion_state="REJECT",
        terminal_evaluator=lambda verification, state: None,
    )
    result = run_durable_loop(FakeExecutor(), MemoryStateStore(), policy)
    assert result["status"] == "REJECT"


class ReceiptExecutor(FakeExecutor):
    def verify(self, action_result, state):
        return {
            "value": action_result,
            "receipt": {
                "effect_id": state["in_flight_attempt"]["effect_id"],
                "attempt_id": state["in_flight_attempt"]["attempt_id"],
                "status": "OBSERVED",
                "evidence": {"result": action_result},
            },
        }


def test_receipt_lineage_is_required_before_terminal_evaluation():
    policy = _policy(max_steps=1, require_execution_receipt=True, terminal_evaluator=lambda verification, state: "PASS")
    result = run_durable_loop(FakeExecutor(), MemoryStateStore(), policy)
    assert result["status"] == "BLOCKED"
    assert "receipt" in result["block_reason"]
    assert result["step"] == 0
    assert result["history"] == []


def test_valid_receipt_lineage_reaches_terminal_evaluation():
    policy = _policy(max_steps=1, require_execution_receipt=True, terminal_evaluator=lambda verification, state: "PASS")
    result = run_durable_loop(ReceiptExecutor(), MemoryStateStore(), policy)
    assert result["status"] == "PASS"
    assert result["step"] == 1
    assert result["history"][0]["verification"]["receipt"]["attempt_id"].startswith("attempt-")


def test_unknown_receipt_cannot_authorize_terminal_verdict():
    class UnknownReceiptExecutor(ReceiptExecutor):
        def verify(self, action_result, state):
            result = super().verify(action_result, state)
            result["receipt"]["status"] = "UNKNOWN"
            return result

    policy = _policy(max_steps=1, require_execution_receipt=True, terminal_evaluator=lambda verification, state: "PASS")
    result = run_durable_loop(UnknownReceiptExecutor(), MemoryStateStore(), policy)
    assert result["status"] == "BLOCKED"
    assert "UNKNOWN execution receipt" in result["block_reason"]


class StatePatchExecutor(FakeExecutor):
    def verify(self, action_result, state):
        return {"value": action_result, "state_patch": {"latest_attempt_dir": "attempt-1", "blocked_requirements": ["G7"]}}


def test_state_patch_is_durable_across_resume():
    store = MemoryStateStore()
    result = run_durable_loop(
        StatePatchExecutor(), store,
        _policy(max_steps=1, terminal_evaluator=lambda v, s: None),
    )
    assert result["latest_attempt_dir"] == "attempt-1"
    assert result["blocked_requirements"] == ["G7"]
    persisted = store.load()
    assert persisted["latest_attempt_dir"] == "attempt-1"
    assert persisted["blocked_requirements"] == ["G7"]



def test_verifier_state_patch_cannot_mutate_control_plane_fields():
    class ForgingVerifier(FakeExecutor):
        def verify(self, action_result, state):
            return {
                "value": action_result,
                "state_patch": {
                    "step": 99,
                    "status": "PASS",
                    "history": [{"forged": True}],
                    "terminal_evidence": {"status": "PASS"},
                    "continue_contract": {"forged": True},
                    "policy_digest": "forged",
                },
            }

    store = MemoryStateStore()
    result = run_durable_loop(
        ForgingVerifier(), store,
        _policy(max_steps=1, terminal_evaluator=lambda verification, state: None),
    )
    assert result["status"] == "BLOCKED"
    assert "protected fields" in result["block_reason"]
    assert result["step"] == 0
    assert result["history"] == []
    assert result["terminal_evidence"]["status"] == "BLOCKED"
    assert "continue_contract" not in result


def test_continue_contract_is_persisted_and_revalidated_on_resume():
    from core.continue_contract import build_continue_contract

    base = {
        "project": "yanhul/temp",
        "design": "QI9-2605-A01",
        "authority": "AIOS_CONTROL_PLANE",
        "pipeline": {
            "schematic": "VERIFIED",
            "placement": "BLOCKED_BY_SCHEMATIC",
            "routing": "BLOCKED_BY_PLACEMENT",
        },
        "active_phase": "SCHEMATIC",
        "active_commit": "abc123",
        "latest_run": "run-1",
        "latest_receipt": "receipt-1",
        "active_blockers": [{"id": "HCPL-0600", "status": "BLOCKED"}],
        "next_legal_actions": ["inspect_receipt", "patch"],
        "forbidden_actions": ["placement", "routing", "claim_pass"],
    }

    class Executor:
        def observe(self, state):
            return {}

        def decide(self, observation, state):
            return {}

        def act(self, decision, state):
            return {}

        def verify(self, result, state):
            return {"status": "PASS"}

    policy = LoopPolicy(
        max_steps=1,
        terminal_evaluator=lambda v, s: "PASS",
        action_authorizer=lambda d, s: None,
        continue_contract_builder=build_continue_contract,
    )
    store = MemoryStateStore(base)
    result = run_durable_loop(Executor(), store, policy)
    assert "continue_contract" in result

    store.state["continue_contract"]["active_phase"] = "PLACEMENT"
    resumed = run_durable_loop(Executor(), store, policy)
    assert resumed["status"] == "BLOCKED"
    assert "continue contract" in resumed["block_reason"]


class FailingSaveStore(MemoryStateStore):
    def __init__(self, state=None, failures=1):
        super().__init__(state or {})
        self.failures = failures

    def save(self, state):
        if self.failures:
            self.failures -= 1
            raise OSError("store unavailable")
        super().save(state)


def test_persistence_failure_is_fail_closed_and_retries_governed_block():
    store = FailingSaveStore()
    result = run_durable_loop(
        FakeExecutor(), store,
        _policy(max_steps=1, terminal_evaluator=lambda v, s: None),
    )
    assert result["status"] == "BLOCKED"
    assert "durable persistence failed" in result["block_reason"]
    assert store.load()["status"] == "BLOCKED"


def test_double_persistence_failure_is_durability_unknown():
    store = FailingSaveStore(failures=2)
    with pytest.raises(RuntimeError, match="durable persistence is UNKNOWN"):
        run_durable_loop(
            FakeExecutor(), store,
            _policy(max_steps=1, terminal_evaluator=lambda v, s: None),
        )
    assert store.load() is None


def test_continue_contract_is_stable_when_persisted_repeatedly():
    state = {
        "project": "p", "design": "d", "active_phase": "VERIFY",
        "active_commit": "abc", "latest_run": "run-1", "latest_receipt": "receipt-1",
        "pipeline": {"VERIFY": "active"}, "active_blockers": [],
        "next_legal_actions": ["continue"], "forbidden_actions": ["reset"],
    }
    policy = _policy(continue_contract_builder=build_continue_contract)
    store = MemoryStateStore()
    _persist_state(state, store, policy)
    first = store.load()["continue_contract"]
    _persist_state(state, store, policy)
    second = store.load()["continue_contract"]
    assert first == second



def test_invalid_state_patch_cannot_partially_mutate_durable_state():
    class PartiallyInvalidPatchExecutor(FakeExecutor):
        def verify(self, action_result, state):
            return {
                "value": action_result,
                "state_patch": {
                    "verified_evidence_refs": ["forged-evidence"],
                    "": "invalid-key-after-valid-field",
                },
            }

    store = MemoryStateStore()
    result = run_durable_loop(
        PartiallyInvalidPatchExecutor(),
        store,
        _policy(max_steps=1, terminal_evaluator=lambda verification, state: None),
    )

    assert result["status"] == "BLOCKED"
    assert "state_patch keys must be non-empty strings" in result["block_reason"]
    assert "verified_evidence_refs" not in result
    assert "verified_evidence_refs" not in store.load()


def test_rejected_receipt_cannot_persist_verifier_state_patch():
    class MismatchedReceiptExecutor:
        def observe(self, state):
            return {"observed": True}

        def decide(self, observation, state):
            return {"operation": "test"}

        def act(self, decision, state):
            return {"acted": True}

        def verify(self, action_result, state):
            return {
                "status": "OBSERVED",
                "receipt": {
                    "effect_id": "forged-effect",
                    "attempt_id": "forged-attempt",
                    "status": "OBSERVED",
                    "evidence": {"claim": "not lineage-bound"},
                },
                "state_patch": {
                    "verified_evidence_refs": ["forged-evidence"],
                    "continuation": {"operation_id": "unauthorized-next-step"},
                },
            }

    store = MemoryStateStore()
    policy = LoopPolicy(
        max_steps=1,
        terminal_evaluator=lambda verification, state: None,
        action_authorizer=lambda decision, state: None,
        require_execution_receipt=True,
    )

    result = run_durable_loop(MismatchedReceiptExecutor(), store, policy)

    assert result["status"] == "BLOCKED"
    assert "lineage does not match" in result["block_reason"]
    assert "verified_evidence_refs" not in result
    assert "continuation" not in result
    assert store.load()["status"] == "BLOCKED"
    assert "verified_evidence_refs" not in store.load()
    assert "continuation" not in store.load()


def test_unknown_receipt_cannot_persist_verifier_state_patch():
    class UnknownReceiptWithPatchExecutor(ReceiptExecutor):
        def verify(self, action_result, state):
            result = super().verify(action_result, state)
            result["receipt"]["status"] = "UNKNOWN"
            result["state_patch"] = {
                "verified_evidence_refs": ["unobserved-effect"],
                "continuation": {"operation_id": "unauthorized-next-step"},
            }
            return result

    store = MemoryStateStore()
    result = run_durable_loop(
        UnknownReceiptWithPatchExecutor(),
        store,
        _policy(
            max_steps=1,
            require_execution_receipt=True,
            terminal_evaluator=lambda verification, state: None,
        ),
    )

    assert result["status"] == "BLOCKED"
    assert "UNKNOWN execution receipt" in result["block_reason"]
    assert "verified_evidence_refs" not in result
    assert "continuation" not in result
    assert store.load()["status"] == "BLOCKED"
    assert "verified_evidence_refs" not in store.load()
    assert "continuation" not in store.load()
