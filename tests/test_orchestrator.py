import pytest

from core.durable_loop import LoopPolicy, MemoryStateStore
from core.orchestrator import GovernedRuntimeExecutor, run_governed_execution


class FakeAdapter:
    name = "fake"


GOVERNING_CONTRACT = {
    "policy_digest": "policy-1",
    "max_attempts": 1,
    "terminal_states": ["PASS", "BLOCKED", "INCONCLUSIVE"],
}


def _patch_authority(monkeypatch, calls):
    monkeypatch.setattr("core.orchestrator.authorize", lambda *args: calls.append("authorize"))
    monkeypatch.setattr("core.orchestrator.load_contract", lambda *args: dict(GOVERNING_CONTRACT))


def make_policy(**overrides):
    values = {
        "max_steps": 1,
        "terminal_evaluator": lambda verification, state: "PASS" if verification["verified"] else None,
        "action_authorizer": lambda decision, state: None,
        "policy_digest": "policy-1",
        "terminal_states": frozenset(GOVERNING_CONTRACT["terminal_states"]),
    }
    values.update(overrides)
    return LoopPolicy(**values)


def test_governed_execution_resolves_authority_before_loop(monkeypatch):
    calls = []
    _patch_authority(monkeypatch, calls)
    monkeypatch.setattr(
        "core.orchestrator.execute",
        lambda *args: calls.append(("execute", args[3])) or {"ok": True},
    )

    executor = GovernedRuntimeExecutor(
        aios_dir="/tmp/aios",
        contract_id="c1",
        permit_id="p1",
        actor="agent",
        adapter=FakeAdapter(),
        observer=lambda state: {"ready": True},
        decider=lambda observation, state: {"logical_operation_id": "op-1"},
        verifier=lambda result, state: {"verified": result["ok"]},
    )

    result = run_governed_execution(executor=executor, store=MemoryStateStore(), policy=make_policy())
    assert result["status"] == "PASS"
    assert calls == ["authorize", "authorize", ("execute", "op-1")]


def test_policy_digest_mismatch_fails_closed(monkeypatch):
    calls = []
    _patch_authority(monkeypatch, calls)
    executor = GovernedRuntimeExecutor(
        aios_dir="/tmp/aios", contract_id="c1", permit_id="p1", actor="agent",
        adapter=FakeAdapter(), observer=lambda state: None,
        decider=lambda observation, state: {"logical_operation_id": "op"},
        verifier=lambda result, state: result,
    )
    with pytest.raises(PermissionError, match="policy digest"):
        run_governed_execution(
            executor=executor,
            store=MemoryStateStore(),
            policy=make_policy(policy_digest="attacker-policy"),
        )


def test_budget_cannot_exceed_contract(monkeypatch):
    calls = []
    _patch_authority(monkeypatch, calls)
    executor = GovernedRuntimeExecutor(
        aios_dir="/tmp/aios", contract_id="c1", permit_id="p1", actor="agent",
        adapter=FakeAdapter(), observer=lambda state: None,
        decider=lambda observation, state: {"logical_operation_id": "op"},
        verifier=lambda result, state: result,
    )
    with pytest.raises(PermissionError, match="execution budget"):
        run_governed_execution(
            executor=executor,
            store=MemoryStateStore(),
            policy=make_policy(max_steps=2),
        )


def test_runtime_action_requires_explicit_operation_id():
    executor = GovernedRuntimeExecutor(
        aios_dir="/tmp/aios", contract_id="c1", permit_id="p1", actor="agent",
        adapter=FakeAdapter(), observer=lambda state: None,
        decider=lambda observation, state: {}, verifier=lambda result, state: result,
    )
    with pytest.raises(ValueError, match="logical_operation_id"):
        executor.act({}, {})


def test_resume_reauthorizes_current_contract_and_permit(monkeypatch):
    calls = []
    _patch_authority(monkeypatch, calls)
    monkeypatch.setattr("core.orchestrator.execute", lambda *args: {"ok": True})

    store = MemoryStateStore({
        "contract_id": "c1", "permit_id": "p1", "step": 0,
        "status": "RUNNING", "history": [], "policy_digest": "policy-1",
    })
    executor = GovernedRuntimeExecutor(
        aios_dir="/tmp/aios", contract_id="c1", permit_id="p1", actor="agent",
        adapter=FakeAdapter(), observer=lambda state: None,
        decider=lambda observation, state: {"logical_operation_id": "op-resume"},
        verifier=lambda result, state: {"verified": True},
    )

    result = run_governed_execution(executor=executor, store=store, policy=make_policy())
    assert result["status"] == "PASS"
    assert calls == ["authorize", "authorize"]


def test_resume_binding_mismatch_fails_closed(monkeypatch):
    calls = []
    _patch_authority(monkeypatch, calls)
    store = MemoryStateStore({
        "contract_id": "attacker-contract", "permit_id": "p1", "step": 0,
        "status": "RUNNING", "history": [],
    })
    executor = GovernedRuntimeExecutor(
        aios_dir="/tmp/aios", contract_id="c1", permit_id="p1", actor="agent",
        adapter=FakeAdapter(), observer=lambda state: None,
        decider=lambda observation, state: {"logical_operation_id": "op"},
        verifier=lambda result, state: result,
    )

    result = run_governed_execution(executor=executor, store=store, policy=make_policy())
    assert result["status"] == "BLOCKED"
    assert "binding" in result["block_reason"]


def test_terminal_states_must_match_governing_contract(monkeypatch):
    calls = []
    _patch_authority(monkeypatch, calls)
    executor = GovernedRuntimeExecutor(
        aios_dir="/tmp/aios", contract_id="c1", permit_id="p1", actor="agent",
        adapter=FakeAdapter(), observer=lambda state: None,
        decider=lambda observation, state: {"logical_operation_id": "op"},
        verifier=lambda result, state: result,
    )
    with pytest.raises(PermissionError, match="terminal states"):
        run_governed_execution(
            executor=executor,
            store=MemoryStateStore(),
            policy=make_policy(terminal_states=frozenset({"PROMOTE", "REJECT", "INCONCLUSIVE", "BLOCKED"})),
        )


def test_custom_terminal_states_are_preserved_and_enforced(monkeypatch):
    calls = []
    contract = dict(GOVERNING_CONTRACT)
    contract["terminal_states"] = ["PROMOTE", "REJECT", "INCONCLUSIVE", "BLOCKED"]
    monkeypatch.setattr("core.orchestrator.authorize", lambda *args: calls.append("authorize"))
    monkeypatch.setattr("core.orchestrator.load_contract", lambda *args: dict(contract))
    monkeypatch.setattr("core.orchestrator.execute", lambda *args: {"ok": True})
    executor = GovernedRuntimeExecutor(
        aios_dir="/tmp/aios", contract_id="c1", permit_id="p1", actor="agent",
        adapter=FakeAdapter(), observer=lambda state: None,
        decider=lambda observation, state: {"logical_operation_id": "op-promote"},
        verifier=lambda result, state: {"verified": True},
    )
    policy = make_policy(
        terminal_states=frozenset(contract["terminal_states"]),
        terminal_evaluator=lambda verification, state: "PROMOTE",
    )
    result = run_governed_execution(executor=executor, store=MemoryStateStore(), policy=policy)
    assert result["status"] == "PROMOTE"


def test_governed_binding_preserves_every_loop_policy_guard(monkeypatch):
    from core.acceptance import AcceptancePredicate
    from core.fix_protocol import FixPlan

    calls = []
    _patch_authority(monkeypatch, calls)
    custom_resume = lambda state: calls.append(("custom_resume", state["contract_id"]))
    receipt_validator = lambda receipt, state: None
    state_patch_validator = lambda before, patch, after: None
    blocked_continuation = lambda result, state: None
    continue_contract_builder = lambda state: {"contract_id": state["contract_id"]}
    predicate = AcceptancePredicate("accept-1", "result.ok", "eq", True)
    fix_plan = FixPlan(
        violated_invariant="invariant", lifecycle="lifecycle",
        broken_boundary="boundary", root_cause="cause",
        proposed_fix="fix", regression_proof="regression",
        runtime_proof="runtime", terminal_condition="PASS",
    )
    policy = make_policy(
        resume_validator=custom_resume,
        require_execution_receipt=True,
        execution_receipt_validator=receipt_validator,
        fix_plan=fix_plan,
        fix_success_state="PASS",
        blocked_continuation=blocked_continuation,
        acceptance_predicates=(predicate,),
        continue_contract_builder=continue_contract_builder,
        state_patch_validator=state_patch_validator,
    )
    captured = {}

    def capture_loop(executor, store, bound_policy):
        captured["policy"] = bound_policy
        bound_policy.resume_validator({
            "contract_id": "c1", "permit_id": "p1",
        })
        return {"status": "CAPTURED"}

    monkeypatch.setattr("core.orchestrator.run_durable_loop", capture_loop)
    executor = GovernedRuntimeExecutor(
        aios_dir="/tmp/aios", contract_id="c1", permit_id="p1", actor="agent",
        adapter=FakeAdapter(), observer=lambda state: None,
        decider=lambda observation, state: {"logical_operation_id": "op"},
        verifier=lambda result, state: result,
    )
    result = run_governed_execution(
        executor=executor, store=MemoryStateStore(), policy=policy,
    )
    bound = captured["policy"]

    assert result["status"] == "CAPTURED"
    assert bound.max_steps == policy.max_steps
    assert bound.terminal_evaluator is policy.terminal_evaluator
    assert bound.action_authorizer is policy.action_authorizer
    assert bound.policy_digest == policy.policy_digest
    assert bound.terminal_states == policy.terminal_states
    assert bound.budget_exhaustion_state == policy.budget_exhaustion_state
    assert bound.failure_state == policy.failure_state
    assert bound.require_execution_receipt is True
    assert bound.execution_receipt_validator is receipt_validator
    assert bound.fix_plan is fix_plan
    assert bound.fix_success_state == "PASS"
    assert bound.blocked_continuation is blocked_continuation
    assert bound.acceptance_predicates is policy.acceptance_predicates
    assert bound.continue_contract_builder is continue_contract_builder
    assert bound.state_patch_validator is state_patch_validator
    assert ("custom_resume", "c1") in calls
