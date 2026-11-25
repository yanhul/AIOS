import pytest

from core.acceptance import AcceptancePredicate
from core.durable_loop import LoopPolicy, MemoryStateStore
from core.orchestrator import GovernedRuntimeExecutor, run_governed_execution


class FakeAdapter:
    name = "fake"


GOVERNING_CONTRACT = {
    "policy_digest": "policy-1",
    "max_attempts": 1,
    "terminal_states": ["PASS", "BLOCKED", "INCONCLUSIVE"],
}


def _patch_authority(monkeypatch, calls, *, governing_policy=None):
    monkeypatch.setattr("core.orchestrator.authorize", lambda *args: calls.append("authorize"))
    monkeypatch.setattr("core.orchestrator.load_contract", lambda *args: dict(GOVERNING_CONTRACT))
    artifact = governing_policy or {
        "policy_type": "GOVERNING_POLICY", "policy_digest": "policy-1",
        "require_execution_receipt": False, "acceptance_predicates": [],
    }
    monkeypatch.setattr("core.orchestrator.resolve_policy", lambda *args: dict(artifact))


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


def _executor():
    return GovernedRuntimeExecutor(
        aios_dir="/tmp/aios", contract_id="c1", permit_id="p1", actor="agent",
        adapter=FakeAdapter(), observer=lambda state: {"ready": True},
        decider=lambda observation, state: {"logical_operation_id": "op-1"},
        verifier=lambda result, state: {"verified": True},
    )


def test_governed_execution_resolves_authority_before_loop(monkeypatch):
    calls = []
    _patch_authority(monkeypatch, calls)
    monkeypatch.setattr(
        "core.orchestrator.execute",
        lambda *args: calls.append(("execute", args[3])) or {"ok": True},
    )

    result = run_governed_execution(executor=_executor(), store=MemoryStateStore(), policy=make_policy())
    assert result["status"] == "PASS"
    assert calls == ["authorize", "authorize", ("execute", "op-1")]


def test_policy_digest_mismatch_fails_closed(monkeypatch):
    calls = []
    _patch_authority(monkeypatch, calls)
    with pytest.raises(PermissionError, match="policy digest"):
        run_governed_execution(
            executor=_executor(), store=MemoryStateStore(),
            policy=make_policy(policy_digest="attacker-policy"),
        )


def test_budget_cannot_exceed_contract(monkeypatch):
    calls = []
    _patch_authority(monkeypatch, calls)
    with pytest.raises(PermissionError, match="execution budget"):
        run_governed_execution(
            executor=_executor(), store=MemoryStateStore(), policy=make_policy(max_steps=2),
        )


def test_runtime_action_requires_explicit_operation_id():
    executor = _executor()
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
    result = run_governed_execution(executor=_executor(), store=store, policy=make_policy())
    assert result["status"] == "PASS"
    assert calls == ["authorize", "authorize"]


def test_resume_binding_mismatch_fails_closed(monkeypatch):
    calls = []
    _patch_authority(monkeypatch, calls)
    store = MemoryStateStore({
        "contract_id": "attacker-contract", "permit_id": "p1", "step": 0,
        "status": "RUNNING", "history": [],
    })
    result = run_governed_execution(executor=_executor(), store=store, policy=make_policy())
    assert result["status"] == "BLOCKED"
    assert "binding" in result["block_reason"]


def test_terminal_states_must_match_governing_contract(monkeypatch):
    calls = []
    _patch_authority(monkeypatch, calls)
    with pytest.raises(PermissionError, match="terminal states"):
        run_governed_execution(
            executor=_executor(), store=MemoryStateStore(),
            policy=make_policy(terminal_states=frozenset({"PROMOTE", "REJECT", "INCONCLUSIVE", "BLOCKED"})),
        )


def test_custom_terminal_states_are_preserved_and_enforced(monkeypatch):
    calls = []
    contract = dict(GOVERNING_CONTRACT)
    contract["terminal_states"] = ["PROMOTE", "REJECT", "INCONCLUSIVE", "BLOCKED"]
    monkeypatch.setattr("core.orchestrator.authorize", lambda *args: calls.append("authorize"))
    monkeypatch.setattr("core.orchestrator.load_contract", lambda *args: dict(contract))
    monkeypatch.setattr("core.orchestrator.resolve_policy", lambda *args: {
        "policy_type": "GOVERNING_POLICY", "policy_digest": "policy-1",
        "require_execution_receipt": False, "acceptance_predicates": [],
    })
    monkeypatch.setattr("core.orchestrator.execute", lambda *args: {"ok": True})
    policy = make_policy(
        terminal_states=frozenset(contract["terminal_states"]),
        terminal_evaluator=lambda verification, state: "PROMOTE",
    )
    result = run_governed_execution(executor=_executor(), store=MemoryStateStore(), policy=policy)
    assert result["status"] == "PROMOTE"


def test_governed_bridge_preserves_receipt_and_continuation_controls(monkeypatch):
    contract = dict(GOVERNING_CONTRACT)
    contract["acceptance_predicates"] = [{
        "predicate_id": "verified-result",
        "path": "verification.verified",
        "operator": "eq",
        "expected": True,
    }]
    monkeypatch.setattr("core.orchestrator.authorize", lambda *args: None)
    monkeypatch.setattr("core.orchestrator.load_contract", lambda *args: dict(contract))
    monkeypatch.setattr("core.orchestrator.resolve_policy", lambda *args: {
        "policy_type": "GOVERNING_POLICY", "policy_digest": "policy-1",
        "require_execution_receipt": True,
        "acceptance_predicates": list(contract["acceptance_predicates"]),
    })
    receipt_validator = lambda receipt, state: None
    patch_validator = lambda patch, receipt, state: None
    blocked_continuation = lambda verification, state: None
    continue_builder = lambda state: {"contract_id": "next"}
    captured = {}
    monkeypatch.setattr(
        "core.orchestrator.run_durable_loop",
        lambda executor, store, policy: captured.setdefault("policy", policy) or {"status": "BLOCKED"},
    )
    policy = make_policy(
        require_execution_receipt=True,
        execution_receipt_validator=receipt_validator,
        state_patch_validator=patch_validator,
        blocked_continuation=blocked_continuation,
        continue_contract_builder=continue_builder,
    )

    run_governed_execution(executor=_executor(), store=MemoryStateStore(), policy=policy)
    bound = captured["policy"]
    assert bound.require_execution_receipt is True
    assert bound.execution_receipt_validator is receipt_validator
    assert bound.state_patch_validator is patch_validator
    assert bound.blocked_continuation is blocked_continuation
    assert bound.continue_contract_builder is continue_builder
    assert bound.acceptance_predicates == (
        AcceptancePredicate.from_mapping(contract["acceptance_predicates"][0]),
    )


def test_caller_cannot_replace_contract_acceptance_predicates(monkeypatch):
    contract = dict(GOVERNING_CONTRACT)
    contract["acceptance_predicates"] = [{
        "predicate_id": "must-be-true", "path": "verified", "operator": "eq", "expected": True,
    }]
    monkeypatch.setattr("core.orchestrator.authorize", lambda *args: None)
    monkeypatch.setattr("core.orchestrator.load_contract", lambda *args: dict(contract))
    monkeypatch.setattr("core.orchestrator.resolve_policy", lambda *args: {
        "policy_type": "GOVERNING_POLICY", "policy_digest": "policy-1",
        "require_execution_receipt": False,
        "acceptance_predicates": list(contract["acceptance_predicates"]),
    })
    conflicting = AcceptancePredicate(
        predicate_id="attacker-rule", path="verified", operator="eq", expected=False,
    )
    with pytest.raises(PermissionError, match="acceptance predicates do not match governing policy"):
        run_governed_execution(
            executor=_executor(), store=MemoryStateStore(),
            policy=make_policy(acceptance_predicates=(conflicting,)),
        )


def test_governing_policy_forces_receipt_even_if_caller_disables_it(monkeypatch):
    calls = []
    artifact = {
        "policy_type": "GOVERNING_POLICY", "policy_digest": "policy-1",
        "require_execution_receipt": True, "acceptance_predicates": [],
    }
    _patch_authority(monkeypatch, calls, governing_policy=artifact)
    receipt_validator = lambda receipt, state: None
    patch_validator = lambda patch, receipt, state: None
    captured = {}
    monkeypatch.setattr(
        "core.orchestrator.run_durable_loop",
        lambda executor, store, policy: captured.setdefault("policy", policy),
    )
    caller_policy = make_policy(
        require_execution_receipt=False,
        execution_receipt_validator=receipt_validator,
        state_patch_validator=patch_validator,
    )
    run_governed_execution(executor=_executor(), store=MemoryStateStore(), policy=caller_policy)
    assert captured["policy"].require_execution_receipt is True


def test_governing_policy_receipt_requirement_without_validators_blocks_before_loop(monkeypatch):
    calls = []
    artifact = {
        "policy_type": "GOVERNING_POLICY", "policy_digest": "policy-1",
        "require_execution_receipt": True, "acceptance_predicates": [],
    }
    _patch_authority(monkeypatch, calls, governing_policy=artifact)
    loop_called = []
    monkeypatch.setattr("core.orchestrator.run_durable_loop", lambda *args: loop_called.append(True))
    with pytest.raises(ValueError, match="requires an execution_receipt_validator"):
        run_governed_execution(
            executor=_executor(), store=MemoryStateStore(), policy=make_policy(),
        )
    assert loop_called == []


def test_contract_cannot_add_acceptance_predicates_absent_from_governing_policy(monkeypatch):
    calls = []
    contract = dict(GOVERNING_CONTRACT)
    contract["acceptance_predicates"] = [{
        "predicate_id": "must-be-true", "path": "verified", "operator": "eq", "expected": True,
    }]
    _patch_authority(monkeypatch, calls)
    monkeypatch.setattr("core.orchestrator.load_contract", lambda *args: dict(contract))
    loop_called = []
    monkeypatch.setattr("core.orchestrator.run_durable_loop", lambda *args: loop_called.append(True))
    with pytest.raises(PermissionError, match="do not match governing policy artifact"):
        run_governed_execution(
            executor=_executor(), store=MemoryStateStore(), policy=make_policy(),
        )
    assert loop_called == []
