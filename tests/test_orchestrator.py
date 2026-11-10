# AIOS-CONTRACT: run_governed_execution binds the durable loop to the governing contract/permit/policy
# AIOS-REGRESSION: Authority resolution order, digest/budget/terminal-state binding and resume re-authorization.
#                  These unit tests stub authority; the effect-authority gate is stubbed to OBSERVED_SUCCESS here
#                  and exercised for real in tests/test_p1_governed_bridge_effect_authority_126.py.
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: No real contract/effect state; see the effect-authority bridge suite.
# AIOS-BASELINE: 826fca0 (629 passed, 1 skipped)
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
    _stub_observed_effect(monkeypatch)


def _fake_effect(*args):
    # execute(aios_dir, contract_id, permit_id, logical_operation_id, actor, adapter)
    from core.effect_authority import _id
    return {"ok": True, "effect_id": _id(args[1], args[3], args[4])}


def _stub_observed_effect(monkeypatch):
    # Unit tests here have no persisted effect state; the real gate is covered elsewhere.
    monkeypatch.setattr("core.orchestrator._authoritative_effect_outcome", lambda *args: "OBSERVED_SUCCESS")


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
        lambda *args: calls.append(("execute", args[3])) or _fake_effect(*args),
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
    monkeypatch.setattr("core.orchestrator.execute", _fake_effect)

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
    _stub_observed_effect(monkeypatch)
    monkeypatch.setattr("core.orchestrator.execute", _fake_effect)
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
