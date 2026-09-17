import pytest

from core.durable_loop import LoopPolicy, MemoryStateStore
from core.orchestrator import GovernedRuntimeExecutor, run_governed_execution


class FakeAdapter:
    name = "fake"


GATEWAY_BINDING = {
    "target_sha": "sha256:test-worker-v1",
    "evidence_ref": "EV-test",
    "lineage_ref": "LIN-test",
    "idempotency_key": "idem-test",
    "attempt_fence": 1,
}

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


def _executor(**overrides):
    values = {
        "aios_dir": "/tmp/aios",
        "contract_id": "c1",
        "permit_id": "p1",
        "actor": "agent",
        "adapter": FakeAdapter(),
        "observer": lambda state: {"ready": True},
        "decider": lambda observation, state: {"logical_operation_id": "op-1"},
        "verifier": lambda result, state: {"verified": result["ok"]},
        "gateway_binding": dict(GATEWAY_BINDING),
    }
    values.update(overrides)
    return GovernedRuntimeExecutor(**values)


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
    executor = _executor()
    with pytest.raises(PermissionError, match="policy digest"):
        run_governed_execution(
            executor=executor,
            store=MemoryStateStore(),
            policy=make_policy(policy_digest="attacker-policy"),
        )


def test_budget_cannot_exceed_contract(monkeypatch):
    calls = []
    _patch_authority(monkeypatch, calls)
    executor = _executor()
    with pytest.raises(PermissionError, match="execution budget"):
        run_governed_execution(
            executor=executor,
            store=MemoryStateStore(),
            policy=make_policy(max_steps=2),
        )


def test_runtime_action_requires_explicit_operation_id():
    executor = _executor(decider=lambda observation, state: {})
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
    executor = _executor(decider=lambda observation, state: {"logical_operation_id": "op-resume"},
                         verifier=lambda result, state: {"verified": True})

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
    executor = _executor()

    result = run_governed_execution(executor=executor, store=store, policy=make_policy())
    assert result["status"] == "BLOCKED"
    assert "binding" in result["block_reason"]


def test_terminal_states_must_match_governing_contract(monkeypatch):
    calls = []
    _patch_authority(monkeypatch, calls)
    executor = _executor()
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
    executor = _executor()
    policy = make_policy(
        terminal_states=frozenset(contract["terminal_states"]),
        terminal_evaluator=lambda verification, state: "PROMOTE",
    )
    result = run_governed_execution(executor=executor, store=MemoryStateStore(), policy=policy)
    assert result["status"] == "PROMOTE"
