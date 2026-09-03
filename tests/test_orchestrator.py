from core.durable_loop import LoopPolicy, MemoryStateStore
from core.orchestrator import GovernedRuntimeExecutor, run_governed_execution


class FakeAdapter:
    name = "fake"


def test_governed_execution_resolves_authority_before_loop(monkeypatch):
    calls = []

    monkeypatch.setattr("core.orchestrator.authorize", lambda *args: calls.append("authorize"))
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
    policy = LoopPolicy(
        max_steps=1,
        terminal_evaluator=lambda verification, state: "PASS" if verification["verified"] else None,
        action_authorizer=lambda decision, state: None,
    )

    result = run_governed_execution(executor=executor, store=MemoryStateStore(), policy=policy)
    assert result["status"] == "PASS"
    assert calls == ["authorize", ("execute", "op-1")]


def test_runtime_action_requires_explicit_operation_id():
    executor = GovernedRuntimeExecutor(
        aios_dir="/tmp/aios",
        contract_id="c1",
        permit_id="p1",
        actor="agent",
        adapter=FakeAdapter(),
        observer=lambda state: None,
        decider=lambda observation, state: {},
        verifier=lambda result, state: result,
    )
    try:
        executor.act({}, {})
    except ValueError as exc:
        assert "logical_operation_id" in str(exc)
    else:
        raise AssertionError("missing operation id was accepted")
