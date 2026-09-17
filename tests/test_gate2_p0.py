from core.durable_loop import LoopPolicy, MemoryStateStore, run_durable_loop
from core.fix_protocol import FixPlan, FixProof


class FixExecutor:
    def observe(self, state):
        return {"step": state["step"]}

    def decide(self, observation, state):
        return {"action": "repair"}

    def act(self, decision, state):
        return "patched"

    def verify(self, action_result, state):
        return {
            "status": "FIXED",
            "fix_proof": FixProof(
                boundary_before="broken",
                boundary_after="repaired",
                runtime_transition_observed=True,
                evidence_refs=("EV-test",),
                regression_passed=True,
            ),
        }


def _plan():
    return FixPlan(
        violated_invariant="terminal authority",
        lifecycle="fix",
        broken_boundary="terminal evaluation",
        root_cause="hard-coded terminal state",
        proposed_fix="govern fix promotion independently of workload terminals",
        regression_proof="pytest",
        runtime_proof="observed transition",
        terminal_condition="PASS with FixProof",
    )


def test_governed_fix_can_use_pass_outside_custom_workload_terminals():
    policy = LoopPolicy(
        max_steps=1,
        terminal_states=frozenset({"PROMOTE", "REJECT", "INCONCLUSIVE", "BLOCKED"}),
        terminal_evaluator=lambda verification, state: "PASS",
        action_authorizer=lambda decision, state: None,
        fix_plan=_plan(),
        fix_success_state="PASS",
    )
    result = run_durable_loop(FixExecutor(), MemoryStateStore(), policy)
    assert result["status"] == "PASS"
    assert result["terminal_evidence"]["status"] == "PASS"


def test_non_fix_custom_terminal_remains_strict():
    policy = LoopPolicy(
        max_steps=1,
        terminal_states=frozenset({"PROMOTE", "REJECT", "INCONCLUSIVE", "BLOCKED"}),
        terminal_evaluator=lambda verification, state: "PASS",
        action_authorizer=lambda decision, state: None,
    )
    result = run_durable_loop(FixExecutor(), MemoryStateStore(), policy)
    assert result["status"] == "BLOCKED"
    assert "invalid terminal status" in result["block_reason"]
