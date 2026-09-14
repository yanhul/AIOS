from core.fix_protocol import FixPlan, FixProof, FixProtocolError, require_fix_plan, require_fix_proof
from core.durable_loop import LoopPolicy, MemoryStateStore, run_durable_loop


def plan():
    return FixPlan(
        violated_invariant="candidate failure must not terminate campaign",
        lifecycle="OOS_FAIL -> next candidate -> execute -> verify",
        broken_boundary="OOS_FAIL -> next candidate",
        root_cause="terminal state was promoted at candidate scope",
        proposed_fix="move terminalization behind externally governed campaign policy",
        regression_proof="historical OOS failure resumes at next candidate",
        runtime_proof="runtime crosses the next-candidate execution boundary",
        terminal_condition="verified edge or exhausted governed budget",
    )


def proof():
    return FixProof(
        boundary_before="OOS_FAIL",
        boundary_after="BC203_DECISION",
        runtime_transition_observed=True,
        evidence_refs=("run:9550", "BC202:failure_analysis", "BC203:receipt"),
        regression_passed=True,
    )


def test_fix_plan_is_fail_closed():
    require_fix_plan(plan())
    try:
        require_fix_plan(FixPlan("", "x", "x", "x", "x", "x", "x", "x"))
    except FixProtocolError:
        return
    raise AssertionError("incomplete fix plan was accepted")


def test_fix_proof_requires_runtime_boundary_and_regression():
    require_fix_proof(proof())
    bad = FixProof("A", "B", False, ("evidence",), True)
    try:
        require_fix_proof(bad)
    except FixProtocolError:
        return
    raise AssertionError("unobserved runtime transition was accepted")


class _FixExecutor:
    def observe(self, state):
        return "observed"

    def decide(self, observation, state):
        return "patch"

    def act(self, decision, state):
        return "changed"

    def verify(self, action_result, state):
        return {"status": "FIXED", "fix_proof": proof()}


def test_durable_harness_requires_runtime_fix_proof_for_pass():
    policy = LoopPolicy(
        max_steps=1,
        terminal_evaluator=lambda verification, state: "PASS",
        action_authorizer=lambda decision, state: None,
        fix_plan=plan(),
    )
    result = run_durable_loop(_FixExecutor(), MemoryStateStore(), policy)
    assert result["status"] == "PASS"


def test_durable_harness_blocks_self_attested_pass_without_proof():
    class SelfAttested(_FixExecutor):
        def verify(self, action_result, state):
            return {"status": "FIXED"}

    policy = LoopPolicy(
        max_steps=1,
        terminal_evaluator=lambda verification, state: "PASS",
        action_authorizer=lambda decision, state: None,
        fix_plan=plan(),
    )
    result = run_durable_loop(SelfAttested(), MemoryStateStore(), policy)
    assert result["status"] == "BLOCKED"
    assert "FixProof" in result["block_reason"]
