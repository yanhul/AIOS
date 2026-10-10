# AIOS-CONTRACT: Blocked continuation requires verified evidence and receipt-bound execution intents.
# AIOS-REGRESSION: Prevent redispatch without verified evidence and prevent receipt/intent lineage mismatch.
# AIOS-OWNER: AIOS governed durable execution and PCB EDA continuation.
# AIOS-COVERAGE-GAP: Exercise authorized continuation after an observed receipt.
# AIOS-BASELINE: Validate the durable-loop blocked continuation contract.

from core.blocked_continuation import classify_blockers, plan_blocked_continuation
from core.durable_loop import LoopPolicy, MemoryStateStore, run_durable_loop

def test_pcb_blockers_are_classified_without_inventing_values():
    verification = {"blockers": [
        {"id": "board_edge_clearance", "status": "BLOCKED"},
        {"id": "assembly_access", "status": "BLOCKED"},
        {"id": "current_capacity", "status": "BLOCKED"},
        {"id": "G7-TOPOLOGY-17", "status": "FAIL"},
    ]}
    kinds = [x["kind"] for x in classify_blockers(verification)]
    assert kinds == ["board_edge_clearance", "assembly_access", "current_capacity", "topology"]

def test_non_blocking_routing_observations_do_not_create_topology_requirements():
    verification = {"findings": [
        {"id": "G6-ROUTING-CORRIDOR-J1", "status": "WARN", "severity": "MEDIUM"},
        {"id": "G7-TOPOLOGY", "status": "VERIFIED", "severity": "INFO"},
        {"id": "G7-TOPOLOGY-LIMIT", "status": "VERIFIED", "severity": "INFO"},
    ]}
    assert classify_blockers(verification) == []

def test_missing_evidence_does_not_authorize_redispatch():
    verification = {"blockers": [{"id": "current_capacity", "status": "BLOCKED"}]}
    plan = plan_blocked_continuation(verification, {"verified_evidence_refs": []})
    assert plan is not None
    assert plan["next_operation_id"] == "pcb.eda.discover_evidence"
    assert plan["authority"] == "AIOS_CONTROL_PLANE"
    assert all(x.startswith("DISCOVERY_REQUIRED:") for x in plan["evidence_refs"])

def test_durable_loop_can_redispatch_only_after_verified_evidence():
    calls = []
    class Executor:
        def observe(self, state): return {"phase": state.get("phase", "audit")}
        def decide(self, observation, state):
            return {"logical_operation_id": state.get("continuation", {}).get("next_operation_id", "pcb.eda@1")}
        def act(self, decision, state):
            calls.append(decision["logical_operation_id"])
            return {"ok": True}
        def verify(self, result, state):
            intent = state["in_flight_attempt"]
            if len(calls) == 1:
                return {"status": "BLOCKED", "blockers": [{"id": "topology"}], "receipt": {"effect_id":intent["effect_id"],"attempt_id":intent["attempt_id"],"status":"OBSERVED","evidence":{"findings":"f1"}}}
            return {"status": "FIXED", "receipt": {"effect_id":intent["effect_id"],"attempt_id":intent["attempt_id"],"status":"OBSERVED","evidence":{"findings":"f2"}}}

    def continuation(verification, state):
        assert verification["status"] == "BLOCKED"
        return {
            "authority": "AIOS_CONTROL_PLANE",
            "evidence_refs": ["evidence://verified/topology"],
            "next_operation_id": "pcb.eda@1",
            "reason": "verified topology evidence permits a new attempt",
        }

    policy = LoopPolicy(
        max_steps=2,
        terminal_evaluator=lambda v, s: "BLOCKED" if v["status"] == "BLOCKED" else "PASS",
        action_authorizer=lambda d, s: None,
        require_execution_receipt=True,
        execution_receipt_validator=lambda receipt, state: None,
        state_patch_validator=lambda patch, receipt, state: None,
        blocked_continuation=continuation,
    )
    result = run_durable_loop(
        Executor(),
        MemoryStateStore({"verified_evidence_refs": ["evidence://verified/topology"]}),
        policy,
    )
    assert result["status"] == "PASS"
    assert calls == ["pcb.eda@1", "pcb.eda@1"]
    assert result["history"][0]["continuation"]["evidence_refs"] == ["evidence://verified/topology"]
