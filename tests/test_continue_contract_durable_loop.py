# AIOS-CONTRACT: CONTINUE_CONTRACT schema and legal-action boundary
# AIOS-REGRESSION: Prevent model drift outside the durable active phase
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Covers deterministic contract projection and fail-closed validation
# AIOS-BASELINE: Tests target the existing durable-loop contract baseline

from core.continue_contract import build_continue_contract
from core.durable_loop import LoopPolicy, MemoryStateStore, run_durable_loop

def _state():
    return {
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
        "latest_run": "37169016057",
        "latest_receipt": "receipt-2605-schematic",
        "active_blockers": [{"id": "HCPL-0600", "status": "BLOCKED"}],
        "next_legal_actions": ["inspect_receipt", "inspect_source", "patch", "commit", "wait_ci"],
        "forbidden_actions": ["placement", "routing", "claim_pass"],
    }

def test_durable_loop_persists_model_facing_continue_contract():
    class Executor:
        def observe(self, state): return {"ok": True}
        def decide(self, observation, state): return {"operation": "patch"}
        def act(self, decision, state): return {"ok": True}
        def verify(self, result, state):
            return {"status": "PASS", "receipt": {
                "effect_id": "e1", "attempt_id": "a1", "status": "OBSERVED",
                "evidence": {"run": "r1"},
            }}

    state = _state()
    policy = LoopPolicy(
        max_steps=1,
        terminal_evaluator=lambda v, s: "PASS",
        action_authorizer=lambda d, s: None,
        continue_contract_builder=build_continue_contract,
    )
    store = MemoryStateStore(state)
    result = run_durable_loop(Executor(), store, policy)
    contract = result["continue_contract"]
    assert contract["active_phase"] == "SCHEMATIC"
    assert contract["forbidden_actions"] == ["placement", "routing", "claim_pass"]
    assert contract["state_digest"]
