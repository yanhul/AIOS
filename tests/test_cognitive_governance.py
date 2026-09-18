import pytest
from core.cognitive import CognitiveProposal, validate_cognitive_output
from core.durable_loop import LoopPolicy, MemoryStateStore, run_durable_loop

class Executor:
    def __init__(self, decision):
        self.decision = decision
        self.acted = False
    def observe(self, state): return {"risk": "high"}
    def decide(self, observation, state): return self.decision
    def act(self, decision, state):
        self.acted = True
        return {"ok": True}
    def verify(self, action_result, state): return {"status": "CONTINUE"}

def _policy():
    return LoopPolicy(max_steps=1, terminal_evaluator=lambda v, s: None,
        action_authorizer=lambda d, s: None,
        terminal_states=frozenset({"PASS", "BLOCKED", "INCONCLUSIVE"}))

def test_cognitive_proposal_cannot_smuggle_authority():
    with pytest.raises(PermissionError):
        CognitiveProposal(content={"logical_operation_id": "x", "authority_granted": True}, source="planner")

def test_runtime_gate_rejects_authority_bearing_decision_before_authorizer_and_act():
    executor = Executor({"logical_operation_id": "x", "permit_id": "forged"})
    result = run_durable_loop(executor, MemoryStateStore(), _policy())
    assert result["status"] == "BLOCKED"
    assert "authority fields" in result["block_reason"]
    assert executor.acted is False

def test_desire_and_risk_are_valid_cognitive_content():
    proposal = CognitiveProposal(
        content={"desire": "preserve continuity", "risk": "provider may be unavailable",
                 "logical_operation_id": "x"},
        source="risk-planner", kind="risk")
    assert proposal.status == "PROPOSAL"
    assert validate_cognitive_output(proposal) is proposal
