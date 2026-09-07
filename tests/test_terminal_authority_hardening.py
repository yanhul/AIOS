import pytest
from core.durable_loop import LoopPolicy, MemoryStateStore, run_durable_loop

class Executor:
    def observe(self, state): return {}
    def decide(self, observation, state): return {}
    def act(self, decision, state): raise RuntimeError("boom")
    def verify(self, result, state): return {}

def policy(**kwargs):
    return LoopPolicy(max_steps=1, terminal_evaluator=lambda v,s: None, action_authorizer=lambda d,s: None, **kwargs)

def test_failure_state_must_be_governed():
    with pytest.raises(ValueError, match="failure_state"):
        policy(terminal_states=frozenset({"REJECT", "INCONCLUSIVE"}))

def test_execution_failure_cannot_escape_terminal_policy():
    result=run_durable_loop(Executor(), MemoryStateStore(), policy(terminal_states=frozenset({"REJECT","INCONCLUSIVE"}), failure_state="REJECT"))
    assert result["status"] == "REJECT"

def test_budget_state_cannot_escape_terminal_policy():
    result=run_durable_loop(type("E",(),{"observe":lambda s,x:{},"decide":lambda s,o,x:{},"act":lambda s,d,x:1,"verify":lambda s,r,x:{}})(), MemoryStateStore(), policy(terminal_states=frozenset({"REJECT","INCONCLUSIVE"}), failure_state="REJECT", budget_exhaustion_state="REJECT"))
    assert result["status"] == "REJECT"
