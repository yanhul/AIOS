# AIOS-CONTRACT: durable loop state patch persistence through WAL
# AIOS-REGRESSION: Prevent verified state patches from being lost across persistence
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Covers durable-loop integration with WAL-backed state
# AIOS-BASELINE: Tests target the existing durable-loop contract baseline

from core.durable_loop import LoopPolicy, run_durable_loop
from core.wal_state_store import WalStateStore

class Executor:
    def observe(self, state):
        return {"n": state["step"]}
    def decide(self, observation, state):
        return {"next": observation["n"] + 1}
    def act(self, decision, state):
        return decision["next"]
    def verify(self, result, state):
        return {"value": result, "state_patch": {"latest_attempt_dir": "attempt-1"}}

def test_durable_loop_persists_state_patch_through_wal(tmp_path):
    store = WalStateStore(str(tmp_path / "state.json"), str(tmp_path / "state.wal.jsonl"))
    policy = LoopPolicy(
        max_steps=1,
        terminal_evaluator=lambda verification, state: None,
        action_authorizer=lambda decision, state: None,
    )
    result = run_durable_loop(Executor(), store, policy)
    assert result["status"] == "INCONCLUSIVE"
    assert store.load()["latest_attempt_dir"] == "attempt-1"
