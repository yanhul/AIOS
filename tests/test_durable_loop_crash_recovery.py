"""Process-death proof for durable loop state, CONTINUE_CONTRACT, and state_patch recovery."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from core.continue_contract import build_continue_contract
from core.durable_loop import LoopPolicy, run_durable_loop
from core.wal_state_store import WalStateStore


def _initial_state():
    return {
        "step": 0,
        "status": "RUNNING",
        "history": [],
        "authority": "AIOS_CONTROL_PLANE",
        "project": "state-continuity-e2e",
        "design": "crash-after-state-wal-commit",
        "pipeline": {"schematic": "PASS", "placement": "PENDING", "routing": "BLOCKED"},
        "active_phase": "placement",
        "active_commit": "commit-before-crash",
        "latest_run": "run-before-crash",
        "latest_receipt": "receipt-before-crash",
        "active_blockers": ["placement-not-verified"],
        "next_legal_actions": ["resume-placement"],
        "forbidden_actions": ["start-routing"],
    }


def _policy():
    return LoopPolicy(
        max_steps=2,
        terminal_evaluator=lambda verification, state: "PASS" if state["step"] >= 2 else None,
        action_authorizer=lambda decision, state: None,
        policy_digest="state-continuity-policy-v1",
        continue_contract_builder=build_continue_contract,
    )


class _Executor:
    def __init__(self, marker: Path):
        self.marker = marker

    def observe(self, state):
        return {"step": state["step"], "latest_receipt": state["latest_receipt"]}

    def decide(self, observation, state):
        return {"operation": "resume-placement", "step": observation["step"]}

    def act(self, decision, state):
        # This marker models a non-idempotent action boundary. Step zero must
        # not be invoked again after recovery of its committed state snapshot.
        with self.marker.open("a", encoding="utf-8") as fh:
            fh.write(f"action-step-{state['step']}\\n")
            fh.flush()
            os.fsync(fh.fileno())
        return {"attempt_id": f"A{state['step'] + 1}", "effect_id": "E-placement"}

    def verify(self, action_result, state):
        next_step = state["step"] + 1
        return {
            "status": "OBSERVED",
            "value": next_step,
            "receipt": {
                "effect_id": action_result["effect_id"],
                "attempt_id": action_result["attempt_id"],
                "status": "OBSERVED",
                "evidence": {"receipt": f"receipt-{next_step}"},
            },
            "state_patch": {
                "latest_attempt_dir": f"attempt-{next_step}",
                "blocked_requirements": ["routing-must-wait-for-placement"],
                "verified_evidence_refs": [f"EV-placement-{next_step}"],
                "discovery": {"last_seen_commit": f"commit-{next_step}"},
                "continuation": {"operation_id": "resume-placement", "cursor": next_step},
                "latest_run": f"run-{next_step}",
                "latest_receipt": f"receipt-{next_step}",
                "active_commit": f"commit-{next_step}",
                "active_blockers": ["routing-waits-for-placement"],
                "next_legal_actions": ["resume-placement"],
                "forbidden_actions": ["start-routing"],
            },
        }


def _child(state_path: str, wal_path: str, marker_path: str) -> None:
    class CrashAfterWalCommitStore(WalStateStore):
        def _write_snapshot(self, state):
            # WalStateStore.save() has already fsynced STATE_COMMITTED here.
            # Die before replacing the snapshot so recovery must use WAL replay.
            if state.get("step") == 1 and state.get("status") == "RUNNING":
                os._exit(42)
            super()._write_snapshot(state)

    store = CrashAfterWalCommitStore(state_path, wal_path)
    store.save(_initial_state())
    run_durable_loop(_Executor(Path(marker_path)), store, _policy())
    raise AssertionError("crash boundary was not reached")


def test_process_death_recovers_state_patch_and_continue_contract_from_wal(tmp_path):
    state_path = tmp_path / "state.json"
    wal_path = tmp_path / "state.wal.jsonl"
    marker_path = tmp_path / "actions.log"

    proc = subprocess.run(
        [sys.executable, __file__, "--child", str(state_path), str(wal_path), str(marker_path)],
        cwd=os.getcwd(),
        text=True,
        capture_output=True,
    )
    assert proc.returncode == 42, (proc.returncode, proc.stdout, proc.stderr)
    # The snapshot is deliberately stale: only the fsynced WAL contains step 1.
    snapshot = json.loads(state_path.read_text(encoding="utf-8"))
    assert snapshot["step"] == 0

    recovered_store = WalStateStore(str(state_path), str(wal_path))
    recovered = recovered_store.load()
    assert recovered["step"] == 1
    assert recovered["status"] == "RUNNING"
    assert recovered["latest_attempt_dir"] == "attempt-1"
    assert recovered["blocked_requirements"] == ["routing-must-wait-for-placement"]
    assert recovered["verified_evidence_refs"] == ["EV-placement-1"]
    assert recovered["discovery"] == {"last_seen_commit": "commit-1"}
    assert recovered["continuation"] == {"operation_id": "resume-placement", "cursor": 1}
    assert recovered["latest_receipt"] == "receipt-1"
    assert recovered["continue_contract"] == build_continue_contract(
        {key: value for key, value in recovered.items() if key != "continue_contract"}
    )

    result = run_durable_loop(_Executor(marker_path), recovered_store, _policy())
    assert result["status"] == "PASS"
    assert result["step"] == 2
    assert result["latest_attempt_dir"] == "attempt-2"
    assert result["latest_receipt"] == "receipt-2"
    assert result["continue_contract"] == build_continue_contract(
        {key: value for key, value in result.items() if key != "continue_contract"}
    )
    assert marker_path.read_text(encoding="utf-8").splitlines() == [
        "action-step-0",
        "action-step-1",
    ]


if __name__ == "__main__" and len(sys.argv) == 5 and sys.argv[1] == "--child":
    _child(sys.argv[2], sys.argv[3], sys.argv[4])
