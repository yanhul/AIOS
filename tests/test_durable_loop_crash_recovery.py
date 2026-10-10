"""Process-death proof for durable loop state, CONTINUE_CONTRACT, and state_patch recovery."""
# AIOS-CONTRACT: Durable state and continuation must survive process death at WAL commit.
# AIOS-REGRESSION: Prevent replay from stale snapshots, lost state_patch, or duplicate actions.
# AIOS-OWNER: AIOS durable control-plane state and continuation projection.
# AIOS-COVERAGE-GAP: Crash between fsynced WAL commit and snapshot replacement.
# AIOS-BASELINE: Validate end-to-end durable-loop resume contract.
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from core.continue_contract import build_continue_contract
from core.durable_loop import LoopPolicy, reconcile_in_flight_attempt, run_durable_loop
from core.wal_state_store import WalStateStore


def _initial_state():
    return {
        "step": 0,
        "status": "RUNNING",
        "history": [],
        "policy_digest": "state-continuity-policy-v1",
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
        require_execution_receipt=True,
        execution_receipt_validator=lambda receipt, state: None,
        state_patch_validator=lambda patch, receipt, state: None,
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
            fh.write(f"action-step-{state['step']}\n")
            fh.flush()
            os.fsync(fh.fileno())
        intent = state["in_flight_attempt"]
        return {"attempt_id": intent["attempt_id"], "effect_id": intent["effect_id"]}

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
        env={**os.environ, "PYTHONPATH": os.getcwd() + os.pathsep + os.environ.get("PYTHONPATH", "")},
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






def _crash_after_provider_effect(state_path: str, wal_path: str, marker_path: str) -> None:
    class CrashAfterEffectExecutor(_Executor):
        def act(self, decision, state):
            with self.marker.open("a", encoding="utf-8") as fh:
                fh.write("provider-effect-committed\n")
                fh.flush()
                os.fsync(fh.fileno())
            os._exit(43)

    store = WalStateStore(state_path, wal_path)
    store.save(_initial_state())
    run_durable_loop(CrashAfterEffectExecutor(Path(marker_path)), store, _policy())
    raise AssertionError("crash boundary was not reached")


def test_process_death_after_provider_effect_never_replays_without_reconciliation(tmp_path):
    state_path = tmp_path / "effect-crash-state.json"
    wal_path = tmp_path / "effect-crash-state.wal.jsonl"
    marker_path = tmp_path / "effect-actions.log"
    proc = subprocess.run(
        [sys.executable, __file__, "--crash-after-effect", str(state_path), str(wal_path), str(marker_path)],
        cwd=os.getcwd(),
        text=True,
        capture_output=True,
        env={**os.environ, "PYTHONPATH": os.getcwd() + os.pathsep + os.environ.get("PYTHONPATH", "")},
    )
    assert proc.returncode == 43, (proc.returncode, proc.stdout, proc.stderr)

    store = WalStateStore(str(state_path), str(wal_path))
    recovered = store.load()
    assert recovered["step"] == 0
    assert recovered["status"] == "RUNNING"
    intent = recovered["in_flight_attempt"]
    assert intent["status"] == "PREPARED"
    assert intent["effect_id"].startswith("effect-")
    assert intent["attempt_id"].startswith("attempt-")

    result = run_durable_loop(_Executor(marker_path), store, _policy())
    assert result["status"] == "BLOCKED"
    assert "unresolved in-flight execution attempt" in result["block_reason"]
    assert result["in_flight_attempt"] == intent
    assert marker_path.read_text(encoding="utf-8").splitlines() == ["provider-effect-committed"]



def test_resume_blocks_if_durable_state_no_longer_matches_persisted_contract(tmp_path):
    state_path = tmp_path / "tampered-state.json"
    wal_path = tmp_path / "tampered-state.wal.jsonl"
    marker_path = tmp_path / "actions.log"
    store = WalStateStore(str(state_path), str(wal_path))
    state = _initial_state()
    state["continue_contract"] = build_continue_contract(state)
    state["active_phase"] = "routing"
    store.save(state)

    result = run_durable_loop(_Executor(marker_path), store, _policy())

    assert result["status"] == "BLOCKED"
    assert "does not match durable state" in result["block_reason"]
    assert not marker_path.exists()


def test_resume_blocks_if_persisted_contract_is_tampered(tmp_path):
    state_path = tmp_path / "tampered-contract.json"
    wal_path = tmp_path / "tampered-contract.wal.jsonl"
    marker_path = tmp_path / "actions.log"
    store = WalStateStore(str(state_path), str(wal_path))
    state = _initial_state()
    contract = build_continue_contract(state)
    contract["next_legal_actions"] = ["tampered-action"]
    state["continue_contract"] = contract
    store.save(state)

    result = run_durable_loop(_Executor(marker_path), store, _policy())

    assert result["status"] == "BLOCKED"
    assert "contract identity mismatch" in result["block_reason"]
    assert not marker_path.exists()




def test_missing_continue_contract_inputs_block_before_any_side_effect(tmp_path):
    state_path = tmp_path / "invalid-state.json"
    wal_path = tmp_path / "invalid-state.wal.jsonl"
    marker_path = tmp_path / "actions.log"
    store = WalStateStore(str(state_path), str(wal_path))
    invalid_state = _initial_state()
    invalid_state.pop("project")
    store.save(invalid_state)

    result = run_durable_loop(_Executor(marker_path), store, _policy())

    assert result["status"] == "BLOCKED"
    assert "project must be a non-empty string" in result["block_reason"]
    assert not marker_path.exists()
    recovered = store.load()
    assert recovered["status"] == "BLOCKED"
    assert recovered["step"] == 0
    assert recovered["history"] == []



def test_authorized_observed_receipt_reconciles_unknown_without_replay(tmp_path):
    state_path = tmp_path / "reconcile-state.json"
    wal_path = tmp_path / "reconcile-state.wal.jsonl"
    marker_path = tmp_path / "reconcile-actions.log"
    store = WalStateStore(str(state_path), str(wal_path))
    store.save(_initial_state())

    class UnknownExecutor(_Executor):
        def verify(self, action_result, state):
            result = super().verify(action_result, state)
            result["status"] = "UNKNOWN"
            result["receipt"]["status"] = "UNKNOWN"
            result["receipt"]["evidence"] = {"reason": "provider response lost"}
            return result

    base = _policy()
    policy = LoopPolicy(
        max_steps=base.max_steps,
        terminal_evaluator=lambda verification, state: "PASS",
        action_authorizer=base.action_authorizer,
        policy_digest=base.policy_digest,
        require_execution_receipt=True,
        execution_receipt_validator=lambda receipt, state: None,
        state_patch_validator=lambda patch, receipt, state: None,
        continue_contract_builder=build_continue_contract,
    )
    blocked = run_durable_loop(UnknownExecutor(marker_path), store, policy)
    assert blocked["status"] == "BLOCKED"
    intent = blocked["in_flight_attempt"]
    receipt = {
        "effect_id": intent["effect_id"],
        "attempt_id": intent["attempt_id"],
        "status": "OBSERVED",
        "evidence": {"provider_query": "effect confirmed"},
    }
    authorized = []

    def authorize_reconciliation(saved_intent, observed_receipt):
        assert saved_intent["effect_id"] == observed_receipt["effect_id"]
        authorized.append(observed_receipt["attempt_id"])

    result = reconcile_in_flight_attempt(
        store, policy, receipt, authorizer=authorize_reconciliation
    )
    assert result["status"] == "PASS"
    assert "in_flight_attempt" not in result
    assert result["history"][-1]["verification"]["receipt"]["status"] == "OBSERVED"
    assert authorized == [intent["attempt_id"]]
    assert marker_path.read_text(encoding="utf-8").splitlines() == ["action-step-0"]
    assert store.load() == result


def test_reconciliation_rejects_wrong_attempt_identity(tmp_path):
    state_path = tmp_path / "wrong-reconcile-state.json"
    wal_path = tmp_path / "wrong-reconcile-state.wal.jsonl"
    marker_path = tmp_path / "wrong-reconcile-actions.log"
    store = WalStateStore(str(state_path), str(wal_path))
    store.save(_initial_state())

    class UnknownExecutor(_Executor):
        def verify(self, action_result, state):
            result = super().verify(action_result, state)
            result["receipt"]["status"] = "UNKNOWN"
            return result

    base = _policy()
    policy = LoopPolicy(
        max_steps=base.max_steps,
        terminal_evaluator=lambda verification, state: "PASS",
        action_authorizer=base.action_authorizer,
        policy_digest=base.policy_digest,
        require_execution_receipt=True,
        execution_receipt_validator=lambda receipt, state: None,
        state_patch_validator=lambda patch, receipt, state: None,
        continue_contract_builder=build_continue_contract,
    )
    blocked = run_durable_loop(UnknownExecutor(marker_path), store, policy)
    intent = blocked["in_flight_attempt"]
    before = store.load()
    wrong = {
        "effect_id": intent["effect_id"],
        "attempt_id": "attempt-forged",
        "status": "OBSERVED",
        "evidence": {"provider_query": "effect confirmed"},
    }
    try:
        reconcile_in_flight_attempt(store, policy, wrong, authorizer=lambda *_: None)
    except ValueError as exc:
        assert "does not match" in str(exc)
    else:
        raise AssertionError("mismatched reconciliation receipt was accepted")
    assert store.load() == before
    assert marker_path.read_text(encoding="utf-8").splitlines() == ["action-step-0"]



def test_unknown_receipt_blocks_and_never_retries_automatically(tmp_path):
    state_path = tmp_path / "unknown-state.json"
    wal_path = tmp_path / "unknown-state.wal.jsonl"
    marker_path = tmp_path / "actions.log"
    store = WalStateStore(str(state_path), str(wal_path))

    class UnknownExecutor(_Executor):
        def verify(self, action_result, state):
            result = super().verify(action_result, state)
            result["status"] = "UNKNOWN"
            result["receipt"]["status"] = "UNKNOWN"
            result["receipt"]["evidence"] = {"reason": "provider outcome not observable"}
            return result

    # Start from a complete governed state so this test reaches the UNKNOWN receipt boundary.
    store.save(_initial_state())
    base = _policy()
    policy = LoopPolicy(
        max_steps=base.max_steps,
        terminal_evaluator=lambda verification, state: "PASS",
        action_authorizer=base.action_authorizer,
        policy_digest=base.policy_digest,
        require_execution_receipt=True,
        execution_receipt_validator=lambda receipt, state: None,
        state_patch_validator=lambda patch, receipt, state: None,
        continue_contract_builder=build_continue_contract,
    )

    result = run_durable_loop(UnknownExecutor(marker_path), store, policy)

    assert result["status"] == "BLOCKED"
    assert "UNKNOWN" in result["block_reason"]
    assert result["step"] == 1
    assert result["history"][-1]["verification"]["receipt"]["attempt_id"] == result["in_flight_attempt"]["attempt_id"]
    assert result["history"][-1]["verification"]["receipt"]["effect_id"] == result["in_flight_attempt"]["effect_id"]
    assert result["history"][-1]["verification"]["receipt"]["status"] == "UNKNOWN"
    assert marker_path.read_text(encoding="utf-8").splitlines() == ["action-step-0"]
    recovered = store.load()
    assert recovered["status"] == "BLOCKED"
    assert recovered["history"][-1]["verification"]["receipt"]["status"] == "UNKNOWN"

if __name__ == "__main__" and len(sys.argv) == 5 and sys.argv[1] == "--child":
    _child(sys.argv[2], sys.argv[3], sys.argv[4])
elif __name__ == "__main__" and len(sys.argv) == 5 and sys.argv[1] == "--crash-after-effect":
    _crash_after_provider_effect(sys.argv[2], sys.argv[3], sys.argv[4])
elif __name__ == "__main__" and len(sys.argv) == 5 and sys.argv[1] == "--crash-after-receipt":
    _crash_after_validated_receipt(sys.argv[2], sys.argv[3], sys.argv[4])
