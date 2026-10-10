#!/usr/bin/env python3
"""AIOS durable schematic-first runner for QI9-2605."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

from core.continue_contract import build_continue_contract
from core.durable_loop import LoopPolicy, run_durable_loop
from core.pcb_eda import validate_schematic_receipt
from core.wal_state_store import WalStateStore


class Store(WalStateStore):
    """Use the shared fsynced WAL as authority; snapshots are projections."""


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_sha(root: Path) -> str:
    """Hash a deterministic manifest of all regular input files; reject symlinks."""
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"expected directory: {root}")
    entries = []
    for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()):
        if path.is_symlink():
            raise ValueError(f"symlink is not allowed in EDA input tree: {path}")
        if path.is_file():
            entries.append({"path": path.relative_to(root).as_posix(), "sha256": sha(path)})
    if not entries:
        raise ValueError(f"EDA input tree contains no regular files: {root}")
    payload = json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(payload).hexdigest()


def workload_identity(a: argparse.Namespace) -> dict[str, str]:
    if not a.source_commit.strip() or not a.design.strip():
        raise ValueError("source commit and design are required for durable identity")
    if not a.config.is_file():
        raise FileNotFoundError(f"EDA config not found: {a.config}")
    proc = subprocess.run(
        ["git", "-C", str(a.kit_root), "rev-parse", "--verify", "HEAD"],
        text=True, capture_output=True, check=False,
    )
    if proc.returncode != 0:
        raise ValueError("cannot resolve exact Audit Kit checkout commit: " + proc.stderr[-1000:])
    kit_commit = proc.stdout.strip()
    if len(kit_commit) != 40 or any(c not in "0123456789abcdefABCDEF" for c in kit_commit):
        raise ValueError("Audit Kit checkout did not return a full Git commit SHA")
    return {
        "design": a.design,
        "source_commit": a.source_commit,
        "input_sha256": tree_sha(a.input),
        "config_sha256": sha(a.config),
        "kit_commit": kit_commit.lower(),
    }


def validate_resume_identity(state: Mapping[str, Any], expected: Mapping[str, str]) -> None:
    """A persisted run cannot be silently rebuilt for different inputs or source."""
    stored = state.get("workload_identity")
    if not isinstance(stored, Mapping):
        raise ValueError("persisted state lacks workload_identity; refusing unsafe legacy resume")
    if dict(stored) != dict(expected):
        raise ValueError("persisted workload identity mismatch; BLOCK instead of rebuilding continuation")
    if state.get("design") != expected["design"] or state.get("active_commit") != expected["source_commit"]:
        raise ValueError("persisted design/source commit does not match workload identity")


def seed(a: argparse.Namespace, identity: Mapping[str, str]) -> dict[str, Any]:
    return {
        "project": "yanhul/temp",
        "design": a.design,
        "authority": "AIOS_CONTROL_PLANE",
        "workload_identity": dict(identity),
        "pipeline": {"schematic": "RUNNING", "placement": "BLOCKED_BY_SCHEMATIC", "routing": "BLOCKED_BY_SCHEMATIC"},
        "active_phase": "SCHEMATIC",
        "active_commit": a.source_commit,
        "latest_run": "NOT_YET_RUN",
        "latest_receipt": "NOT_YET_RECEIPT",
        "active_blockers": [],
        "next_legal_actions": ["run_schematic", "inspect_receipt", "inspect_source", "patch", "commit", "wait_ci"],
        "forbidden_actions": ["placement", "routing", "claim_pass"],
        "verified_evidence_refs": [],
        "blocked_requirements": [],
    }


class Executor:
    def __init__(self, a: argparse.Namespace):
        self.a = a

    def observe(self, state: Mapping[str, Any]) -> dict[str, Any]:
        return {"capability": "pcb.eda@1", "phase": "SCHEMATIC", "step": state.get("step", 0)}

    def decide(self, observation: Mapping[str, Any], state: Mapping[str, Any]) -> dict[str, str]:
        return {"logical_operation_id": "pcb.eda.schematic", "authority": "AIOS_CONTROL_PLANE"}

    def act(self, decision: Mapping[str, Any], state: Mapping[str, Any]) -> dict[str, Any]:
        if decision.get("logical_operation_id") != "pcb.eda.schematic":
            raise PermissionError("only schematic operation is legal")
        number = state.get("step", 0) + 1
        output = self.a.output / f"attempt-{number}"
        output.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            [sys.executable, str(self.a.kit_root / "tools/altium-audit/e2e_phase.py"),
             "--phase", "schematic", "--input", str(self.a.input), "--output", str(output),
             "--config", str(self.a.config)],
            text=True, capture_output=True, check=False,
        )
        receipt_path = output / "phase_receipt.json"
        if not receipt_path.is_file():
            raise RuntimeError("schematic phase emitted no phase_receipt.json: " + proc.stderr[-4000:])
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        validate_schematic_receipt(receipt)
        if receipt.get("status") == "PASS" and proc.returncode != 0:
            raise ValueError("schematic receipt claims PASS but Audit Kit process returned non-zero")
        return {
            "attempt_dir": str(output.resolve()),
            "returncode": proc.returncode,
            "receipt": receipt,
            "receipt_sha256": sha(receipt_path),
            "stderr_tail": proc.stderr[-4000:],
        }

    def verify(self, result: Mapping[str, Any], state: Mapping[str, Any]) -> dict[str, Any]:
        receipt_data = result["receipt"]
        validate_schematic_receipt(receipt_data)
        status = receipt_data["status"]
        inventory = receipt_data["evidence"]["finding_inventory"]
        blockers = list(inventory.get("blocking") or inventory.get("errors") or [])
        pipeline = dict(state.get("pipeline") or {})
        pipeline["schematic"] = "VERIFIED" if status == "PASS" else "BLOCKED"
        pipeline["placement"] = "READY" if status == "PASS" else "BLOCKED_BY_SCHEMATIC"
        pipeline["routing"] = "BLOCKED_BY_PLACEMENT" if status == "PASS" else "BLOCKED_BY_SCHEMATIC"
        intent = state.get("in_flight_attempt")
        if not isinstance(intent, Mapping):
            raise ValueError("persisted execution intent missing during receipt verification")
        execution_receipt = {
            "effect_id": intent.get("effect_id"),
            "attempt_id": intent.get("attempt_id"),
            "status": "OBSERVED",
            "evidence": {
                "phase_receipt": str(Path(result["attempt_dir"]) / "phase_receipt.json"),
                "phase_receipt_sha256": result["receipt_sha256"],
                "source_commit": self.a.source_commit,
                "kit_commit": state["workload_identity"]["kit_commit"],
            },
        }
        return {
            "status": status,
            "receipt": execution_receipt,
            "state_patch": {
                "active_phase": "SCHEMATIC_VERIFIED" if status == "PASS" else "SCHEMATIC",
                "pipeline": pipeline,
                "active_blockers": blockers,
                "latest_attempt_dir": result["attempt_dir"],
                "latest_receipt": str(Path(result["attempt_dir"]) / "phase_receipt.json"),
                "latest_run": self.a.run_id,
                "next_legal_actions": ["placement"] if status == "PASS" else ["inspect_receipt", "inspect_source", "patch", "commit", "wait_ci"],
                "forbidden_actions": ["routing", "claim_pass"] if status == "PASS" else ["placement", "routing", "claim_pass"],
                "receipt": execution_receipt,
            },
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-id", "--task_id", dest="task_id", required=True)
    parser.add_argument("--source-commit", "--source_commit", dest="source_commit", required=True)
    parser.add_argument("--run-id", "--run_id", dest="run_id", required=True)
    parser.add_argument("--design", default="QI9-2605-A01")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kit-root", "--kit_root", dest="kit_root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--max-steps", "--max_steps", dest="max_steps", type=int, default=1)
    a = parser.parse_args()
    if a.max_steps != 1:
        parser.error("schematic-first runner permits exactly one bounded phase per invocation")
    a.input = a.input.resolve(strict=True)
    a.kit_root = a.kit_root.resolve(strict=True)
    a.config = a.config.resolve(strict=True)
    a.output.mkdir(parents=True, exist_ok=True)
    store = Store(str(a.state))
    identity = workload_identity(a)
    loaded = store.load()
    if loaded is None:
        store.save(seed(a, identity))
    else:
        validate_resume_identity(loaded, identity)

    policy = LoopPolicy(
        max_steps=1,
        terminal_evaluator=lambda verification, state: verification.get("status") if verification.get("status") in {"PASS", "BLOCKED"} else None,
        action_authorizer=lambda decision, state: None if decision.get("logical_operation_id") == "pcb.eda.schematic" else (_ for _ in ()).throw(PermissionError("unauthorized phase")),
        require_execution_receipt=True,
        resume_validator=lambda state: validate_resume_identity(state, identity),
        continue_contract_builder=build_continue_contract,
    )
    result = run_durable_loop(Executor(a), store, policy)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
