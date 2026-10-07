#!/usr/bin/env python3
"""Product-E2E proof of crash-safe DISPATCHED attempt recovery.

This is intentionally a process boundary, not a pytest/unit simulation:
child process persists DISPATCHED(A1) and exits abruptly; parent process loads
the durable effect and calls resume_attempt() with the exact same attempt_id.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

AIOS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AIOS_ROOT))

from core.authority import load_contract, persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.durable_runtime import RuntimeSubmission
from core.effect_authority import create_effect, dispatch
from core.policy_registry import persist_policy
from core.runtime import ProviderReceipt, resume_attempt


ACTOR = "agent:product-e2e"
PROVIDER = "fake-provider"
LOGICAL_OPERATION = "product-e2e-crash-recovery"


class RecordingRuntime:
    name = "product-e2e-runtime"

    def __init__(self, log: Path):
        self.log = log

    def submit(self, *, effect, attempt_id):
        return RuntimeSubmission(effect["effect_id"], attempt_id, PROVIDER)

    def retry(self, *, effect, attempt_id, attempt):
        return RuntimeSubmission(effect["effect_id"], attempt_id, PROVIDER)

    def resume(self, *, effect, attempt_id):
        self.log.write_text(
            json.dumps({"event": "resume", "effect_id": effect["effect_id"],
                        "attempt_id": attempt_id}) + "\n",
            encoding="utf-8",
        )
        return RuntimeSubmission(effect["effect_id"], attempt_id, PROVIDER)


class RecordingAdapter:
    name = PROVIDER

    def __init__(self, log: Path):
        self.log = log

    def execute(self, *, contract, effect, attempt_id):
        current = json.loads(self.log.read_text(encoding="utf-8")) if self.log.exists() else {}
        current["provider_execute"] = {
            "effect_id": effect["effect_id"], "attempt_id": attempt_id,
        }
        self.log.write_text(json.dumps(current) + "\n", encoding="utf-8")
        return ProviderReceipt(
            self.name, effect["effect_id"], attempt_id, "product-e2e-op-1",
            "OBSERVED_SUCCESS", {"status": "ok", "crash_recovered": True},
        )


def setup(root: Path) -> tuple[str, str]:
    registry = CapabilityRegistry()
    registry.register(Capability(PROVIDER, "1", "product-e2e", "product-e2e", status="ACTIVE"))
    registry.persist(str(root), "product-e2e")
    policy = persist_policy(
        str(root),
        {"policy_type": "GOVERNING_POLICY", "name": "product-e2e-m6-crash-recovery"},
    )
    contract = {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": LOGICAL_OPERATION,
        "scope": "product-e2e",
        "actor": ACTOR,
        "capabilities": [f"{PROVIDER}@1"],
        "input_digest": "product-e2e-input",
        "allowed_effects": ["external_effect"],
        "evidence_required": ["provider_receipt"],
        "max_attempts": 1,
        "terminal_states": ["SUCCESS", "FAILURE"],
        "policy_digest": policy,
    }
    cid = contract_identity(contract)
    persist_contract(str(root), contract)
    permit = persist_permit(str(root), contract, "root")
    return cid, permit["permit_id"]


def crash_after_dispatch(root: Path, cid: str, pid: str) -> int:
    effect = create_effect(str(root), cid, LOGICAL_OPERATION, ACTOR, pid, "external_effect")
    attempt_id = f"{effect['effect_id']}:attempt:1"
    dispatched = dispatch(str(root), effect["effect_id"], ACTOR, attempt_id, PROVIDER)
    assert dispatched["state"] == "DISPATCHED"
    assert dispatched["attempt_id"] == attempt_id
    print(json.dumps({"crash_boundary": "DISPATCHED", "effect_id": dispatched["effect_id"],
                      "attempt_id": attempt_id}), flush=True)
    os._exit(97)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--phase", choices=("crash", "resume"), default="resume")
    args = ap.parse_args()
    root = Path(args.root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    log = root / "recovery-proof.json"

    if args.phase == "crash":
        cid, pid = setup(root)
        return crash_after_dispatch(root, cid, pid)

    cid, pid = setup(root)
    child = subprocess.run(
        [sys.executable, __file__, "--root", str(root), "--phase", "crash"],
        text=True, capture_output=True, check=False,
    )
    if child.returncode != 97:
        raise AssertionError(f"crash child did not die at boundary: rc={child.returncode} stderr={child.stderr}")
    effect_files = list((root / "effects").glob("EF-*.json"))
    if len(effect_files) != 1:
        raise AssertionError(f"expected exactly one durable effect, got {len(effect_files)}")
    effect = json.loads(effect_files[0].read_text(encoding="utf-8"))
    if effect["state"] != "DISPATCHED":
        raise AssertionError(f"crash boundary did not persist DISPATCHED: {effect}")
    attempt_id = effect["attempt_id"]
    if attempt_id != f"{effect['effect_id']}:attempt:1":
        raise AssertionError("persisted attempt identity is not deterministic")

    contract = load_contract(str(root), cid)
    result = resume_attempt(
        str(root), contract, effect, ACTOR, RecordingAdapter(log), RecordingRuntime(log),
    )
    if result["state"] != "OBSERVED_SUCCESS":
        raise AssertionError(f"resume did not reach OBSERVED_SUCCESS: {result}")
    if result["attempt_id"] != attempt_id or result["attempt"] != 1:
        raise AssertionError("resume allocated or changed the attempt identity")

    proof = json.loads(log.read_text(encoding="utf-8"))
    if proof["resume"]["attempt_id"] != attempt_id:
        raise AssertionError("runtime resume receipt changed attempt identity")
    if proof["provider_execute"]["attempt_id"] != attempt_id:
        raise AssertionError("provider execution changed attempt identity")
    print(json.dumps({
        "status": "PASS",
        "crash_exit_code": child.returncode,
        "effect_id": effect["effect_id"],
        "attempt_id": attempt_id,
        "before_crash": "DISPATCHED",
        "after_resume": result["state"],
        "provider_execution": "OBSERVED",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
