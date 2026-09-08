#!/usr/bin/env python3
"""Run the three executable AIOS workload adapters through the central runner.

MiniMind is a registered capability provider, not a fourth workload, so it is
intentionally excluded from workload conformance.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

WORKLOADS = {
    "yanhul/try": ("try.research@1", "python", "aios/adapter.py"),
    "yanhul/android-ai-assistant": ("android.assistant@1", "bash", "aios/adapter.sh"),
    "yanhul/RX50": ("rx50.engineering@1", "python", "aios/adapter.py"),
}


def run_one(runner: Path, workload_id: str, root: Path, receipt: Path) -> dict:
    capability, interpreter, adapter = WORKLOADS[workload_id]
    command = [sys.executable, str(runner), "--workload-id", workload_id,
               "--execution-id", f"conformance-{workload_id.replace('/', '-')}",
               "--cwd", str(root), "--problem", "AIOS v1 three-workload conformance",
               "--receipt-path", str(receipt), "--", interpreter, adapter]
    proc = subprocess.run(command, text=True, capture_output=True, check=False, timeout=900)
    if proc.returncode != 0:
        raise RuntimeError(f"{workload_id}: runner failed: {proc.stdout.strip()} {proc.stderr.strip()}")
    try:
        receipt_obj = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{workload_id}: runner did not emit JSON receipt") from exc
    required = {"receipt_type", "execution_id", "workload_id", "capability", "policy_digest",
                "contract_id", "permit_id", "status", "evidence_refs", "verification_refs", "provenance"}
    missing = required - set(receipt_obj)
    if missing:
        raise RuntimeError(f"{workload_id}: receipt missing {sorted(missing)}")
    if receipt_obj["workload_id"] != workload_id or receipt_obj["capability"] != capability:
        raise RuntimeError(f"{workload_id}: receipt binding mismatch")
    if receipt_obj["provenance"].get("producer") != workload_id:
        raise RuntimeError(f"{workload_id}: provenance mismatch")
    if not receipt_obj["evidence_refs"] or not receipt_obj["verification_refs"]:
        raise RuntimeError(f"{workload_id}: evidence/verification refs missing")
    return receipt_obj


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runner", default="scripts/run_workload_adapter.py")
    ap.add_argument("--root", action="append", nargs=2, metavar=("WORKLOAD_ID", "PATH"), required=True)
    ap.add_argument("--receipt-dir", default="artifacts/conformance")
    args = ap.parse_args()
    runner = Path(args.runner).resolve()
    roots = dict(args.root)
    if set(roots) != set(WORKLOADS):
        raise SystemExit(f"exactly these workload roots are required: {sorted(WORKLOADS)}")
    receipt_dir = Path(args.receipt_dir).resolve()
    receipt_dir.mkdir(parents=True, exist_ok=True)
    for workload_id in WORKLOADS:
        root = Path(roots[workload_id]).resolve()
        receipt = receipt_dir / (workload_id.replace("/", "__") + ".json")
        first = run_one(runner, workload_id, root, receipt)
        second = run_one(runner, workload_id, root, receipt)
        if first != second:
            raise RuntimeError(f"{workload_id}: durable receipt changed on reuse")
        print(json.dumps({"workload": workload_id, "status": first["status"],
                          "permit_id": first["permit_id"], "receipt": str(receipt)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
