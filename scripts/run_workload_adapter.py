#!/usr/bin/env python3
"""Fail-closed central runner for AIOS workload adapters.

The workload repository is untrusted input. Policy, authority and contract
semantics live here; the adapter can only produce an observed result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from core.contract import contract_identity, issue_permit, validate_contract, verify_permit
from core.policy_registry import policy_digest

POLICY = {
    "policy_type": "GOVERNING_POLICY",
    "policy_id": "central-workload-conformance",
    "version": "1",
    "max_attempts": 1,
    "allowed_effects": ["process_execution"],
    "evidence_required": ["adapter_result"],
    "terminal_state_source": "workload_manifest",
    "require_manifest_authority": "yanhul/AIOS",
    "require_manifest_capability_binding": True,
}


def die(message: str, code: int = 2) -> None:
    print(json.dumps({"status": "BLOCKED", "reason": message}, sort_keys=True))
    raise SystemExit(code)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path):
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        die(f"cannot load JSON artifact: {path}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workload-id", required=True)
    ap.add_argument("--execution-id", required=True)
    ap.add_argument("--cwd", required=True)
    ap.add_argument("--problem", required=True)
    ap.add_argument("--timeout-seconds", type=int, default=300)
    ap.add_argument("--", dest="_separator", nargs="*")
    args, command = ap.parse_known_args()
    if not command:
        die("adapter command missing")
    if args.timeout_seconds < 1 or args.timeout_seconds > 3600:
        die("timeout outside governed range")

    root = Path(args.cwd).resolve()
    manifest_path = root / "aios" / "workload.json"
    if not manifest_path.is_file():
        die("workload manifest missing")
    manifest = load_json(manifest_path)
    required = {"protocol_version", "capability", "owner", "aios_authority", "adapter", "entrypoint", "terminal_states", "verification_classes"}
    if not required.issubset(manifest):
        die("workload manifest schema incomplete")
    if manifest["aios_authority"] != POLICY["require_manifest_authority"]:
        die("workload manifest authority mismatch")
    if manifest["owner"] + "@" + str(manifest["protocol_version"]) != args.workload_id and args.workload_id not in (manifest["owner"], manifest["capability"]):
        # Keep the CLI identifier an explicit workload selector, never an authority grant.
        die("workload identity mismatch")
    if not isinstance(manifest["terminal_states"], list) or not manifest["terminal_states"]:
        die("manifest terminal states missing")
    if not isinstance(manifest["verification_classes"], list) or not manifest["verification_classes"]:
        die("manifest verification classes missing")

    declared_adapter = (root / manifest["adapter"]).resolve()
    try:
        declared_adapter.relative_to(root)
    except ValueError:
        die("declared adapter escapes workload root")
    if not declared_adapter.is_file():
        die("declared adapter missing")
    # The command must execute exactly the declared adapter; this prevents a
    # workflow from bypassing the manifest by substituting another program.
    command_paths = [Path(x) for x in command[1:] if not x.startswith("-")]
    if command[0] in {"python", "python3", sys.executable} and command_paths:
        invoked = (root / command_paths[0]).resolve()
    elif command[0].endswith("/python") and command_paths:
        invoked = (root / command_paths[0]).resolve()
    else:
        invoked = (root / command[0]).resolve()
    if invoked != declared_adapter:
        die("execution command does not match manifest adapter")

    pdigest = policy_digest(POLICY)
    contract = {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": args.execution_id,
        "scope": str(root),
        "actor": "AIOS_CENTRAL_RUNNER",
        "capabilities": [manifest["capability"]],
        "input_digest": "sha256:" + sha256_bytes(args.problem.encode("utf-8")),
        "allowed_effects": list(POLICY["allowed_effects"]),
        "evidence_required": list(POLICY["evidence_required"]),
        "max_attempts": POLICY["max_attempts"],
        "terminal_states": list(manifest["terminal_states"]),
        "policy_digest": pdigest,
    }
    validate_contract(contract)
    permit = issue_permit(contract, "yanhul/AIOS")
    verify_permit(contract, permit)

    env = os.environ.copy()
    env["AIOS_POLICY_DIGEST"] = pdigest
    env["AIOS_CONTRACT_ID"] = contract_identity(contract)
    env["AIOS_EXECUTION_ID"] = args.execution_id
    env["AIOS_CAPABILITY"] = manifest["capability"]
    try:
        proc = subprocess.run(command, cwd=root, env=env, text=True, capture_output=True, timeout=args.timeout_seconds, shell=False)
    except subprocess.TimeoutExpired:
        die("adapter exceeded governed timeout")
    if proc.returncode != 0:
        die(f"adapter exited non-zero: {proc.returncode}")
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        die("adapter must emit exactly one JSON result object")
    try:
        result = json.loads(lines[0])
    except ValueError:
        die("adapter output is not valid JSON")
    if not isinstance(result, dict):
        die("adapter result must be an object")
    if result.get("status") not in {"PASS", "BLOCKED", "INCONCLUSIVE"}:
        die("adapter result has unsupported status")
    if not isinstance(result.get("evidence_refs"), (list, tuple)):
        die("adapter result missing evidence_refs")
    if not isinstance(result.get("verification_refs"), (list, tuple)):
        die("adapter result missing verification_refs")
    if not isinstance(result.get("provenance"), dict):
        die("adapter result missing provenance")
    if result["provenance"].get("producer") != manifest["owner"]:
        die("adapter provenance producer mismatch")
    observed = dict(result)
    observed["governed"] = True
    observed["policy_digest"] = pdigest
    observed["contract_id"] = contract_identity(contract)
    observed["permit_id"] = permit["permit_id"]
    observed["execution_id"] = args.execution_id
    observed["manifest_sha256"] = sha256_bytes(manifest_path.read_bytes())
    print(json.dumps(observed, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
