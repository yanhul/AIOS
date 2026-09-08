#!/usr/bin/env python3
"""Fail-closed central AIOS workload adapter runner."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

AIOS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AIOS_ROOT))

import yaml

from core.capability_catalog import load_catalog
from core.contract import contract_identity, issue_permit, validate_contract, verify_permit
from core.policy_registry import resolve_policy
from core.workload_registry import WorkloadRegistry
from core.mutation import canonical_json

AUTHORITY = "yanhul/AIOS"
DEFAULT_POLICY = "sha256:0640840b0d5ab455470a7069163a928bd6d14a79168e834bb218a79559ba46b7"


def blocked(reason: str) -> int:
    print(json.dumps({"status": "BLOCKED", "reason": reason}, sort_keys=True))
    return 2


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"invalid JSON artifact: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must be an object: {path}")
    return value


def parse_single_json_document(stdout: str) -> dict:
    """Accept one JSON document regardless of pretty-printing; reject extra data."""
    decoder = json.JSONDecoder()
    stripped = stdout.lstrip()
    try:
        value, end = decoder.raw_decode(stripped)
    except ValueError as exc:
        raise ValueError("adapter output is not valid JSON") from exc
    if stripped[end:].strip():
        raise ValueError("adapter must emit exactly one JSON result object")
    if not isinstance(value, dict):
        raise ValueError("adapter result must be an object")
    return value


def receipt_digest(receipt: dict) -> str:
    unsigned = dict(receipt)
    unsigned.pop("receipt_sha256", None)
    return "sha256:" + sha256_bytes(canonical_json(unsigned).encode())


def validate_saved_receipt(saved: dict, *, execution_id: str, workload_id: str,
                           capability_ref: str, contract_id: str, policy_digest: str,
                           producer: str, terminal_states: list[str]) -> None:
    required = {
        "receipt_type", "execution_id", "workload_id", "capability", "policy_digest",
        "contract_id", "permit_id", "status", "evidence_refs", "verification_refs",
        "provenance", "manifest_sha256", "result_sha256", "receipt_sha256",
    }
    missing = required - set(saved)
    if missing:
        raise ValueError(f"persisted receipt missing fields: {sorted(missing)}")
    if saved.get("receipt_type") != "AIOS_GOVERNED_EXECUTION_RECEIPT":
        raise ValueError("persisted receipt type mismatch")
    if saved.get("execution_id") != execution_id or saved.get("workload_id") != workload_id:
        raise ValueError("persisted receipt identity mismatch")
    if saved.get("contract_id") != contract_id:
        raise ValueError("persisted receipt contract mismatch")
    if saved.get("policy_digest") != policy_digest or saved.get("capability") != capability_ref:
        raise ValueError("persisted receipt authority mismatch")
    if saved.get("status") not in terminal_states:
        raise ValueError("persisted receipt terminal state mismatch")
    if not isinstance(saved.get("evidence_refs"), list) or not saved["evidence_refs"]:
        raise ValueError("persisted receipt evidence refs missing")
    if not isinstance(saved.get("verification_refs"), list) or not saved["verification_refs"]:
        raise ValueError("persisted receipt verification refs missing")
    provenance = saved.get("provenance")
    if not isinstance(provenance, dict) or provenance.get("producer") != producer or provenance.get("adapter") != capability_ref:
        raise ValueError("persisted receipt provenance mismatch")
    if saved.get("receipt_sha256") != receipt_digest(saved):
        raise ValueError("persisted receipt integrity mismatch")


def persist_receipt(path: Path, receipt: dict) -> None:
    """Atomically publish the terminal receipt so a restart can reuse it."""
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(canonical_json(receipt) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workload-id", required=True)
    ap.add_argument("--execution-id", required=True)
    ap.add_argument("--cwd", required=True)
    ap.add_argument("--problem", required=True)
    ap.add_argument("--timeout-seconds", type=int, default=300)
    ap.add_argument("--policy-digest", default=DEFAULT_POLICY)
    ap.add_argument("--receipt-path")
    args, command = ap.parse_known_args()
    if command and command[0] == "--":
        command = command[1:]
    try:
        if args.timeout_seconds < 1 or args.timeout_seconds > 3600:
            raise ValueError("timeout outside governed range")
        cwd = Path(args.cwd).resolve()
        if not cwd.is_dir():
            raise ValueError("workload cwd does not exist")

        policy = resolve_policy(str(AIOS_ROOT), args.policy_digest)
        catalog_path = AIOS_ROOT / "capabilities" / "registry.yaml"
        catalog = load_catalog(catalog_path)
        raw_catalog = yaml.safe_load(catalog_path.read_text(encoding="utf-8")) or {}
        entries = [e for e in raw_catalog.get("capabilities", []) if e.get("owner") == args.workload_id]
        if len(entries) != 1:
            raise ValueError("workload must have exactly one normative catalog registration")
        entry = entries[0]
        capability_ref = f"{entry['capability_id']}@{entry['version']}"
        registration_id = f"{entry['owner']}@{entry['version']}"
        registration = WorkloadRegistry.from_capability_entries(entries).resolve(registration_id)
        capability = catalog.require(capability_ref)
        if capability.status != "ACTIVE":
            raise ValueError("capability is not ACTIVE under the normative catalog")

        manifest_path = (cwd / registration.adapter).resolve()
        try:
            manifest_path.relative_to(cwd)
        except ValueError as exc:
            raise ValueError("catalog manifest escapes workload root") from exc
        manifest = read_json(manifest_path)
        if manifest.get("aios_authority") != AUTHORITY:
            raise ValueError("manifest authority mismatch")
        if manifest.get("owner") != entry["owner"]:
            raise ValueError("manifest owner mismatch")
        if manifest.get("capability") != capability_ref:
            raise ValueError("manifest capability/version mismatch")
        if manifest.get("protocol_version") != 1:
            raise ValueError("unsupported workload protocol version")
        terminal_states = manifest.get("terminal_states")
        catalog_terminal_states = set(entry.get("terminal_states", []))
        if not isinstance(terminal_states, list) or not terminal_states:
            raise ValueError("manifest terminal states missing")
        if not set(terminal_states).issubset(catalog_terminal_states):
            raise ValueError("manifest terminal states exceed normative capability contract")
        verification = manifest.get("verification_classes")
        if not isinstance(verification, list) or not verification:
            raise ValueError("manifest verification classes missing")

        adapter_rel = manifest.get("adapter")
        if not isinstance(adapter_rel, str) or not adapter_rel:
            raise ValueError("manifest adapter missing")
        declared_adapter = (cwd / adapter_rel).resolve()
        try:
            declared_adapter.relative_to(cwd)
        except ValueError as exc:
            raise ValueError("declared adapter escapes workload root") from exc
        if not declared_adapter.is_file():
            raise ValueError("manifest must declare an existing adapter")
        if not command:
            raise ValueError("adapter command missing")
        if len(command) != 2:
            raise ValueError("adapter command must contain exactly interpreter and adapter")
        interpreter, invoked_rel = command
        allowed_interpreters = {"python", "python3", sys.executable, "bash", "sh", "/bin/bash", "/bin/sh"}
        if interpreter not in allowed_interpreters:
            raise ValueError("execution command interpreter is not governed")
        invoked = (cwd / invoked_rel).resolve()
        if invoked != declared_adapter:
            raise ValueError("execution command does not match manifest adapter")
        if declared_adapter.suffix == ".py" and interpreter not in {"python", "python3", sys.executable}:
            raise ValueError("Python adapter requires a Python interpreter")
        if declared_adapter.suffix == ".sh" and interpreter not in {"bash", "sh", "/bin/bash", "/bin/sh"}:
            raise ValueError("shell adapter requires a shell interpreter")
        if declared_adapter.suffix not in {".py", ".sh"}:
            raise ValueError("only Python and POSIX shell adapters are supported")

        input_digest = "sha256:" + sha256_bytes(canonical_json({"problem": args.problem, "workload_id": args.workload_id}).encode())
        contract = {
            "contract_type": "EXECUTION_CONTRACT", "task_id": args.execution_id,
            "scope": args.workload_id, "actor": "AIOS_CENTRAL_RUNNER",
            "capabilities": [capability_ref], "input_digest": input_digest,
            "allowed_effects": list(policy["allowed_effects"]),
            "evidence_required": list(policy["evidence_required"]),
            "max_attempts": int(policy["max_attempts"]),
            "terminal_states": sorted(terminal_states), "policy_digest": args.policy_digest,
        }
        validate_contract(contract)
        permit = issue_permit(contract, AUTHORITY)
        verify_permit(contract, permit)

        receipt_path = Path(args.receipt_path).resolve() if args.receipt_path else None
        if receipt_path and receipt_path.exists():
            saved = read_json(receipt_path)
            validate_saved_receipt(
                saved, execution_id=args.execution_id, workload_id=args.workload_id,
                capability_ref=capability_ref, contract_id=contract_identity(contract),
                policy_digest=args.policy_digest, producer=entry["owner"], terminal_states=terminal_states,
            )
            print(canonical_json(saved))
            return 0

        env = os.environ.copy()
        env.update({"AIOS_POLICY_DIGEST": args.policy_digest, "AIOS_CONTRACT_ID": contract_identity(contract),
                    "AIOS_EXECUTION_ID": args.execution_id, "AIOS_CAPABILITY": capability_ref,
                    "AIOS_PROBLEM": args.problem})
        existing_pythonpath = env.get("PYTHONPATH")
        env["PYTHONPATH"] = str(cwd) + (os.pathsep + existing_pythonpath if existing_pythonpath else "")
        proc = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True,
                              timeout=args.timeout_seconds, check=False, shell=False)
        if proc.returncode != 0:
            raise ValueError(f"adapter exited non-zero: {proc.returncode}: {proc.stderr.strip()[-500:]}")
        result = parse_single_json_document(proc.stdout)
        required = {"status", "evidence_refs", "verification_refs", "provenance"}
        if not required.issubset(result):
            raise ValueError(f"adapter result missing fields: {sorted(required - set(result))}")
        if result["status"] not in terminal_states:
            raise ValueError(f"adapter returned undeclared terminal state: {result['status']!r}")
        if not isinstance(result["evidence_refs"], (list, tuple)) or not result["evidence_refs"]:
            raise ValueError("adapter result must contain evidence refs")
        if not isinstance(result["verification_refs"], (list, tuple)) or not result["verification_refs"]:
            raise ValueError("adapter result must contain verification refs")
        if not isinstance(result["provenance"], dict) or result["provenance"].get("producer") != entry["owner"]:
            raise ValueError("adapter provenance producer mismatch")
        if result["provenance"].get("adapter") != capability_ref:
            raise ValueError("adapter provenance capability mismatch")
        if not set(result["verification_refs"]).issubset(set(verification)):
            raise ValueError("adapter verification refs exceed manifest verification classes")
        if "adapter_result" not in policy["evidence_required"]:
            raise ValueError("governing policy does not require adapter-result evidence")

        receipt = {
            "receipt_type": "AIOS_GOVERNED_EXECUTION_RECEIPT", "execution_id": args.execution_id,
            "workload_id": args.workload_id, "capability": capability_ref,
            "policy_digest": args.policy_digest, "contract_id": contract_identity(contract),
            "permit_id": permit["permit_id"], "status": result["status"],
            "evidence_refs": list(result["evidence_refs"]), "verification_refs": list(result["verification_refs"]),
            "provenance": result["provenance"], "manifest_sha256": "sha256:" + sha256_bytes(manifest_path.read_bytes()),
            "result_sha256": "sha256:" + sha256_bytes(canonical_json(result).encode()),
        }
        receipt["receipt_sha256"] = receipt_digest(receipt)
        if receipt_path:
            persist_receipt(receipt_path, receipt)
        print(canonical_json(receipt))
        return 0
    except subprocess.TimeoutExpired:
        return blocked("adapter exceeded governed timeout")
    except Exception as exc:
        return blocked(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
