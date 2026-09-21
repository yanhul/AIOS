"""Independent conformance verification for governed absorption proposals.

This verifies the AIOS-native proposal artifact itself. It does not execute or copy
external source code and it cannot mutate AIOS source/policy state.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path

INPUT = Path(os.environ.get("AIOS_ABSORPTION_EXECUTOR_OUT", "research/artifacts/absorption-executor.json"))
OUT = Path(os.environ.get("AIOS_ABSORPTION_VERIFY_OUT", "research/artifacts/absorption-verification.json"))

REQUIRED_CHECKS = {
    "source_evidence_digest",
    "AIOS_conformance",
    "independent_tests",
    "evidence_promotion_gate",
}

def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

def _verify_record(record: dict) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if record.get("status") != "RESEARCHED_ADAPTATION_PROPOSED":
        errors.append("research/adaptation did not complete")
    if record.get("evidence_status") != "COLLECTED":
        errors.append("source evidence not collected")
    adaptation = record.get("adaptation") or {}
    if adaptation.get("external_code_copy") is not False:
        errors.append("external code copy is not explicitly disabled")
    if adaptation.get("external_code_execution") is not False:
        errors.append("external code execution is not explicitly disabled")
    if adaptation.get("target_surface") != "new AIOS adapter/task only":
        errors.append("target surface is not AIOS-native bounded surface")
    if set(adaptation.get("required_checks", [])) != REQUIRED_CHECKS:
        errors.append("required verification checks are incomplete")
    for key in ("candidate_id", "source_ref", "source_digest", "evidence_digest", "run_id"):
        if not record.get(key):
            errors.append(f"missing provenance: {key}")
    return not errors, errors

def verify(data: dict, *, run_id: str) -> dict:
    records = data.get("records", [])
    verified = []
    failures = []
    for record in records:
        ok, errors = _verify_record(record)
        if ok:
            verified.append({
                "candidate_id": record["candidate_id"],
                "run_id": run_id,
                "source_ref": record["source_ref"],
                "claim": "AIOS_NATIVE_ADAPTATION_PROPOSAL_CONFORMS",
                "source_digest": record["source_digest"],
                "evidence_digest": record["evidence_digest"],
                "verification": "INDEPENDENT_STRUCTURAL_CONFORMANCE",
                "level": "VERIFIED_DIGITAL",
                "authority": "AIOS_CONTROL_PLANE",
                "external_code_copy": False,
                "external_code_execution": False,
            })
        else:
            failures.append({
                "candidate_id": record.get("candidate_id"),
                "errors": errors,
                "level": "UNKNOWN",
            })
    result = {
        "schema_version": 1,
        "kind": "AIOS_ABSORPTION_INDEPENDENT_VERIFICATION",
        "run_id": run_id,
        "records": verified,
        "failures": failures,
        "overall": "PASS" if records and len(verified) == len(records) else "BLOCKED",
        "digest": _digest({"verified": verified, "failures": failures}),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result

if __name__ == "__main__":
    data = json.loads(INPUT.read_text(encoding="utf-8"))
    result = verify(data, run_id=os.environ.get("GITHUB_RUN_ID", data.get("run_id", "local")))
    raise SystemExit(0 if result["overall"] == "PASS" else 1)
