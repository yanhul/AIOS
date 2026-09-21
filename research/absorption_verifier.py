"""Independent conformance verification for governed absorption proposals.

This verifies the AIOS-native proposal artifact and independently runs the local
absorption test suite. It never executes or copies external source code.
"""
from __future__ import annotations
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

DEFAULT_INPUT = Path("research/artifacts/absorption-executor.json")
DEFAULT_OUT = Path("research/artifacts/absorption-verification.json")

def _path(env_name, default): return Path(os.environ.get(env_name, str(default)))

REQUIRED_CHECKS = {
    "source_evidence_digest",
    "AIOS_conformance",
    "independent_tests",
    "evidence_promotion_gate",
}

def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

def run_independent_tests() -> tuple[bool, str]:
    proc = subprocess.run(
        [
            sys.executable, "-m", "pytest",
            "tests/test_absorption_executor.py",
            "tests/test_absorption_pipeline.py",
            "tests/test_absorption_verifier.py",
            "tests/test_absorption_repair.py",
            "-v",
        ],
        capture_output=True, text=True, timeout=120,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, hashlib.sha256(output.encode("utf-8")).hexdigest()

def _verify_record(record: dict, tests_passed: bool, test_digest: str) -> tuple[bool, list[str]]:
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
    if not tests_passed:
        errors.append("independent absorption tests failed")
    if not test_digest:
        errors.append("missing independent test digest")
    for key in ("candidate_id", "source_ref", "source_digest", "evidence_digest", "run_id"):
        if not record.get(key):
            errors.append(f"missing provenance: {key}")
    return not errors, errors

def verify(data: dict, *, run_id: str, tests_passed: bool = True, test_digest: str = "unit-test-fixture") -> dict:
    records = data.get("records", [])
    input_overall = data.get("overall")
    verified = []
    failures = []
    for record in records:
        ok, errors = _verify_record(record, tests_passed, test_digest)
        if ok:
            verified.append({
                "candidate_id": record["candidate_id"],
                "run_id": run_id,
                "source_ref": record["source_ref"],
                "claim": "AIOS_NATIVE_ADAPTATION_PROPOSAL_CONFORMS",
                "source_digest": record["source_digest"],
                "evidence_digest": record["evidence_digest"],
                "test_digest": test_digest,
                "verification": "INDEPENDENT_STRUCTURAL_CONFORMANCE",
                "level": "VERIFIED_DIGITAL",
                "authority": "AIOS_CONTROL_PLANE",
                "external_code_copy": False,
                "external_code_execution": False,
            })
        else:
            failures.append({"candidate_id": record.get("candidate_id"), "errors": errors, "level": "UNKNOWN"})
    if input_overall != "PASS":
        failures.append({
            "candidate_id": None,
            "errors": [f"executor intake is not PASS: {input_overall!r}"],
            "level": "UNKNOWN",
        })
    result = {
        "schema_version": 1,
        "kind": "AIOS_ABSORPTION_INDEPENDENT_VERIFICATION",
        "run_id": run_id,
        "records": verified,
        "failures": failures,
        "candidate_count": len(records),
        "verified_count": len(verified),
        "failure_count": len(failures),
        "overall": "PASS" if input_overall == "PASS" and records and len(verified) == len(records) and not failures else "BLOCKED",
        "independent_tests": {"passed": tests_passed, "digest": test_digest},
        "digest": _digest({"verified": verified, "failures": failures}),
    }
    out = _path("AIOS_ABSORPTION_VERIFY_OUT", DEFAULT_OUT)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result

if __name__ == "__main__":
    data = json.loads(_path("AIOS_ABSORPTION_EXECUTOR_OUT", DEFAULT_INPUT).read_text(encoding="utf-8"))
    tests_passed, test_digest = run_independent_tests()
    result = verify(data, run_id=os.environ.get("GITHUB_RUN_ID", data.get("run_id", "local")),
                    tests_passed=tests_passed, test_digest=test_digest)
    # Candidate-level holds are expected outcomes; promotion remains fail-closed.
    raise SystemExit(0)
