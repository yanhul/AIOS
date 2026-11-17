"""Independent conformance verification for governed absorption proposals.

Verification is current-run only. Trusted evidence attestations bind the
source, collected-evidence, and independent-test digests into one record.
"""
from __future__ import annotations
import hashlib, json, os, re, subprocess, sys
from pathlib import Path
from core.evidence import EvidenceRecord, attest_evidence

DEFAULT_INPUT = Path("research/artifacts/absorption-executor.json")
DEFAULT_OUT = Path("research/artifacts/absorption-verification.json")
EVIDENCE_SECRET_ENV = "AIOS_EVIDENCE_SIGNING_SECRET"
REQUIRED_CHECKS = {"source_evidence_digest", "AIOS_conformance", "independent_tests", "evidence_promotion_gate"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _path(env_name, default):
    return Path(os.environ.get(env_name, str(default)))


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def run_independent_tests() -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_absorption_executor.py",
         "tests/test_absorption_pipeline.py", "tests/test_absorption_verifier.py",
         "tests/test_absorption_repair.py", "-v"],
        capture_output=True, text=True, timeout=120,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, hashlib.sha256(output.encode("utf-8")).hexdigest()


def _verify_record(record: dict, *, run_id: str, tests_passed: bool, test_digest: str,
                   evidence_secret: str | None) -> tuple[bool, list[str]]:
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
        errors.append("independent absorption tests did not pass in this invocation")
    if not _valid_digest(test_digest):
        errors.append("independent test digest is not a SHA-256 hex digest")
    for key in ("candidate_id", "source_ref"):
        if not isinstance(record.get(key), str) or not record[key].strip():
            errors.append(f"missing provenance: {key}")
    snapshot = record.get("source_snapshot")
    if not isinstance(snapshot, dict):
        errors.append("missing source snapshot for independent digest recomputation")
    elif _valid_digest(record.get("source_digest")):
        actual_source_digest = hashlib.sha256(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()
        if actual_source_digest != record.get("source_digest"):
            errors.append("source snapshot digest mismatch")
    else:
        errors.append("invalid or missing provenance SHA-256: source_digest")
    evidence_content = record.get("evidence_content")
    if not isinstance(evidence_content, str):
        errors.append("missing collected evidence content for digest recomputation")
    elif _valid_digest(record.get("evidence_digest")):
        actual_evidence_digest = hashlib.sha256(evidence_content.encode("utf-8")).hexdigest()
        if actual_evidence_digest != record.get("evidence_digest"):
            errors.append("collected evidence content digest mismatch")
    else:
        errors.append("invalid or missing provenance SHA-256: evidence_digest")
    if record.get("run_id") != run_id:
        errors.append("executor record run_id does not match current run")
    if not evidence_secret or len(evidence_secret) < 16:
        errors.append(f"trusted evidence secret {EVIDENCE_SECRET_ENV} is not configured")
    return not errors, errors


def verify(data: dict, *, run_id: str, tests_passed: bool = False,
           test_digest: str = "", evidence_secret: str | None = None) -> dict:
    records = data.get("records", [])
    input_overall = data.get("overall")
    secret = evidence_secret if evidence_secret is not None else os.environ.get(EVIDENCE_SECRET_ENV)
    verified, failures = [], []
    if data.get("run_id") != run_id:
        failures.append({"candidate_id": None,
                         "errors": [f"executor artifact run_id mismatch: expected {run_id!r}, got {data.get('run_id')!r}"],
                         "level": "UNKNOWN"})
    for record in records:
        ok, errors = _verify_record(record, run_id=run_id, tests_passed=tests_passed,
                                    test_digest=test_digest, evidence_secret=secret)
        if ok:
            evidence = EvidenceRecord(
                evidence_id=str(record["candidate_id"]), level="VERIFIED_DIGITAL",
                source_ref=str(record["source_ref"]),
                claim="AIOS_NATIVE_ADAPTATION_PROPOSAL_CONFORMS", run_id=run_id,
                provider="AIOS_CONTROL_PLANE",
                artifact_ref=str(record.get("evidence_url") or ""),
                source_digest=record["source_digest"],
                evidence_digest=record["evidence_digest"],
                test_digest=test_digest,
            ).as_record()
            evidence["attestation"] = attest_evidence(evidence, secret)
            verified.append({
                **evidence, "candidate_id": record["candidate_id"],
                "verification": "INDEPENDENT_STRUCTURAL_CONFORMANCE",
                "authority": "AIOS_CONTROL_PLANE", "external_code_copy": False,
                "external_code_execution": False,
            })
        else:
            failures.append({"candidate_id": record.get("candidate_id"), "errors": errors, "level": "UNKNOWN"})
    if input_overall != "PASS":
        failures.append({"candidate_id": None,
                         "errors": [f"executor intake is not PASS: {input_overall!r}"], "level": "UNKNOWN"})
    verified_payload = {"verified": verified, "failures": failures}
    result = {
        "schema_version": 3, "kind": "AIOS_ABSORPTION_INDEPENDENT_VERIFICATION",
        "run_id": run_id, "records": verified, "failures": failures,
        "candidate_count": len(records), "verified_count": len(verified),
        "failure_count": len(failures),
        "overall": "PASS" if input_overall == "PASS" and data.get("run_id") == run_id
                   and records and len(verified) == len(records) and not failures else "BLOCKED",
        "independent_tests": {"passed": tests_passed, "digest": test_digest},
        "digest": _digest(verified_payload),
    }
    out = _path("AIOS_ABSORPTION_VERIFY_OUT", DEFAULT_OUT)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    data = json.loads(_path("AIOS_ABSORPTION_EXECUTOR_OUT", DEFAULT_INPUT).read_text(encoding="utf-8"))
    current_run = os.environ.get("GITHUB_RUN_ID", "")
    tests_passed, test_digest = run_independent_tests()
    result = verify(data, run_id=current_run, tests_passed=tests_passed, test_digest=test_digest)
    raise SystemExit(0 if result["overall"] == "PASS" else 1)
