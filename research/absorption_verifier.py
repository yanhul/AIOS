"""Candidate-specific conformance gate for governed AIOS absorption.

A README, repository metadata, shared unit-test pass, or generic runtime probe is
not evidence that a particular external candidate was reviewed or integrated.
Promotion requires immutable source review, AIOS implementation references,
candidate tests, and authority receipt lineage.
"""
from __future__ import annotations
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
DEFAULT_INPUT = Path("research/artifacts/absorption-executor.json")
DEFAULT_OUT = Path("research/artifacts/absorption-verification.json")

def _path(env_name, default):
    return Path(os.environ.get(env_name, str(default)))

def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def _file_ref_errors(refs, *, label, require_tests=False):
    errors = []
    if not isinstance(refs, list) or not refs:
        return [f"source_review requires non-empty {label}"]
    for ref in refs:
        if not isinstance(ref, str) or not ref.strip():
            errors.append(f"{label} entries must be repository-relative file paths")
            continue
        path = Path(ref)
        try:
            resolved = (ROOT / path).resolve()
            resolved.relative_to(ROOT.resolve())
        except (ValueError, OSError):
            errors.append(f"{label} path escapes repository: {ref}")
            continue
        if path.is_absolute() or ".." in path.parts or not resolved.is_file():
            errors.append(f"{label} file does not exist as a safe repository file: {ref}")
            continue
        if require_tests and ("tests" not in path.parts or path.suffix != ".py"):
            errors.append(f"candidate test reference must be a Python file under tests/: {ref}")
    return errors

def _run_candidate_tests(refs):
    errors = _file_ref_errors(refs, label="candidate_test_refs", require_tests=True)
    if errors:
        return False, "", errors
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *refs],
        cwd=ROOT, capture_output=True, text=True, timeout=180,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, hashlib.sha256(output.encode("utf-8")).hexdigest(), ([] if proc.returncode == 0 else ["candidate-specific pytest run failed"])

def run_independent_tests() -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_absorption_executor.py",
         "tests/test_absorption_pipeline.py", "tests/test_absorption_verifier.py",
         "tests/test_absorption_repair.py", "-v"],
        cwd=ROOT, capture_output=True, text=True, timeout=180,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, hashlib.sha256(output.encode("utf-8")).hexdigest()

def _source_review_errors(record: dict) -> list[str]:
    errors: list[str] = []
    review = record.get("source_review")
    if not isinstance(review, dict):
        return ["missing candidate-specific source_review; README/metadata evidence is insufficient"]
    required = ("source_commit", "reviewed_files", "source_code_digest", "candidate_primitive",
                "implementation_refs", "candidate_test_refs", "conformance_run_id", "log_digest",
                "authority_receipt_lineage", "reviewer", "review_decision", "reviewed_at")
    for key in required:
        if not review.get(key):
            errors.append(f"source_review missing {key}")
    commit = str(review.get("source_commit", ""))
    if commit and (len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit.lower())):
        errors.append("source_review source_commit must be a full immutable Git commit SHA")
    files = review.get("reviewed_files")
    if not isinstance(files, list) or not files or not all(
        isinstance(f, dict) and isinstance(f.get("path"), str) and f.get("path")
        and isinstance(f.get("sha256"), str) and len(f["sha256"]) == 64
        and all(c in "0123456789abcdef" for c in f["sha256"].lower()) for f in (files or [])
    ):
        errors.append("source_review reviewed_files must list paths and valid SHA-256 digests")
    if review.get("review_decision") != "ACCEPTED":
        errors.append("source_review must contain an explicit ACCEPTED decision")
    errors.extend(_file_ref_errors(review.get("implementation_refs"), label="implementation_refs"))
    errors.extend(_file_ref_errors(review.get("candidate_test_refs"), label="candidate_test_refs", require_tests=True))
    lineage = review.get("authority_receipt_lineage")
    if not isinstance(lineage, dict) or not all(lineage.get(k) for k in
        ("effect_id", "attempt_id", "receipt_id", "evidence_digest")):
        errors.append("source_review authority_receipt_lineage must bind effect, attempt, receipt and evidence")
    if review.get("candidate_primitive") != (record.get("adaptation") or {}).get("primitive"):
        errors.append("source_review primitive does not match candidate adaptation primitive")
    if review.get("conformance_run_id") != record.get("run_id"):
        errors.append("candidate conformance run_id does not match executor run_id")
    return errors

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
    required_checks = {"source_evidence_digest", "AIOS_conformance", "independent_tests", "evidence_promotion_gate"}
    if set(adaptation.get("required_checks", [])) != required_checks:
        errors.append("required verification checks are incomplete")
    errors.extend(_source_review_errors(record))
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
    seen: set[str] = set()
    for record in records:
        cid = record.get("candidate_id")
        if not cid or cid in seen:
            failures.append({"candidate_id": cid, "errors": ["missing or duplicate candidate_id"], "level": "UNKNOWN"})
            continue
        seen.add(cid)
        ok, errors = _verify_record(record, tests_passed, test_digest)
        if record.get("run_id") != data.get("run_id"):
            errors.append("candidate run_id does not match executor artifact run_id")
            ok = False
        candidate_test_passed, candidate_test_digest, candidate_test_errors = _run_candidate_tests(
            (record.get("source_review") or {}).get("candidate_test_refs", [])
        )
        errors.extend(candidate_test_errors)
        if not candidate_test_passed:
            ok = False
        if ok:
            review = record["source_review"]
            verified.append({
                "candidate_id": cid, "run_id": run_id, "source_ref": record["source_ref"],
                "claim": "CANDIDATE_SPECIFIC_ADAPTATION_CONFORMS",
                "source_digest": record["source_digest"], "evidence_digest": record["evidence_digest"],
                "test_digest": test_digest, "candidate_test_digest": candidate_test_digest,
                "source_commit": review["source_commit"], "source_code_digest": review["source_code_digest"],
                "reviewed_files": review["reviewed_files"], "implementation_refs": review["implementation_refs"],
                "candidate_test_refs": review["candidate_test_refs"], "conformance_run_id": review["conformance_run_id"],
                "log_digest": review["log_digest"], "authority_receipt_lineage": review["authority_receipt_lineage"],
                "verification": "CANDIDATE_SPECIFIC_CONFORMANCE", "level": "VERIFIED_DIGITAL",
                "authority": "AIOS_CONTROL_PLANE", "external_code_copy": False, "external_code_execution": False,
            })
        else:
            failures.append({"candidate_id": cid, "errors": errors, "level": "UNKNOWN"})
    if input_overall != "PASS":
        failures.append({"candidate_id": None, "errors": [f"executor intake is not PASS: {input_overall!r}"], "level": "UNKNOWN"})
    result = {
        "schema_version": 3, "kind": "AIOS_ABSORPTION_CANDIDATE_SPECIFIC_VERIFICATION",
        "run_id": run_id, "records": verified, "failures": failures,
        "candidate_count": len(records), "verified_count": len(verified), "failure_count": len(failures),
        "overall": "PASS" if input_overall == "PASS" and records and len(verified) == len(records) and not failures else "BLOCKED",
        "independent_tests": {"passed": tests_passed, "digest": test_digest},
        "digest": _digest({"verified": verified, "failures": failures}),
        "promotion": "BLOCKED_UNLESS_CANDIDATE_SPECIFIC_EVIDENCE_COMPLETE",
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
    raise SystemExit(0 if result["overall"] == "PASS" else 1)
