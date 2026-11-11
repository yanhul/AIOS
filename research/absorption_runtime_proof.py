"""AIOS runtime probes plus candidate-specific implementation/test proof.

Generic AIOS probes are never promoted as proof for an unrelated candidate. For
each independently verified candidate, re-check local implementation refs, rerun
its declared test files, and bind the result to immutable source/test/receipt lineage.
External candidate code is never executed.
"""
from __future__ import annotations
import hashlib, json, os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.durable_loop import LoopPolicy, MemoryStateStore, run_durable_loop
from core.durable_runtime import RuntimeSubmission, validate_submission
from core.evidence import EvidenceRecord, verify_evidence
from research.absorbed_capabilities import run_conformance
from research.absorption_verifier import _file_ref_errors, _run_candidate_tests

OUT = Path(os.environ.get("AIOS_ABSORPTION_RUNTIME_PROOF_OUT", "research/artifacts/absorption-runtime-proof.json"))
VERIFY_IN = Path(os.environ.get("AIOS_ABSORPTION_VERIFY_IN", "research/artifacts/absorption-verification.json"))

def _digest(v):
    return hashlib.sha256(json.dumps(v, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def _durable_loop_probe():
    class E:
        def observe(self, state): return {"seen": state["step"]}
        def decide(self, observation, state): return {"op": "probe"}
        def act(self, decision, state): return {"ok": True}
        def verify(self, action_result, state):
            intent = state["in_flight_attempt"]
            return {"status": "PASS", "receipt": {"effect_id":intent["effect_id"],"attempt_id":intent["attempt_id"],"status":"OBSERVED","evidence":{"probe":"ok"}}}
    def validate_probe_receipt(receipt, state):
        if receipt.get("evidence") != {"probe": "ok"}:
            raise ValueError("absorption proof receipt evidence is invalid")
        intent = state.get("in_flight_attempt")
        if not isinstance(intent, dict):
            raise ValueError("absorption proof has no persisted intent")
        if receipt.get("effect_id") != intent.get("effect_id") or receipt.get("attempt_id") != intent.get("attempt_id"):
            raise ValueError("absorption proof receipt lineage mismatch")
    policy = LoopPolicy(max_steps=1, terminal_evaluator=lambda verification, state: verification["status"],
                        action_authorizer=lambda decision, state: None, require_execution_receipt=True,
                        execution_receipt_validator=validate_probe_receipt,
                        state_patch_validator=lambda patch, receipt, state: None)
    result = run_durable_loop(E(), MemoryStateStore(), policy)
    return result.get("status") == "PASS" and result.get("terminal_evidence", {}).get("verification", {}).get("receipt", {}).get("status") == "OBSERVED"

def _evidence_probe():
    r = EvidenceRecord("absorption-runtime-proof", "VERIFIED_DIGITAL", "aios://absorption-runtime",
                        "AIOS_NATIVE_ABSORBED_PRIMITIVE_RUNTIME_PROOF",
                        os.environ.get("GITHUB_RUN_ID","local"), "AIOS_RUNTIME").as_record()
    return verify_evidence(r)

def _runtime_probe():
    effect = {"effect_id":"effect-proof"}
    validate_submission(effect, RuntimeSubmission("effect-proof","attempt-proof","AIOS_RUNTIME"), "attempt-proof", "AIOS_RUNTIME")
    try:
        validate_submission(effect, RuntimeSubmission("wrong","attempt-proof","AIOS_RUNTIME"), "attempt-proof", "AIOS_RUNTIME")
    except ValueError:
        return True
    return False

def _candidate_proofs(verification):
    records = verification.get("records", [])
    proofs = []
    failures = []
    seen = set()
    for record in records:
        cid = record.get("candidate_id")
        if not cid or cid in seen:
            failures.append({"candidate_id": cid, "reason": "missing or duplicate candidate id"})
            continue
        seen.add(cid)
        refs = record.get("implementation_refs", [])
        errors = _file_ref_errors(refs, label="implementation_refs")
        passed, actual_test_digest, test_errors = _run_candidate_tests(record.get("candidate_test_refs", []))
        errors.extend(test_errors)
        if actual_test_digest != record.get("candidate_test_digest"):
            errors.append("candidate test digest changed between verification and runtime proof")
        lineage = record.get("authority_receipt_lineage") or {}
        if not all(lineage.get(k) for k in ("effect_id", "attempt_id", "receipt_id", "evidence_digest")):
            errors.append("missing effect-attempt-receipt-evidence lineage")
        commit = record.get("source_commit", "")
        if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit.lower()):
            errors.append("source commit is not a full immutable SHA")
        status = "PASS" if passed and not errors else "BLOCKED"
        proof = {
            "candidate_id": cid, "status": status, "source_commit": commit,
            "test_digest": record.get("test_digest"),
            "candidate_test_digest": actual_test_digest,
            "source_code_digest": record.get("source_code_digest"),
            "reviewed_files": record.get("reviewed_files"),
            "effect_id": lineage.get("effect_id"), "attempt_id": lineage.get("attempt_id"),
            "receipt_id": lineage.get("receipt_id"), "evidence_digest": lineage.get("evidence_digest"),
            "implementation_refs": refs, "candidate_test_refs": record.get("candidate_test_refs", []),
            "errors": errors,
        }
        proof["proof_digest"] = _digest(proof)
        proofs.append(proof)
        if status != "PASS":
            failures.append({"candidate_id": cid, "reason": "; ".join(errors) or "candidate test run failed"})
    expected = len(records)
    return proofs, failures, expected == len(proofs) and not failures

def run():
    implementation = run_conformance()
    probes = {
        "implementation_conformance": implementation["overall"] == "PASS",
        "durable_execution": _durable_loop_probe(),
        "evidence_provenance": _evidence_probe(),
        "retry_provider_lineage": _runtime_probe(),
    }
    verify_in = Path(os.environ.get("AIOS_ABSORPTION_VERIFY_IN", str(VERIFY_IN)))
    verification = json.loads(verify_in.read_text(encoding="utf-8")) if verify_in.exists() else {}
    candidate_proofs, candidate_failures, candidate_ok = _candidate_proofs(verification)
    # With no verified candidates this artifact proves only generic AIOS probes;
    # promotion still requires verification PASS and a matching candidate proof.
    overall = all(probes.values()) and (
        not verification.get("records") or
        (verification.get("overall") == "PASS" and candidate_ok and len(candidate_proofs) == len(verification.get("records", [])))
    )
    result = {
        "schema_version": 3, "kind": "AIOS_ABSORPTION_RUNTIME_PROOF",
        "run_id": os.environ.get("GITHUB_RUN_ID","local"),
        "implementation": implementation, "probes": probes,
        "passed_count": sum(probes.values()), "total_count": len(probes),
        "candidate_proofs": candidate_proofs, "candidate_failure_count": len(candidate_failures),
        "candidate_failures": candidate_failures,
        "overall": "PASS" if overall else "BLOCKED",
        "external_code_execution": False, "external_code_copy": False, "source_mutation": False,
        "digest": _digest({"implementation": implementation, "probes": probes,
                           "candidate_proofs": candidate_proofs, "candidate_failures": candidate_failures}),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    return result

if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["overall"] == "PASS" else 1)
