import hashlib
import json
from research.absorption_verifier import verify
from research.absorption_promotion import promote


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _record(run_id="run-1"):
    return {
        "candidate_id": "cand-1", "source_ref": "https://github.com/example/agent",
        "source_digest": "a" * 64, "evidence_digest": "b" * 64, "run_id": run_id,
        "status": "RESEARCHED_ADAPTATION_PROPOSED", "evidence_status": "COLLECTED",
        "adaptation": {"external_code_copy": False, "external_code_execution": False,
            "target_surface": "new AIOS adapter/task only",
            "required_checks": ["source_evidence_digest", "AIOS_conformance", "independent_tests", "evidence_promotion_gate"]},
    }


def _runtime(run_id="run-1"):
    implementation, probes = {"overall": "PASS"}, {"runtime": True}
    return {"run_id": run_id, "overall": "PASS", "implementation": implementation,
            "probes": probes, "digest": _digest({"implementation": implementation, "probes": probes})}


def test_independent_verification_and_gate(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOS_ABSORPTION_VERIFY_OUT", str(tmp_path / "verify.json"))
    monkeypatch.setenv("AIOS_ABSORPTION_PROMOTION_OUT", str(tmp_path / "promote.json"))
    data = {"run_id": "run-1", "overall": "PASS", "records": [_record()]}
    v = verify(data, run_id="run-1", tests_passed=True, test_digest="c" * 64)
    assert v["overall"] == "PASS" and v["records"][0]["level"] == "VERIFIED_DIGITAL"
    runtime = _runtime()
    p = promote(v, runtime, run_id="run-1")
    assert p["overall"] == "PASS" and p["decisions"][0]["allowed"] is True
    assert p["input_verification_digest"] == v["digest"]
    assert p["input_runtime_digest"] == runtime["digest"]


def test_promotion_blocks_without_current_run_runtime_proof():
    v = verify({"run_id": "run-2", "overall": "PASS", "records": [_record("run-2")]},
               run_id="run-2", tests_passed=True, test_digest="c" * 64)
    p = promote(v, {"run_id": "old-run", "overall": "PASS"}, run_id="run-2")
    assert p["overall"] == "PASS_WITH_HOLDS" and p["promoted_count"] == 0


def test_verification_blocks_untrusted_record(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOS_ABSORPTION_VERIFY_OUT", str(tmp_path / "verify.json"))
    data = {"run_id": "run-2", "overall": "PASS", "records": [{
        "candidate_id": "cand-2", "source_ref": "https://github.com/example/x",
        "source_digest": "a" * 64, "run_id": "run-2", "status": "HOLD",
        "evidence_status": "ERROR",
        "adaptation": {"external_code_copy": False, "external_code_execution": False}}]}
    v = verify(data, run_id="run-2", tests_passed=True, test_digest="c" * 64)
    assert v["overall"] == "BLOCKED" and not v["records"]


def test_verification_blocks_non_pass_executor_intake(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOS_ABSORPTION_VERIFY_OUT", str(tmp_path / "verify.json"))
    data = {"run_id": "run-3", "overall": "HOLD", "records": [_record("run-3")]}
    v = verify(data, run_id="run-3", tests_passed=True, test_digest="c" * 64)
    assert v["overall"] == "BLOCKED"
    assert any("executor intake is not PASS" in e for f in v["failures"] for e in f["errors"])


def test_verification_rejects_stale_executor_run_id():
    data = {"run_id": "old-run", "overall": "PASS", "records": [_record("old-run")]}
    v = verify(data, run_id="current-run", tests_passed=True, test_digest="c" * 64)
    assert v["overall"] == "BLOCKED"
    assert any("run_id mismatch" in e for f in v["failures"] for e in f["errors"])


def test_verification_does_not_default_tests_to_pass():
    v = verify({"run_id": "run-4", "overall": "PASS", "records": [_record("run-4")]},
               run_id="run-4")
    assert v["overall"] == "BLOCKED"


def test_verification_rejects_malformed_provenance_digest():
    record = _record()
    record["source_digest"] = "not-a-digest"
    v = verify({"run_id": "run-1", "overall": "PASS", "records": [record]},
               run_id="run-1", tests_passed=True, test_digest="c" * 64)
    assert v["overall"] == "BLOCKED"
