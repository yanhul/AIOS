from research.absorption_verifier import verify
from research.absorption_promotion import promote
import pytest

def _review():
    return {
        "source_commit": "a" * 40,
        "reviewed_files": [{"path": "src/agent.py", "sha256": "b" * 64}],
        "source_code_digest": "c" * 64,
        "candidate_primitive": "durable_execution",
        "implementation_refs": ["core/durable_runtime.py"],
        "candidate_test_refs": ["tests/test_candidate_adapter.py"],
        "conformance_run_id": "run-1",
        "log_digest": "d" * 64,
        "authority_receipt_lineage": {
            "effect_id": "effect-1", "attempt_id": "attempt-1",
            "receipt_id": "receipt-1", "evidence_digest": "e" * 64,
        },
    }

def _record():
    return {
        "candidate_id":"cand-1","source_ref":"https://github.com/example/agent",
        "source_digest":"src","evidence_digest":"ev","run_id":"run-1",
        "status":"RESEARCHED_ADAPTATION_PROPOSED","evidence_status":"COLLECTED",
        "adaptation":{"primitive":"durable_execution","external_code_copy":False,
            "external_code_execution":False,"target_surface":"new AIOS adapter/task only",
            "required_checks":["source_evidence_digest","AIOS_conformance","independent_tests","evidence_promotion_gate"]},
        "source_review": _review(),
    }

def test_independent_verification_and_gate(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOS_ABSORPTION_VERIFY_OUT", str(tmp_path / "verify.json"))
    data={"run_id":"run-1","overall":"PASS","records":[_record()]}
    v=verify(data,run_id="run-1",test_digest="f"*64)
    assert v["overall"]=="PASS"
    assert v["records"][0]["verification"]=="CANDIDATE_SPECIFIC_CONFORMANCE"
    assert v["records"][0]["source_commit"]=="a"*40
    p=promote(v,{"overall":"PASS","digest":"runtime"})
    assert p["overall"]=="PASS" and p["decisions"][0]["allowed"] is True

def test_readme_only_candidate_is_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOS_ABSORPTION_VERIFY_OUT", str(tmp_path / "verify.json"))
    record=_record()
    record.pop("source_review")
    v=verify({"run_id":"run-1","overall":"PASS","records":[record]},run_id="run-1")
    assert v["overall"]=="BLOCKED"
    assert not v["records"]
    assert any("README/metadata evidence is insufficient" in error
               for failure in v["failures"] for error in failure["errors"])

def test_candidate_source_commit_must_be_immutable(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOS_ABSORPTION_VERIFY_OUT", str(tmp_path / "verify.json"))
    record=_record()
    record["source_review"]["source_commit"]="main"
    v=verify({"run_id":"run-1","overall":"PASS","records":[record]},run_id="run-1")
    assert v["overall"]=="BLOCKED"

def test_verification_blocks_missing_candidate_receipt_lineage(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOS_ABSORPTION_VERIFY_OUT", str(tmp_path / "verify.json"))
    record=_record()
    record["source_review"]["authority_receipt_lineage"]={"effect_id":"effect-1"}
    v=verify({"run_id":"run-1","overall":"PASS","records":[record]},run_id="run-1")
    assert v["overall"]=="BLOCKED"

def test_promotion_blocks_without_runtime_proof():
    data={"run_id":"run-2","records":[{"candidate_id":"cand-2","source_ref":"https://github.com/example/x",
        "source_digest":"src","evidence_digest":"ev","run_id":"run-2","claim":"x","level":"VERIFIED_DIGITAL"}]}
    p=promote(data,{"overall":"BLOCKED"})
    assert p["overall"]=="PASS_WITH_HOLDS" and p["promoted_count"]==0

def test_verification_blocks_untrusted_record(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOS_ABSORPTION_VERIFY_OUT", str(tmp_path / "verify.json"))
    data={"run_id":"run-2","records":[{"candidate_id":"cand-2","source_ref":"https://github.com/example/x",
        "source_digest":"src","status":"HOLD","evidence_status":"ERROR",
        "adaptation":{"external_code_copy":False,"external_code_execution":False}}]}
    v=verify(data,run_id="run-2")
    assert v["overall"]=="BLOCKED" and not v["records"]

def test_verification_blocks_non_pass_executor_intake(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOS_ABSORPTION_VERIFY_OUT", str(tmp_path / "verify.json"))
    record=_record()
    v=verify({"run_id":"run-1","overall":"HOLD","records":[record]},run_id="run-1")
    assert v["overall"]=="BLOCKED"
    assert any("executor intake is not PASS" in error
               for failure in v["failures"] for error in failure["errors"])
