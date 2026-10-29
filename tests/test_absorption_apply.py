from research.absorption_apply import absorb
import pytest

def _executor():
    return {"records":[{"candidate_id":"c1","source_ref":"https://github.com/example/x",
        "source_digest":"metadata","evidence_digest":"ed","adaptation":{"primitive":"durable_execution",
        "signals":["retry"],"proposal":"p","target_surface":"new AIOS adapter/task only"}}]}

def _verification():
    return {"overall":"PASS","records":[{"candidate_id":"c1","claim":"CANDIDATE_SPECIFIC_ADAPTATION_CONFORMS",
        "test_digest":"td","source_commit":"a"*40,"reviewed_files":[{"path":"src/x.py","sha256":"b"*64}],
        "source_code_digest":"c"*64,"implementation_refs":["core/x.py"],"candidate_test_refs":["tests/test_x.py"],
        "conformance_run_id":"run-1","log_digest":"d"*64,
        "authority_receipt_lineage":{"effect_id":"e1","attempt_id":"a1","receipt_id":"r1","evidence_digest":"evidence"}}]}

def _promotion():
    return {"decisions":[{"candidate_id":"c1","allowed":True,"verdict":"PROMOTE"}],"blocked":[]}

def test_absorb_requires_candidate_specific_runtime_proof(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOS_ABSORPTION_OUTCOME",str(tmp_path/"absorption.json"))
    with pytest.raises(RuntimeError,match="candidate_proofs is required"):
        absorb(_executor(),_verification(),_promotion(),{"overall":"PASS","digest":"generic"},run_id="run-1")

def test_absorb_blocks_missing_lineage(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOS_ABSORPTION_OUTCOME",str(tmp_path/"absorption.json"))
    runtime={"overall":"PASS","candidate_proofs":[{"candidate_id":"c1","status":"PASS",
        "source_commit":"a"*40,"test_digest":"td","effect_id":"wrong","attempt_id":"a1",
        "receipt_id":"r1","proof_digest":"proof"}]}
    result=absorb(_executor(),_verification(),_promotion(),runtime,run_id="run-1")
    assert result["overall"]=="BLOCKED" and result["absorbed_count"]==0

def test_absorb_accepts_matching_candidate_proof(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOS_ABSORPTION_OUTCOME",str(tmp_path/"absorption.json"))
    runtime={"overall":"PASS","candidate_proofs":[{"candidate_id":"c1","status":"PASS",
        "source_commit":"a"*40,"test_digest":"td","effect_id":"e1","attempt_id":"a1",
        "receipt_id":"r1","proof_digest":"proof"}]}
    result=absorb(_executor(),_verification(),_promotion(),runtime,run_id="run-1")
    assert result["overall"]=="PASS" and result["absorbed_count"]==1
    assert result["records"][0]["verification"]=="CANDIDATE_SPECIFIC_CONFORMANCE"
