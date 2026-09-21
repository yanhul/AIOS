from research.absorption_verifier import verify
from research.absorption_promotion import promote

def test_independent_verification_and_gate(tmp_path, monkeypatch):
    verify_out = tmp_path / "verify.json"
    promote_out = tmp_path / "promote.json"
    monkeypatch.setenv("AIOS_ABSORPTION_VERIFY_OUT", str(verify_out))
    monkeypatch.setenv("AIOS_ABSORPTION_PROMOTION_OUT", str(promote_out))
    data = {"run_id":"run-1","records":[{
        "candidate_id":"cand-1","source_ref":"https://github.com/example/agent","source_digest":"src",
        "evidence_digest":"ev","run_id":"run-1","status":"RESEARCHED_ADAPTATION_PROPOSED","evidence_status":"COLLECTED",
        "adaptation":{"external_code_copy":False,"external_code_execution":False,"target_surface":"new AIOS adapter/task only",
        "required_checks":["source_evidence_digest","AIOS_conformance","independent_tests","evidence_promotion_gate"]}}]}
    v=verify(data,run_id="run-1")
    assert v["overall"]=="PASS" and v["records"][0]["level"]=="VERIFIED_DIGITAL"
    p=promote(v,{"overall":"PASS","digest":"runtime"})
    assert p["overall"]=="PASS" and p["decisions"][0]["allowed"] is True

def test_promotion_blocks_without_runtime_proof():
    data={"run_id":"run-2","overall":"PASS","records":[{
        "candidate_id":"cand-2","source_ref":"https://github.com/example/x","source_digest":"src",
        "evidence_digest":"ev","run_id":"run-2","claim":"x","level":"VERIFIED_DIGITAL"}]}
    p=promote(data,{"overall":"BLOCKED"})
    assert p["overall"]=="PASS_WITH_HOLDS" and p["promoted_count"]==0

def test_verification_blocks_untrusted_record():
    data={"run_id":"run-2","records":[{
        "candidate_id":"cand-2","source_ref":"https://github.com/example/x","source_digest":"src","status":"HOLD",
        "evidence_status":"ERROR","adaptation":{"external_code_copy":False,"external_code_execution":False}}]}
    v=verify(data,run_id="run-2")
    assert v["overall"]=="BLOCKED" and not v["records"]
