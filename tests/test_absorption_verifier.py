from research.absorption_verifier import verify
from research.absorption_promotion import promote

def test_independent_verification_and_gate(tmp_path, monkeypatch):
    verify_out = tmp_path / "verify.json"
    promote_out = tmp_path / "promote.json"
    monkeypatch.setenv("AIOS_ABSORPTION_VERIFY_OUT", str(verify_out))
    monkeypatch.setenv("AIOS_ABSORPTION_PROMOTION_OUT", str(promote_out))
    data = {
        "run_id": "run-1",
        "records": [{
            "candidate_id": "cand-1",
            "source_ref": "https://github.com/example/agent",
            "source_digest": "src",
            "evidence_digest": "ev",
            "run_id": "run-1",
            "status": "RESEARCHED_ADAPTATION_PROPOSED",
            "evidence_status": "COLLECTED",
            "adaptation": {
                "external_code_copy": False,
                "external_code_execution": False,
                "target_surface": "new AIOS adapter/task only",
                "required_checks": [
                    "source_evidence_digest", "AIOS_conformance",
                    "independent_tests", "evidence_promotion_gate"
                ],
            },
        }],
    }
    v = verify(data, run_id="run-1")
    assert v["overall"] == "PASS"
    assert v["records"][0]["level"] == "VERIFIED_DIGITAL"
    p = promote(v)
    assert p["overall"] == "PASS"
    assert p["decisions"][0]["allowed"] is True
    assert p["decisions"][0]["action"] == "PROMOTE_TO_AIOS_REVIEW_QUEUE"

def test_verification_blocks_untrusted_record():
    data = {"run_id":"run-2","records":[{
        "candidate_id":"cand-2","source_ref":"https://github.com/example/x",
        "source_digest":"src","status":"HOLD","evidence_status":"ERROR",
        "adaptation":{"external_code_copy":False,"external_code_execution":False},
    }]}
    v = verify(data, run_id="run-2")
    assert v["overall"] == "BLOCKED"
    assert not v["records"]
