from research.absorption_pipeline import build,verify
def test_candidate_is_fail_closed(tmp_path,monkeypatch):
 monkeypatch.setenv("AIOS_ABSORPTION_OUT",str(tmp_path/"c.json"));c=build({"records":[{"source_ref":"https://github.com/example/agent","source_digest":"abc","repo":"example/agent","description":"durable agent research harness with provenance","query":"agent research framework"}]})["candidates"][0]
 assert c["status"]=="UNTRUSTED_EVIDENCE" and c["mutation_authority"]=="AIOS" and c["external_code_copy"] is False and c["promotion_required"] is True
def test_verification_is_non_authoritative(tmp_path,monkeypatch):
 monkeypatch.setenv("AIOS_ABSORPTION_VERIFY",str(tmp_path/"v.json"));r=verify([{"candidate_id":"cand-1","source_ref":"https://github.com/example/agent","source_digest":"abc","primitive":"durable_execution"}],run_id="intake-1")["records"][0]
 assert r["level"]=="ADVISORY" and r["status"]=="UNTRUSTED_EVIDENCE" and r["authority"]=="AIOS_CONTROL_PLANE"
 assert r["source_digest"]=="abc" and r["promotion"]=="REQUIRES_INDEPENDENT_RESEARCH_AND_EVIDENCE_GATE" and r["run_id"]=="intake-1"
