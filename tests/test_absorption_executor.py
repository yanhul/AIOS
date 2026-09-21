from research.absorption_executor import execute

def test_executor_is_fail_closed(tmp_path,monkeypatch):
    monkeypatch.setenv("AIOS_ABSORPTION_EXECUTOR_OUT",str(tmp_path/"e.json"))
    monkeypatch.setattr("research.absorption_executor._get",lambda url:"# durable provenance research\n")
    r=execute([{"candidate_id":"cand-1","source_ref":"https://github.com/example/agent","source_digest":"abc","primitive":"durable_execution"}],run_id="run-1")["records"][0]
    assert r["evidence_status"]=="COLLECTED"
    assert r["status"]=="RESEARCHED_ADAPTATION_PROPOSED"
    assert r["adaptation"]["external_code_copy"] is False
    assert r["adaptation"]["external_code_execution"] is False
    assert r["promotion"]=="REQUIRES_INDEPENDENT_RESEARCH_AND_EVIDENCE_GATE"

def test_executor_holds_on_fetch_failure(monkeypatch):
    monkeypatch.setattr("research.absorption_executor._get",lambda url: (_ for _ in ()).throw(RuntimeError("network")))
    r=execute([{"candidate_id":"cand-1","source_ref":"https://github.com/example/agent","source_digest":"abc","primitive":"agent_harness"}],run_id="run-2")["records"][0]
    assert r["status"]=="HOLD" and r["evidence_status"]=="ERROR"
