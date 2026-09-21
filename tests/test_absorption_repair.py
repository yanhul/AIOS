from research.absorption_repair import run

def test_repair_no_failures_passes():
    r=run({"failures":[]},run_id="test")
    assert r["overall"]=="PASS" and r["obligation_count"]==0

def test_repair_budget_is_bounded(monkeypatch):
    monkeypatch.setattr("research.absorption_repair._tests",lambda:(False,"digest"))
    monkeypatch.setattr("research.absorption_repair.MAX_ATTEMPTS",2)
    r=run({"failures":[{"candidate_id":"c1","errors":["x"]}]},run_id="test")
    assert r["overall"]=="BLOCKED"
    assert r["obligations"][0]["attempts"]==2
    assert r["obligations"][0]["status"]=="BLOCKED_BUDGET_EXHAUSTED"
