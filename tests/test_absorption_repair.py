from research.absorption_repair import run


def test_repair_no_failures_passes_only_for_current_verified_run():
    r = run({"run_id": "test", "overall": "PASS", "failures": []}, run_id="test")
    assert r["overall"] == "PASS" and r["obligation_count"] == 0


def test_repair_blocks_stale_or_missing_verification():
    r = run({"run_id": "old", "overall": "PASS", "failures": []}, run_id="current")
    assert r["overall"] == "BLOCKED"
    assert r["obligation_count"] == 1


def test_repair_budget_is_bounded(monkeypatch):
    monkeypatch.setattr("research.absorption_repair._tests", lambda: (False, "digest"))
    monkeypatch.setattr("research.absorption_repair.MAX_ATTEMPTS", 2)
    r = run({"run_id": "test", "overall": "PASS",
             "failures": [{"candidate_id": "c1", "errors": ["x"]}]}, run_id="test")
    assert r["overall"] == "BLOCKED"
    assert r["obligations"][0]["attempts"] == 2
    assert r["obligations"][0]["status"] == "BLOCKED_BUDGET_EXHAUSTED"
