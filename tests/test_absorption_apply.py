import pytest
from research.absorption_apply import absorb


def _artifacts():
    run = "r1"
    e = {"run_id": run, "records": [{"candidate_id": "c1", "run_id": run,
        "source_ref": "s", "source_digest": "sd", "evidence_digest": "ed",
        "adaptation": {"primitive": "durable_execution", "signals": ["retry"],
                       "proposal": "p", "target_surface": "new AIOS adapter/task only"}}]}
    v = {"run_id": run, "overall": "PASS", "records": [{"candidate_id": "c1", "run_id": run,
        "claim": "AIOS_NATIVE_ADAPTATION_PROPOSAL_CONFORMS", "test_digest": "td"}]}
    p = {"run_id": run, "overall": "PASS",
         "decisions": [{"candidate_id": "c1", "run_id": run, "allowed": True, "verdict": "PROMOTE"}],
         "blocked": []}
    runtime = {"run_id": run, "overall": "PASS", "digest": "runtime"}
    return e, v, p, runtime


def test_absorb_requires_current_run_promotion_and_verification():
    r = absorb(*_artifacts(), run_id="r1")
    assert r["overall"] == "PASS" and r["absorbed_count"] == 1
    assert r["records"][0]["status"] == "ABSORBED"
    assert r["records"][0]["source_mutation"] is False


def test_absorb_rejects_stale_artifact_run_id():
    e, v, p, runtime = _artifacts()
    runtime["run_id"] = "old-run"
    with pytest.raises(RuntimeError, match="runtime artifact run_id"):
        absorb(e, v, p, runtime, run_id="r1")


def test_absorb_blocks_missing_candidate_lineage():
    run = "r2"
    e = {"run_id": run, "records": []}
    v = {"run_id": run, "overall": "PASS", "records": []}
    p = {"run_id": run, "overall": "PASS",
         "decisions": [{"candidate_id": "c1", "run_id": run, "allowed": True, "verdict": "PROMOTE"}],
         "blocked": []}
    runtime = {"run_id": run, "overall": "PASS", "digest": "runtime"}
    r = absorb(e, v, p, runtime, run_id=run)
    assert r["overall"] == "BLOCKED" and r["absorbed_count"] == 0
