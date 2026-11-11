# AIOS-CONTRACT: Source review evidence must be tied to immutable source bytes and an explicit accepted review manifest.
# AIOS-REGRESSION: A missing review, mutable ref, invalid path, or unverifiable commit must never create source_review.
# AIOS-OWNER: research.absorption_source_review / source provenance intake.
# AIOS-COVERAGE-GAP: The executor previously fetched README text but did not collect candidate-specific source file hashes.
# AIOS-BASELINE: Source review is now explicit and fail-closed; the collector does not invent reviewer approval or authority receipts.
import json
from research.absorption_source_review import collect

def _executor():
    return {"run_id":"run-1","overall":"PASS","records":[{
        "candidate_id":"cand-1","source_ref":"https://github.com/example/agent",
        "source_digest":"metadata","run_id":"run-1",
        "adaptation":{"primitive":"durable_execution"}
    }]}

def _manifest():
    return {"reviews":[{
        "candidate_id":"cand-1","source_commit":"a"*40,"reviewer":"reviewer-1",
        "reviewed_at":"2026-10-29T00:00:00Z","review_decision":"ACCEPTED",
        "candidate_primitive":"durable_execution","reviewed_files":["src/agent.py"],
        "implementation_refs":["core/durable_runtime.py"],
        "candidate_test_refs":["tests/test_absorption_executor.py"],
        "log_digest":"d"*64,
        "authority_receipt_lineage":{"effect_id":"effect-1","attempt_id":"attempt-1",
            "receipt_id":"receipt-1","evidence_digest":"e"*64}
    }]}

def test_source_review_collector_hashes_exact_commit_files(tmp_path, monkeypatch):
    executor_path=tmp_path/"executor.json"
    out_path=tmp_path/"source-review.json"
    monkeypatch.setenv("AIOS_ABSORPTION_EXECUTOR_OUT",str(executor_path))
    monkeypatch.setenv("AIOS_ABSORPTION_SOURCE_REVIEW_OUT",str(out_path))
    def fetch(url):
        if "/commits/" in url:
            return json.dumps({"sha":"a"*40}).encode()
        return b"reviewed-source-bytes"
    result=collect(_executor(),_manifest(),fetch=fetch)
    saved=json.loads(executor_path.read_text())
    review=saved["records"][0]["source_review"]
    assert result["overall"]=="PASS"
    assert review["source_commit"]=="a"*40
    assert review["reviewed_files"][0]["sha256"]
    assert review["source_code_digest"]
    assert review["conformance_run_id"]=="run-1"

def test_source_review_collector_blocks_unapproved_or_unverifiable_source(tmp_path, monkeypatch):
    executor_path=tmp_path/"executor.json"
    monkeypatch.setenv("AIOS_ABSORPTION_EXECUTOR_OUT",str(executor_path))
    manifest=_manifest()
    manifest["reviews"][0]["review_decision"]="PENDING"
    result=collect(_executor(),manifest,fetch=lambda url:b"{}")
    saved=json.loads(executor_path.read_text())
    assert result["overall"]=="BLOCKED"
    assert "source_review" not in saved["records"][0]
