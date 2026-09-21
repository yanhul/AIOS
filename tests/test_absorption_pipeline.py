import json
from pathlib import Path
from research.absorption_pipeline import build

def test_candidate_is_fail_closed(tmp_path, monkeypatch):
    out = tmp_path / "candidates.json"
    monkeypatch.setenv("AIOS_ABSORPTION_OUT", str(out))
    result = build({"records":[{
        "source_ref":"https://github.com/example/agent",
        "source_digest":"abc",
        "repo":"example/agent",
        "description":"durable agent research harness with provenance",
        "query":"agent research framework",
    }]})
    c = result["candidates"][0]
    assert c["status"] == "UNTRUSTED_EVIDENCE"
    assert c["mutation_authority"] == "AIOS"
    assert c["external_code_copy"] is False
    assert c["promotion_required"] is True
