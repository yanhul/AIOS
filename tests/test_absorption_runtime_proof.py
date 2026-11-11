# AIOS-CONTRACT: Generic runtime probes must not imply candidate absorption.
# AIOS-REGRESSION: Stale legacy verification artifacts cannot be accepted as candidate-specific proof.
# AIOS-OWNER: research.absorption_runtime_proof / candidate runtime proof boundary.
# AIOS-COVERAGE-GAP: The runtime probe previously ignored stale candidate records lacking source/test/receipt lineage.
# AIOS-BASELINE: Generic four-probe PASS is retained only as a generic proof, with no candidate promotion implied.
import json
from research.absorption_runtime_proof import run

def test_absorption_runtime_proof_is_generic_only_without_verified_candidates(tmp_path, monkeypatch):
    verification = tmp_path / "verification.json"
    verification.write_text(json.dumps({"overall": "BLOCKED", "records": []}), encoding="utf-8")
    monkeypatch.setenv("AIOS_ABSORPTION_VERIFY_IN", str(verification))
    monkeypatch.setenv("AIOS_ABSORPTION_RUNTIME_PROOF_OUT", str(tmp_path / "runtime.json"))
    result = run()
    assert result["overall"] == "PASS"
    assert result["passed_count"] == result["total_count"] == 4
    assert result["candidate_proofs"] == []

def test_legacy_candidate_records_do_not_receive_candidate_runtime_proof(tmp_path, monkeypatch):
    verification = tmp_path / "verification.json"
    verification.write_text(json.dumps({"overall": "PASS", "records": [
        {"candidate_id": "legacy", "source_commit": "", "test_digest": "old",
         "candidate_test_refs": [], "implementation_refs": []}
    ]}), encoding="utf-8")
    monkeypatch.setenv("AIOS_ABSORPTION_VERIFY_IN", str(verification))
    monkeypatch.setenv("AIOS_ABSORPTION_RUNTIME_PROOF_OUT", str(tmp_path / "runtime.json"))
    result = run()
    assert result["overall"] == "BLOCKED"
    assert result["candidate_proofs"][0]["status"] == "BLOCKED"
