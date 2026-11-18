import hashlib
import json
import pytest
from core.evidence import EvidenceRecord, attest_evidence
from core.artifact_attestation import attest_artifact
from research.absorption_apply import absorb
import research.absorption_apply as apply_module
_REAL_AUTHORIZE_ABSORPTION_EFFECT = apply_module._authorize_absorption_effect


@pytest.fixture(autouse=True)
def _isolate_existing_apply_unit_tests(monkeypatch):
    # Existing tests exercise data lineage. Permit enforcement is covered by a
    # dedicated negative test below; production CLI always invokes the real guard.
    monkeypatch.setattr(apply_module, "_authorize_absorption_effect", lambda *a, **k: True)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _artifacts():
    run = "r1"
    source_digest, evidence_digest, test_digest = "a" * 64, "b" * 64, "c" * 64
    e = {"run_id": run, "records": [{"candidate_id": "c1", "run_id": run,
        "source_ref": "https://github.com/example/repo", "source_digest": source_digest,
        "evidence_digest": evidence_digest,
        "adaptation": {"primitive": "durable_execution", "signals": ["retry"],
                       "proposal": "p", "target_surface": "new AIOS adapter/task only"}}]}
    evidence = EvidenceRecord("c1", "VERIFIED_DIGITAL", e["records"][0]["source_ref"],
        "AIOS_NATIVE_ADAPTATION_PROPOSAL_CONFORMS", run, "AIOS_CONTROL_PLANE",
        source_digest=source_digest, evidence_digest=evidence_digest, test_digest=test_digest,
        candidate_digest=_digest(e["records"][0])).as_record()
    evidence["candidate_id"] = "c1"
    evidence["attestation"] = attest_evidence(evidence, "unit-test-evidence-secret-32")
    v = {"run_id": run, "overall": "PASS", "records": [evidence], "failures": [],
         "independent_tests": {"passed": True, "digest": test_digest}}
    v["digest"] = _digest({"verified": v["records"], "failures": v["failures"]})
    implementation, probes = {"overall": "PASS"}, {"runtime": True}
    runtime_digest = _digest({"implementation": implementation, "probes": probes})
    runtime = {"run_id": run, "overall": "PASS", "implementation": implementation,
               "probes": probes, "digest": runtime_digest,
               "attestation": attest_artifact("AIOS_ABSORPTION_RUNTIME_PROOF", run, runtime_digest,
                                              "unit-test-evidence-secret-32")}
    p = {"schema_version": 4, "kind": "AIOS_ABSORPTION_PROMOTION", "run_id": run,
         "input_verification_run_id": run, "input_verification_digest": v["digest"],
         "input_runtime_run_id": run, "input_runtime_digest": runtime["digest"],
         "decisions": [{"candidate_id": "c1", "run_id": run, "allowed": True, "verdict": "PROMOTE"}],
         "blocked": [], "overall": "PASS"}
    p["digest"] = _digest(p)
    p["attestation"] = attest_artifact("AIOS_ABSORPTION_PROMOTION", run, p["digest"],
                                       "unit-test-evidence-secret-32")
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
    v = {"run_id": run, "overall": "PASS", "records": [], "failures": []}
    v["digest"] = _digest({"verified": [], "failures": []})
    implementation, probes = {"overall": "PASS"}, {"runtime": True}
    runtime_digest = _digest({"implementation": implementation, "probes": probes})
    runtime = {"run_id": run, "overall": "PASS", "implementation": implementation,
               "probes": probes, "digest": runtime_digest,
               "attestation": attest_artifact("AIOS_ABSORPTION_RUNTIME_PROOF", run, runtime_digest,
                                              "unit-test-evidence-secret-32")}
    p = {"run_id": run, "overall": "PASS", "input_verification_digest": v["digest"],
         "input_runtime_digest": runtime["digest"],
         "decisions": [{"candidate_id": "c1", "run_id": run, "allowed": True, "verdict": "PROMOTE"}],
         "blocked": []}
    p["digest"] = _digest(p)
    p["attestation"] = attest_artifact("AIOS_ABSORPTION_PROMOTION", run, p["digest"],
                                       "unit-test-evidence-secret-32")
    r = absorb(e, v, p, runtime, run_id=run)
    assert r["overall"] == "BLOCKED" and r["absorbed_count"] == 0


def test_apply_rejects_same_run_source_digest_tampering():
    e, v, p, runtime = _artifacts()
    e["records"][0]["source_digest"] = "d" * 64
    result = absorb(e, v, p, runtime, run_id="r1")
    assert result["overall"] == "BLOCKED"
    assert result["absorbed_count"] == 0
    assert "source/evidence/test digest chain mismatch" in result["blocked"][0]["reason"]


def test_apply_revalidates_signed_evidence_after_promotion():
    e, v, p, runtime = _artifacts()
    v["records"][0]["source_digest"] = "d" * 64
    v["digest"] = _digest({"verified": v["records"], "failures": v["failures"]})
    p["input_verification_digest"] = v["digest"]
    p.pop("digest")
    p.pop("attestation")
    p["digest"] = _digest(p)
    p["attestation"] = attest_artifact("AIOS_ABSORPTION_PROMOTION", "r1", p["digest"],
                                       "unit-test-evidence-secret-32")
    result = absorb(e, v, p, runtime, run_id="r1")
    assert result["overall"] == "BLOCKED"
    assert result["absorbed_count"] == 0
    assert "source/evidence/test digest chain mismatch" in result["blocked"][0]["reason"]


def test_apply_rejects_tampered_promotion_artifact():
    e, v, p, runtime = _artifacts()
    p["decisions"][0]["allowed"] = False
    with pytest.raises(RuntimeError, match="promotion is not PASS or its content digest is invalid"):
        absorb(e, v, p, runtime, run_id="r1")


def test_apply_rejects_tampered_candidate_proposal():
    e, v, p, runtime = _artifacts()
    e["records"][0]["adaptation"]["proposal"] = "attacker-modified"
    result = absorb(e, v, p, runtime, run_id="r1")
    assert result["overall"] == "BLOCKED"
    assert result["absorbed_count"] == 0
    assert "source/evidence/test digest chain mismatch" in result["blocked"][0]["reason"]



def test_apply_fails_closed_when_ed25519_permit_is_missing(monkeypatch):
    e, v, p, runtime = _artifacts()
    with monkeypatch.context() as patch:
        patch.setattr(apply_module, "_authorize_absorption_effect",
                      _REAL_AUTHORIZE_ABSORPTION_EFFECT)
        patch.delenv("AIOS_ABSORPTION_PERMIT_PATH", raising=False)
        patch.delenv("AIOS_ABSORPTION_PERMIT_KEYRING_PATH", raising=False)
        result = absorb(e, v, p, runtime, run_id="r1")
    assert result["overall"] == "BLOCKED"
    assert result["absorbed_count"] == 0
    assert "Ed25519 permit enforcement denied effect" in result["blocked"][0]["reason"]
