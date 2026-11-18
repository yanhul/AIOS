import os
from core.evidence import EvidenceRecord, attest_evidence
from core.evidence_gate import gate_promotion


def _signed(level="VERIFIED_DIGITAL"):
    record = EvidenceRecord("ev-1", level, "source://one", "EDGE_FOUND", "run-1", "AIOS_CONTROL_PLANE").as_record()
    record["attestation"] = attest_evidence(record, os.environ["AIOS_EVIDENCE_SIGNING_SECRET"])
    return record


def test_advisory_cannot_promote():
    result = gate_promotion({"level": "ADVISORY", "run_id": "r", "source_ref": "s", "claim": "EDGE_FOUND"})
    assert not result.allowed


def test_unknown_cannot_promote():
    result = gate_promotion({"level": "UNKNOWN", "run_id": "r", "source_ref": "s", "claim": "EDGE_FOUND"})
    assert not result.allowed


def test_self_declared_verified_level_cannot_promote():
    record = {"level": "VERIFIED_DIGITAL", "run_id": "r", "source_ref": "s", "claim": "EDGE_FOUND"}
    result = gate_promotion(record)
    assert not result.allowed
    assert "attestation" in result.reason


def test_trusted_verified_digital_can_pass_gate():
    result = gate_promotion(_signed())
    assert result.allowed


def test_tampered_level_invalidates_attestation():
    record = _signed()
    record["level"] = "PROMOTED"
    assert not gate_promotion(record).allowed


def test_missing_provenance_fails_closed():
    result = gate_promotion({"level": "VERIFIED_DIGITAL", "run_id": "r"})
    assert not result.allowed


def test_tampered_source_digest_invalidates_attestation():
    record = _signed()
    record["source_digest"] = "a" * 64
    assert not gate_promotion(record).allowed
