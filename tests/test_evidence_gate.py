from core.evidence_gate import gate_promotion


def test_advisory_cannot_promote():
    result = gate_promotion({"level": "ADVISORY", "run_id": "r", "source_ref": "s", "claim": "EDGE_FOUND"})
    assert not result.allowed


def test_unknown_cannot_promote():
    result = gate_promotion({"level": "UNKNOWN", "run_id": "r", "source_ref": "s", "claim": "EDGE_FOUND"})
    assert not result.allowed


def test_verified_digital_can_pass_gate():
    result = gate_promotion({"level": "VERIFIED_DIGITAL", "run_id": "r", "source_ref": "s", "claim": "EDGE_FOUND"})
    assert result.allowed


def test_missing_provenance_fails_closed():
    result = gate_promotion({"level": "VERIFIED_DIGITAL", "run_id": "r"})
    assert not result.allowed
