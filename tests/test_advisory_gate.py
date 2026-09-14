import pytest

from core.advisory_gate import AdvisoryFinding, authorize_promotion


def finding():
    return AdvisoryFinding("f1", "candidate edge", "analysis:1", "gemini", "run-1")


def evidence():
    return {
        "evidence_id": "e1",
        "level": "VERIFIED_DIGITAL",
        "run_id": "run-1",
        "provider": "gemini",
        "claim": "candidate edge",
        "digest": "external-verified-digest",
    }


def test_advisory_cannot_directly_promote_edge():
    with pytest.raises(PermissionError):
        authorize_promotion(finding(), evidence(), "EDGE_FOUND")


def test_advisory_requires_evidence():
    with pytest.raises(PermissionError):
        authorize_promotion(finding(), None, "NEXT_STEP")


def test_evidence_must_bind_to_run_and_provider():
    bad = dict(evidence(), provider="other")
    with pytest.raises(PermissionError):
        authorize_promotion(finding(), bad, "NEXT_STEP")


def test_bound_evidence_can_pass_advisory_boundary():
    authorize_promotion(finding(), evidence(), "NEXT_STEP")
