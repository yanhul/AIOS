import pytest

from core.attestation import issue_attestation, verify_attestation
from core.contract import issue_permit


def contract():
    return {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": "RESEARCH_BC7",
        "scope": "research",
        "actor": "bc-controller",
        "capabilities": ["research_is_validation"],
        "input_digest": "sha256:input",
        "allowed_effects": ["persist_evidence"],
        "evidence_required": ["is_validation_report"],
        "max_attempts": 3,
        "terminal_states": ["PROMOTED", "REJECTED", "HOLD"],
        "policy_digest": "sha256:policy",
    }


def test_attestation_binds_external_permit():
    c = contract()
    p = issue_permit(c, "AIOS_AUTHORITY")
    a = issue_attestation(c, p, "test-secret-for-permit-attestation")
    assert verify_attestation(c, p, a, "test-secret-for-permit-attestation") is True

    forged = dict(a)
    forged["permit_id"] = "PT-forged"
    with pytest.raises(ValueError):
        verify_attestation(c, p, forged, "test-secret-for-permit-attestation")

    with pytest.raises(ValueError):
        verify_attestation(c, p, a, "wrong-secret")


def test_attestation_rejects_short_signing_secret():
    c = contract()
    p = issue_permit(c, "AIOS_AUTHORITY")
    with pytest.raises(ValueError, match="at least 16 characters"):
        issue_attestation(c, p, "short")
