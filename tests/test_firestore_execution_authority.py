"""Execution-path tests for the Firestore authority resolver integration."""
from unittest.mock import Mock, patch

import pytest

from core.contract import contract_identity
from core.firestore_execution import _authorized_context


class Adapter:
    name = "ci-test-provider"


def _contract():
    return {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": "task-ci",
        "scope": "test-only",
        "actor": "ci-issuer",
        "capabilities": ["test-capability@1.0.0"],
        "input_digest": "a" * 64,
        "allowed_effects": ["external_effect"],
        "evidence_required": ["signed-receipt"],
        "max_attempts": 1,
        "terminal_states": ["OBSERVED_SUCCESS", "OBSERVED_FAILURE"],
        "policy_digest": "b" * 64,
    }


def _digests():
    return {
        "contract_digest": "1" * 64,
        "permit_digest": "2" * 64,
        "attestation_digest": "3" * 64,
        "policy_digest": "4" * 64,
        "capability_digests": {"test-capability@1.0.0": "5" * 64},
    }


def test_execution_authorizes_from_verified_firestore_bundle_without_filesystem():
    contract = _contract()
    permit = {"permit_id": "PT-ci", "actor": "ci-issuer"}
    resolver = Mock()
    resolver.resolve.return_value = {
        "contract": contract,
        "permit": permit,
        "authority_backend": "firestore-ed25519",
    }

    with patch("core.firestore_execution.authorize", side_effect=AssertionError("filesystem authority used")), \
         patch("core.firestore_execution.load_contract", side_effect=AssertionError("filesystem contract used")), \
         patch("core.firestore_execution.load_permit", side_effect=AssertionError("filesystem permit used")), \
         patch("core.firestore_execution._provider_authorized", return_value=True):
        resolved, provider = _authorized_context(
            "/unused", contract_identity(contract), "PT-ci", "ci-issuer", Adapter(),
            authority_resolver=resolver, authority_digests=_digests(),
        )

    assert resolved == contract
    assert provider == "ci-test-provider"
    resolver.resolve.assert_called_once_with(**_digests())


def test_execution_rejects_firestore_contract_identity_mismatch():
    contract = _contract()
    resolver = Mock()
    resolver.resolve.return_value = {
        "contract": contract,
        "permit": {"permit_id": "PT-ci", "actor": "ci-issuer"},
        "authority_backend": "firestore-ed25519",
    }
    with pytest.raises(PermissionError, match="contract identity"):
        _authorized_context(
            "/unused", "CT-wrong", "PT-ci", "ci-issuer", Adapter(),
            authority_resolver=resolver, authority_digests=_digests(),
        )


def test_execution_rejects_incomplete_firestore_digest_bundle():
    with pytest.raises(PermissionError, match="complete Firestore authority digest bundle"):
        _authorized_context(
            "/unused", "CT-any", "PT-any", "ci-issuer", Adapter(),
            authority_resolver=Mock(), authority_digests={"contract_digest": "1" * 64},
        )
