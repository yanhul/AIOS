import hashlib
import json
import base64
import time

import pytest

from tests.try_operation_receipt_fixtures import PUBLIC_KEY_B64, sign_receipt

from core.try_operation_receipt import (
    TryOperationReceiptError, TryOperationReceiptKeyring, SIGNED_FIELDS,
    verify_try_operation_receipt,
)

KEY_ID = "try-op-test-v1"


def _keyring(revoked=False):
    return TryOperationReceiptKeyring({"try.repair": {
        "key_id": KEY_ID, "public_key": PUBLIC_KEY_B64,
        "scopes": ["try.operation.receipt.verify"], "revoked": revoked,
    }})


def _receipt(status="FAILED", **changes):
    now = time.time()
    body = {
        "type": "TRY_PROPOSAL_OPERATION_RECEIPT_V1", "issuer": "try.repair",
        "key_id": KEY_ID, "receipt_id": "TR-" + "a" * 32,
        "request_id": "EF-1:attempt:1", "request_digest": "b" * 64,
        "repository": "yanhul/AIOS", "sha": "c" * 40, "attempt": 1,
        "status": status,
        "execution_state": "NOT_SUBMITTED" if status == "FAILED" else (
            "COMPLETED" if status == "COMPLETED" else "IN_PROGRESS_OR_AMBIGUOUS"),
        "failure_code": "provider_not_configured" if status == "FAILED" else None,
        "proposal_digest": "d" * 64 if status == "COMPLETED" else None,
        "issued_at": now, "expires_at": now + 300, "algorithm": "Ed25519",
    }
    body.update(changes)
    return sign_receipt(body, SIGNED_FIELDS)


def _verify(receipt, keyring=None, **changes):
    expected = {
        "request_id": "EF-1:attempt:1", "request_digest": "b" * 64,
        "repository": "yanhul/AIOS", "sha": "c" * 40, "attempt": 1,
    }
    expected.update(changes)
    return verify_try_operation_receipt(receipt, keyring=keyring or _keyring(), **expected)


def test_verified_pre_submission_failure_is_the_only_retry_eligible_operation_state():
    result = _verify(_receipt())
    assert result["status"] == "FAILED"
    assert result["execution_state"] == "NOT_SUBMITTED"
    assert result["proven_not_submitted"] is True
    assert len(result["receipt_digest"]) == 64


def test_unknown_receipt_never_proves_non_submission():
    result = _verify(_receipt("UNKNOWN"))
    assert result["status"] == "UNKNOWN"
    assert result["proven_not_submitted"] is False


def test_provider_http_failure_cannot_be_relabelled_as_pre_submission_failure():
    receipt = _receipt(failure_code="gemini_http_429")
    with pytest.raises(TryOperationReceiptError, match="does not prove pre-submission"):
        _verify(receipt)


def test_signature_tampering_and_key_id_substitution_fail_closed():
    receipt = _receipt()
    receipt["signature"] = base64.b64encode(b"0" * 64).decode("ascii")
    with pytest.raises(TryOperationReceiptError, match="signature is invalid"):
        _verify(receipt)
    receipt = _receipt(key_id="untrusted-key")
    with pytest.raises(TryOperationReceiptError, match="key_id is not pinned"):
        _verify(receipt)


@pytest.mark.parametrize("field,value", [
    ("request_id", "EF-OTHER:attempt:1"),
    ("request_digest", "e" * 64),
    ("repository", "attacker/repo"),
    ("sha", "f" * 40),
    ("attempt", 2),
])
def test_operation_receipt_must_bind_exact_request_and_attempt(field, value):
    with pytest.raises(TryOperationReceiptError, match=field + " binding mismatch"):
        _verify(_receipt(), **{field: value})


def test_expired_or_revoked_receipt_trust_is_rejected():
    expired = _receipt(expires_at=time.time() - 1, issued_at=time.time() - 600)
    with pytest.raises(TryOperationReceiptError, match="expired or issued in the future"):
        _verify(expired)
    with pytest.raises(TryOperationReceiptError, match="unavailable or revoked"):
        _verify(_receipt(), keyring=_keyring(revoked=True))


def test_hmac_downgrade_is_rejected_even_with_a_valid_ed25519_key():
    receipt = _receipt()
    receipt["algorithm"] = "HMAC-SHA256"
    with pytest.raises(TryOperationReceiptError, match="identity/signature is malformed"):
        _verify(receipt)


def test_shared_secret_only_keyring_is_rejected():
    with pytest.raises(ValueError, match="key entry is malformed"):
        TryOperationReceiptKeyring({"try.repair": {
            "key_id": KEY_ID, "secret": "legacy-shared-secret-that-must-not-be-used",
            "scopes": ["try.operation.receipt.verify"], "revoked": False,
        }})
