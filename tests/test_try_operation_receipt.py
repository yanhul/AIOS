import hashlib
import hmac
import json
import time

import pytest

from core.try_operation_receipt import (
    TryOperationReceiptError, TryOperationReceiptKeyring, SIGNED_FIELDS,
    verify_try_operation_receipt,
)

SECRET = "try-operation-receipt-secret-for-adversarial-tests"
KEY_ID = "try-op-test-v1"


def _keyring(revoked=False):
    return TryOperationReceiptKeyring({"try.repair": {
        "key_id": KEY_ID, "secret": SECRET,
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
        "issued_at": now, "expires_at": now + 300, "algorithm": "HMAC-SHA256",
    }
    body.update(changes)
    signed = {key: body[key] for key in SIGNED_FIELDS}
    body["signature"] = hmac.new(SECRET.encode(), json.dumps(
        signed, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode(), hashlib.sha256).hexdigest()
    return body


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
    receipt["signature"] = "0" * 64
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
