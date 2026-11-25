import base64
import time
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from core.mutation import canonical_json
from core.algorithm_worker_receipt import (
    AlgorithmWorkerKeyring, AlgorithmWorkerReceiptError, RECEIPT_ISSUER,
    RECEIPT_SCOPE, SIGNED_FIELDS, verify_algorithm_worker_receipt,
)


def setup(revoked=False):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keyring = AlgorithmWorkerKeyring({RECEIPT_ISSUER: {
        "public_key": base64.b64encode(public).decode("ascii"),
        "key_id": "algorithm-worker-test-v1", "scopes": [RECEIPT_SCOPE], "revoked": revoked,
    }})
    expected = {
        "contract_id": "CT-1", "permit_id": "PM-1", "execution_id": "EX-1", "effect_id": "EF-1", "dispatch_id": "DP-1",
        "dispatch_digest": "8" * 64, "attempt_id": "EX-1:attempt:1", "attempt_number": 1,
        "worker_id": "try-worker-prod-a", "worker_build_sha256": "a" * 64,
        "executor_revision": "b" * 40, "executor_sha256": "c" * 64,
        "spec_sha256": "d" * 64, "input_sha256": "e" * 64,
    }
    return private, keyring, expected


def sign_receipt(private, expected, status="COMPLETED", **changes):
    now = time.time()
    body = {
        "type": "TRY_ALGORITHM_EXECUTION_RECEIPT_V1", "issuer": RECEIPT_ISSUER,
        "key_id": "algorithm-worker-test-v1", "receipt_id": "TA-" + "1" * 32,
        **expected, "artifact_sha256": "f" * 64 if status == "COMPLETED" else None,
        "output_sha256": "9" * 64 if status == "COMPLETED" else None,
        "status": status,
        "execution_state": "COMPLETED" if status == "COMPLETED" else "IN_PROGRESS_OR_AMBIGUOUS",
        "issued_at": now, "expires_at": now + 300, "algorithm": "Ed25519",
    }
    body.update(changes)
    signed = {field: body[field] for field in SIGNED_FIELDS}
    body["signature"] = base64.b64encode(private.sign(canonical_json(signed).encode("utf-8"))).decode("ascii")
    return body


def test_valid_completed_receipt_authenticates_exact_attempt_without_authority():
    private, keyring, expected = setup()
    result = verify_algorithm_worker_receipt(sign_receipt(private, expected), expected=expected, keyring=keyring)
    assert result["status"] == "INDEPENDENTLY_AUTHENTICATED"
    assert result["worker_id"] == expected["worker_id"]
    assert result["retry_authorized"] is False
    assert result["promotion"] == "NOT_AUTHORIZED"


def test_unknown_is_accepted_as_ambiguous_but_never_retryable():
    private, keyring, expected = setup()
    result = verify_algorithm_worker_receipt(sign_receipt(private, expected, status="UNKNOWN"), expected=expected, keyring=keyring)
    assert result["status"] == "UNKNOWN"
    assert result["retry_authorized"] is False


def test_wrong_attempt_or_worker_binding_fails():
    private, keyring, expected = setup()
    receipt = sign_receipt(private, expected)
    with pytest.raises(AlgorithmWorkerReceiptError, match="attempt_number binding mismatch"):
        verify_algorithm_worker_receipt(receipt, expected=dict(expected, attempt_number=2), keyring=keyring)
    with pytest.raises(AlgorithmWorkerReceiptError, match="worker_id binding mismatch"):
        verify_algorithm_worker_receipt(receipt, expected=dict(expected, worker_id="untrusted"), keyring=keyring)


def test_tampering_and_revoked_key_fail_closed():
    private, keyring, expected = setup()
    receipt = sign_receipt(private, expected)
    receipt["output_sha256"] = "0" * 64
    with pytest.raises(AlgorithmWorkerReceiptError, match="signature is invalid"):
        verify_algorithm_worker_receipt(receipt, expected=expected, keyring=keyring)
    _, revoked, expected = setup(revoked=True)
    with pytest.raises(AlgorithmWorkerReceiptError, match="unavailable or revoked"):
        verify_algorithm_worker_receipt(sign_receipt(private, expected), expected=expected, keyring=revoked)


def test_expired_receipt_and_input_mismatch_fail():
    private, keyring, expected = setup()
    expired = sign_receipt(private, expected, issued_at=time.time() - 600, expires_at=time.time() - 1)
    with pytest.raises(AlgorithmWorkerReceiptError, match="expired"):
        verify_algorithm_worker_receipt(expired, expected=expected, keyring=keyring)
    with pytest.raises(AlgorithmWorkerReceiptError, match="input_sha256 binding mismatch"):
        verify_algorithm_worker_receipt(sign_receipt(private, expected), expected=dict(expected, input_sha256="0" * 64), keyring=keyring)


def test_unknown_cannot_claim_completed_artifacts():
    private, keyring, expected = setup()
    bad = sign_receipt(private, expected, status="UNKNOWN", artifact_sha256="f" * 64)
    with pytest.raises(AlgorithmWorkerReceiptError, match="UNKNOWN receipt"):
        verify_algorithm_worker_receipt(bad, expected=expected, keyring=keyring)


def test_unrecognized_status_is_rejected():
    private, keyring, expected = setup()
    bad = sign_receipt(private, expected)
    bad["status"] = "FAILED"
    with pytest.raises(AlgorithmWorkerReceiptError, match="receipt status is invalid"):
        verify_algorithm_worker_receipt(bad, expected=expected, keyring=keyring)
