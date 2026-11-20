import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.retry_issuer import (
    SCHEMA, RetryAuthorizationRejected, RetryIssuerKeyring,
    canonical_payload, effect_state_digest,
)


def fixture():
    private = Ed25519PrivateKey.generate()
    public_hex = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    key_id = "retry-ed25519:" + hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:32]
    effect = {
        "effect_id": "EF-retry-1", "contract_id": "CT-1", "permit_id": "PM-1",
        "actor": "worker", "provider": "provider-a",
        "attempt_id": "EF-retry-1:attempt:1", "attempt": 1,
        "state": "UNKNOWN", "revision": 2, "policy_digest": "a" * 64,
    }
    attempt = {
        "effect_id": effect["effect_id"], "attempt_id": effect["attempt_id"],
        "state": "UNKNOWN",
    }
    payload = {
        "schema": SCHEMA, "issuer_id": "independent-retry-issuer", "key_id": key_id,
        "effect_id": effect["effect_id"], "contract_id": effect["contract_id"],
        "permit_id": effect["permit_id"], "actor": effect["actor"],
        "provider": effect["provider"], "attempt_id": effect["attempt_id"],
        "attempt_number": 1, "state": "UNKNOWN", "state_revision": 2,
        "state_digest": effect_state_digest(effect), "not_applied_proof_digest": "b" * 64,
        "nonce": "nonce-unique-00000001", "issued_at": 100.0, "expires_at": 200.0,
        "policy_digest": effect["policy_digest"],
    }
    auth = dict(payload, signature=private.sign(canonical_payload(payload)).hex())
    keyring = RetryIssuerKeyring({"independent-retry-issuer": {
        "key_id": key_id, "public_key": public_hex, "revoked": False,
    }})
    return auth, keyring, effect, attempt


def verify(auth, keyring, effect, attempt, proof=True, now=150):
    return keyring.verify(
        auth, now=now, effect=effect, attempt=attempt,
        not_applied_verifier=lambda **_kwargs: proof,
    )


def test_valid_independent_retry_authorization_verifies():
    auth, keyring, effect, attempt = fixture()
    claims = verify(auth, keyring, effect, attempt)
    assert claims["state"] == "UNKNOWN"
    assert claims["not_applied_proof_digest"] == "b" * 64


@pytest.mark.parametrize("field,value", [
    ("effect_id", "EF-other"), ("attempt_id", "EF-retry-1:attempt:2"),
    ("permit_id", "PM-other"), ("state_revision", 99),
    ("state_digest", "0" * 64), ("not_applied_proof_digest", "0" * 64),
])
def test_tampered_or_cross_bound_claims_rejected(field, value):
    auth, keyring, effect, attempt = fixture()
    auth[field] = value
    with pytest.raises(RetryAuthorizationRejected):
        verify(auth, keyring, effect, attempt)


def test_signature_tampering_rejected():
    auth, keyring, effect, attempt = fixture()
    auth["signature"] = "0" * 128
    with pytest.raises(RetryAuthorizationRejected):
        verify(auth, keyring, effect, attempt)


def test_expired_authorization_rejected():
    auth, keyring, effect, attempt = fixture()
    with pytest.raises(RetryAuthorizationRejected, match="expired"):
        verify(auth, keyring, effect, attempt, now=201)


def test_revoked_issuer_key_rejected():
    auth, _keyring, effect, attempt = fixture()
    public_hex = "00" * 32
    key_id = "retry-ed25519:" + hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:32]
    keyring = RetryIssuerKeyring({"independent-retry-issuer": {
        "key_id": key_id, "public_key": public_hex, "revoked": True,
    }})
    with pytest.raises(RetryAuthorizationRejected, match="revoked"):
        verify(auth, keyring, effect, attempt)


def test_missing_or_inconclusive_not_applied_proof_rejected():
    auth, keyring, effect, attempt = fixture()
    with pytest.raises(RetryAuthorizationRejected, match="NOT_APPLIED"):
        verify(auth, keyring, effect, attempt, proof=False)


def test_unknown_is_required_and_attempt_must_match():
    auth, keyring, effect, attempt = fixture()
    effect["state"] = "DISPATCHED"
    with pytest.raises(RetryAuthorizationRejected):
        verify(auth, keyring, effect, attempt)
