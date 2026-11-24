"""AIOS-only Ed25519 signer for one exact Harness Gateway retry attempt."""
from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Mapping

from .mutation import canonical_json

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # no signing fallback; Gateway retry remains disabled
    serialization = Ed25519PrivateKey = None

PERMIT_TYPE = "AIOS_GATEWAY_RETRY_PERMIT_V1"
PERMIT_FIELDS = (
    "type", "permit_id", "key_id", "algorithm", "effect_id", "contract_id", "authority_ref",
    "actor", "issuer", "retry_authorization_id", "ticket_id", "target_sha",
    "prior_gateway_attempt_id", "prior_fence", "prior_gateway_receipt_digest",
    "operation_receipt_digest", "reconciliation_evidence_digest", "reconciliation_outcome",
    "decision_id", "next_attempt_number", "next_attempt_id", "next_fence", "nonce",
    "issued_at", "expires_at",
)


class GatewayRetryPermitSigner:
    """Deployment-held Ed25519 private key; only the public key goes to Gateway."""

    def __init__(self, private_key, key_id=None):
        if Ed25519PrivateKey is None or not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("Ed25519 private key unavailable")
        self._private_key = private_key
        raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_key_hex = raw.hex()
        expected_id = "ed25519:" + hashlib.sha256(raw).hexdigest()[:32]
        if key_id is not None and key_id != expected_id:
            raise ValueError("Gateway retry permit key_id does not match private key")
        self.key_id = expected_id

    @classmethod
    def from_env(cls, environ=None):
        env = os.environ if environ is None else environ
        path = env.get("AIOS_GATEWAY_RETRY_PRIVATE_KEY_FILE", "")
        if not path:
            raise ValueError("AIOS_GATEWAY_RETRY_PRIVATE_KEY_FILE is not configured")
        if serialization is None:
            raise ValueError("cryptography Ed25519 support unavailable")
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode & 0o077:
            raise ValueError("AIOS Gateway retry private-key file must not be group/world accessible")
        with open(path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
        return cls(key)

    def verify(self, permit: Mapping[str, object]) -> bool:
        if not isinstance(permit, Mapping) or set(permit) != set(PERMIT_FIELDS) | {"signature"}:
            return False
        body = {key: permit[key] for key in PERMIT_FIELDS}
        if body.get("key_id") != self.key_id or body.get("algorithm") != "Ed25519" or body.get("type") != PERMIT_TYPE:
            return False
        try:
            self._private_key.public_key().verify(bytes.fromhex(permit["signature"]), canonical_json(body).encode("utf-8"))
        except Exception:
            return False
        return True

    def sign(self, fields: Mapping[str, object]) -> dict:
        if not isinstance(fields, Mapping) or set(fields) != set(PERMIT_FIELDS) - {"key_id", "type", "algorithm", "permit_id"}:
            raise ValueError("Gateway retry permit fields mismatch")
        body = {"type": PERMIT_TYPE, "permit_id": "GRP-" + __import__("secrets").token_hex(16),
                "key_id": self.key_id, "algorithm": "Ed25519", **dict(fields)}
        signature = self._private_key.sign(canonical_json(body).encode("utf-8")).hex()
        return {**body, "signature": signature}


__all__ = ["GatewayRetryPermitSigner", "PERMIT_TYPE", "PERMIT_FIELDS"]
