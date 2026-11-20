"""Independent Ed25519 retry authorization verification.

AIOS is verifier-only: this module accepts pinned public keys and never
creates, loads, or exports an issuer private key.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # fail closed
    InvalidSignature = Exception
    Ed25519PublicKey = None

SCHEMA = "aios.retry.authorization.v1"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")
_REQUIRED = {
    "schema", "issuer_id", "key_id", "effect_id", "contract_id", "permit_id",
    "actor", "provider", "attempt_id", "attempt_number", "state",
    "state_revision", "state_digest", "not_applied_proof_digest",
    "nonce", "issued_at", "expires_at", "policy_digest",
}


class RetryAuthorizationRejected(PermissionError):
    """Retry authorization is invalid, stale, replayed, or untrusted."""


def canonical_payload(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def effect_state_digest(effect: Mapping[str, Any]) -> str:
    selected = {
        "effect_id": effect.get("effect_id"),
        "contract_id": effect.get("contract_id"),
        "permit_id": effect.get("permit_id"),
        "actor": effect.get("actor"),
        "provider": effect.get("provider"),
        "attempt_id": effect.get("attempt_id"),
        "attempt": effect.get("attempt"),
        "state": effect.get("state"),
        "revision": effect.get("revision"),
        "policy_digest": effect.get("policy_digest"),
    }
    return hashlib.sha256(canonical_payload(selected)).hexdigest()


class RetryIssuerKeyring:
    """Pinned public key registry; key entries contain no private material."""

    def __init__(self, keys: Mapping[str, Mapping[str, Any]]):
        if Ed25519PublicKey is None:
            raise RetryAuthorizationRejected("cryptography unavailable; DENY")
        if not isinstance(keys, Mapping) or not keys:
            raise RetryAuthorizationRejected("independent issuer public keys required; DENY")
        self._keys = {}
        for issuer_id, entry in keys.items():
            if not isinstance(issuer_id, str) or not issuer_id.strip() or not isinstance(entry, Mapping):
                raise RetryAuthorizationRejected("malformed issuer key entry; DENY")
            if set(entry) != {"key_id", "public_key", "revoked"}:
                raise RetryAuthorizationRejected("issuer key entry schema mismatch; DENY")
            kid, public_hex, revoked = entry["key_id"], entry["public_key"], entry["revoked"]
            if not isinstance(public_hex, str) or not _HEX64.fullmatch(public_hex):
                raise RetryAuthorizationRejected("issuer public key must be 32-byte lowercase hex; DENY")
            expected = "retry-ed25519:" + hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:32]
            if kid != expected or not isinstance(revoked, bool):
                raise RetryAuthorizationRejected("issuer key identity/status invalid; DENY")
            self._keys[issuer_id] = (kid, bytes.fromhex(public_hex), revoked)

    def verify(self, authorization: Mapping[str, Any], *, now: float,
               effect: Mapping[str, Any], attempt: Mapping[str, Any],
               not_applied_verifier) -> dict[str, Any]:
        if not isinstance(authorization, Mapping) or set(authorization) != _REQUIRED | {"signature"}:
            raise RetryAuthorizationRejected("authorization schema mismatch; DENY")
        payload = {k: v for k, v in authorization.items() if k != "signature"}
        if payload["schema"] != SCHEMA:
            raise RetryAuthorizationRejected("unsupported retry authorization schema; DENY")
        issuer = payload["issuer_id"]
        if issuer not in self._keys:
            raise RetryAuthorizationRejected("issuer is not pinned; DENY")
        kid, public_bytes, revoked = self._keys[issuer]
        if revoked or payload["key_id"] != kid:
            raise RetryAuthorizationRejected("issuer key revoked or key ID mismatch; DENY")
        signature = authorization["signature"]
        if not isinstance(signature, str) or not _HEX128.fullmatch(signature):
            raise RetryAuthorizationRejected("malformed Ed25519 signature; DENY")
        try:
            Ed25519PublicKey.from_public_bytes(public_bytes).verify(
                bytes.fromhex(signature), canonical_payload(payload)
            )
        except (InvalidSignature, ValueError) as exc:
            raise RetryAuthorizationRejected("retry authorization signature invalid; DENY") from exc

        issued, expires = payload["issued_at"], payload["expires_at"]
        if (isinstance(issued, bool) or isinstance(expires, bool)
                or not isinstance(issued, (int, float)) or not isinstance(expires, (int, float))
                or not math.isfinite(issued) or not math.isfinite(expires)
                or expires <= issued or now < issued or now > expires):
            raise RetryAuthorizationRejected("retry authorization expired or invalid window; DENY")
        if payload["state"] != "UNKNOWN" or effect.get("state") != "UNKNOWN":
            raise RetryAuthorizationRejected("retry requires current UNKNOWN state; DENY")
        expected = {
            "effect_id": effect.get("effect_id"),
            "contract_id": effect.get("contract_id"),
            "permit_id": effect.get("permit_id"),
            "actor": effect.get("actor"),
            "provider": effect.get("provider"),
            "attempt_id": effect.get("attempt_id"),
            "attempt_number": effect.get("attempt"),
            "state_revision": effect.get("revision"),
            "state_digest": effect_state_digest(effect),
            "policy_digest": effect.get("policy_digest"),
        }
        for key, value in expected.items():
            if payload.get(key) != value:
                raise RetryAuthorizationRejected(f"retry authorization {key} binding mismatch; DENY")
        if attempt.get("effect_id") != effect.get("effect_id") or attempt.get("attempt_id") != effect.get("attempt_id"):
            raise RetryAuthorizationRejected("current attempt binding mismatch; DENY")
        if attempt.get("state") != "UNKNOWN":
            raise RetryAuthorizationRejected("current attempt is not UNKNOWN; DENY")
        proof_digest = payload["not_applied_proof_digest"]
        if not isinstance(proof_digest, str) or not _HEX64.fullmatch(proof_digest):
            raise RetryAuthorizationRejected("NOT_APPLIED proof digest missing; DENY")
        if not callable(not_applied_verifier) or not not_applied_verifier(
            proof_digest=proof_digest, effect=effect, attempt=attempt
        ):
            raise RetryAuthorizationRejected("NOT_APPLIED proof did not verify; DENY")
        nonce = payload["nonce"]
        if not isinstance(nonce, str) or len(nonce) < 16 or len(nonce) > 256:
            raise RetryAuthorizationRejected("retry nonce invalid; DENY")
        return dict(payload)


__all__ = ["SCHEMA", "RetryAuthorizationRejected", "RetryIssuerKeyring",
           "canonical_payload", "effect_state_digest"]
