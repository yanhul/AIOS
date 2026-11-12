"""Ed25519 provider receipts for externally owned workloads (audit F-04.1).

Asymmetric: the workload holds the private key; the AIOS verifier holds only
public keys (``AIOS_PROVIDER_ED25519_KEYRING``). Nothing in the AIOS process
can therefore sign a receipt for an Ed25519 provider. Providers listed in
``ED25519_REQUIRED_PROVIDERS`` or registered in the public keyring are
Ed25519-only: their HMAC entries in ``AIOS_PROVIDER_KEYRING`` are never used.

Requires ``cryptography``; without it verification fails closed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time

from .mutation import canonical_json

try:  # verification is impossible without the library -> fail closed, never fall back to HMAC
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
except ImportError:  # pragma: no cover - exercised by monkeypatching ED25519_AVAILABLE
    InvalidSignature = serialization = Ed25519PrivateKey = Ed25519PublicKey = None

ED25519_AVAILABLE = Ed25519PublicKey is not None
ED25519_KEYRING_ENV = "AIOS_PROVIDER_ED25519_KEYRING"
ED25519_RECEIPT_TYPE = "PROVIDER_RECEIPT_ED25519"
ED25519_ALGORITHM = "Ed25519"
ED25519_REQUIRED_PROVIDERS = frozenset({"minimind"})
ED25519_AUTH_FIELDS = ("type", "algorithm", "key_id", "receipt_id", "contract_id", "permit_id",
                       "issued_at", "expires_at", "signature")
_KEY_ID = re.compile(r"ed25519:[0-9a-f]{32}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")


class Ed25519ConfigError(ValueError):
    """Ed25519 trust configuration is missing, malformed or unusable."""


def _require_library():
    if not ED25519_AVAILABLE:
        raise Ed25519ConfigError("Ed25519 verification unavailable (cryptography not installed)")


def key_id_for(public_key_hex: str) -> str:
    return "ed25519:" + hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:32]


def receipt_digest(observation) -> str:
    return hashlib.sha256(canonical_json(observation).encode("utf-8")).hexdigest()


def ed25519_payload(*, key_id, receipt_id, effect_id, contract_id, permit_id, attempt_id, provider,
                    provider_operation_id, outcome, observation, issued_at, expires_at) -> bytes:
    """Canonical bytes signed by the workload and rebuilt by the verifier from trusted state."""
    return canonical_json({
        "type": ED25519_RECEIPT_TYPE, "algorithm": ED25519_ALGORITHM, "key_id": key_id,
        "receipt_id": receipt_id, "effect_id": effect_id, "contract_id": contract_id,
        "permit_id": permit_id, "attempt_id": attempt_id, "provider": provider,
        "provider_operation_id": provider_operation_id, "outcome": outcome,
        "receipt_digest": receipt_digest(observation), "issued_at": issued_at, "expires_at": expires_at,
    }).encode("utf-8")


class ProviderPublicKeyring:
    """Verifier-side registry: ``{"<provider>": {"key_id": "...", "public_key": "<hex>", "revoked": false}}``.

    Holds public keys only; any other field (e.g. a private key) is rejected.
    """

    def __init__(self, spec):
        if not isinstance(spec, dict):
            raise Ed25519ConfigError("Ed25519 public keyring must be an object")
        self._keys = {}
        for provider, entry in spec.items():
            if not isinstance(provider, str) or not provider.strip() or not isinstance(entry, dict):
                raise Ed25519ConfigError("Ed25519 public keyring entry is malformed")
            if not {"key_id", "public_key"}.issubset(entry) or not set(entry) <= {"key_id", "public_key", "revoked"}:
                raise Ed25519ConfigError(f"Ed25519 public keyring entry for {provider!r} has invalid fields")
            pub, kid, revoked = entry["public_key"], entry["key_id"], entry.get("revoked", False)
            if not isinstance(pub, str) or not _HEX64.fullmatch(pub):
                raise Ed25519ConfigError(f"Ed25519 public key for {provider!r} must be 32 bytes hex")
            if not isinstance(kid, str) or kid != key_id_for(pub):
                raise Ed25519ConfigError(f"Ed25519 key_id for {provider!r} does not match its public key")
            if not isinstance(revoked, bool):
                raise Ed25519ConfigError("revoked must be a boolean")
            self._keys[provider] = (kid, pub, revoked)

    @classmethod
    def from_env(cls, environ=None):
        raw = (os.environ if environ is None else environ).get(ED25519_KEYRING_ENV)
        if raw is None:
            return None
        try:
            spec = json.loads(raw)
        except ValueError as exc:
            raise Ed25519ConfigError(f"{ED25519_KEYRING_ENV} is not valid JSON") from exc
        return cls(spec)

    def __contains__(self, provider):
        return provider in self._keys

    def __repr__(self):
        return f"ProviderPublicKeyring(providers={sorted(self._keys)!r})"

    def verify(self, provider, key_id, signature_hex, payload: bytes):
        _require_library()
        if provider not in self._keys:
            raise Ed25519ConfigError(f"no Ed25519 public key registered for provider {provider!r}")
        kid, pub, revoked = self._keys[provider]
        if revoked:
            raise Ed25519ConfigError(f"Ed25519 key for provider {provider!r} is revoked")
        if key_id != kid:
            raise ValueError("Ed25519 key_id does not match the dispatched provider's registered key")
        if not isinstance(signature_hex, str) or not _HEX128.fullmatch(signature_hex):
            raise ValueError("Ed25519 signature is malformed")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(signature_hex), payload)
        except InvalidSignature as exc:
            raise ValueError("Ed25519 signature is invalid or not bound to this effect/attempt/outcome/receipt") from exc


class Ed25519ReceiptSigner:
    """Workload-side signer. The private key must come from the workload's own secret store
    (e.g. a PEM file readable only by the workload user) - never argv, agent env or stdout."""

    def __init__(self, provider, private_key, ttl_seconds=300):
        _require_library()
        if not isinstance(provider, str) or not provider.strip():
            raise ValueError("provider must be a non-empty string")
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("private_key must be an Ed25519PrivateKey")
        if not isinstance(ttl_seconds, (int, float)) or not 0 < ttl_seconds <= 3600:
            raise ValueError("ttl_seconds out of range")
        self.provider = provider
        self._key = private_key
        raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_key_hex = raw.hex()
        self.key_id = key_id_for(self.public_key_hex)
        self.ttl_seconds = float(ttl_seconds)

    @classmethod
    def from_pem_file(cls, provider, path, ttl_seconds=300):
        _require_library()
        with open(path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
        return cls(provider, key, ttl_seconds)

    def __repr__(self):  # never leak the key
        return f"Ed25519ReceiptSigner(provider={self.provider!r}, key_id={self.key_id!r})"

    def sign(self, *, effect, attempt_id, provider_operation_id, outcome, observation, now=None):
        issued_at = float(time.time() if now is None else now)
        auth = {"type": ED25519_RECEIPT_TYPE, "algorithm": ED25519_ALGORITHM, "key_id": self.key_id,
                "receipt_id": "PR-" + secrets.token_hex(16), "contract_id": effect["contract_id"],
                "permit_id": effect["permit_id"], "issued_at": issued_at,
                "expires_at": issued_at + self.ttl_seconds}
        payload = ed25519_payload(
            key_id=self.key_id, receipt_id=auth["receipt_id"], effect_id=effect["effect_id"],
            contract_id=auth["contract_id"], permit_id=auth["permit_id"], attempt_id=attempt_id,
            provider=self.provider, provider_operation_id=provider_operation_id, outcome=outcome,
            observation=observation, issued_at=issued_at, expires_at=auth["expires_at"])
        auth["signature"] = self._key.sign(payload).hex()
        return auth


__all__ = ["ED25519_AVAILABLE", "ED25519_KEYRING_ENV", "ED25519_REQUIRED_PROVIDERS", "ED25519_RECEIPT_TYPE",
           "Ed25519ConfigError", "Ed25519ReceiptSigner", "ProviderPublicKeyring", "ed25519_payload",
           "key_id_for", "receipt_digest"]
