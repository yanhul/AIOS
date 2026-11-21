"""Independent Ed25519 retry authorization trust primitives.

The issuer process owns the private key. AIOS loads only pinned public keys.
Records are canonical JSON signatures over the complete one-shot retry context.
"""
from __future__ import annotations
import hashlib, json, os, re, time
from .mutation import canonical_json

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
except ImportError:  # fail closed
    InvalidSignature = serialization = Ed25519PrivateKey = Ed25519PublicKey = None

ENV = "AIOS_RETRY_ISSUER_ED25519_KEYRING"
ALGORITHM = "Ed25519"
SCOPE = "effect.retry.approve"
KEY_ID_RE = re.compile(r"ed25519:[0-9a-f]{32}")
HEX64 = re.compile(r"[0-9a-f]{64}")
SIGNED_FIELDS = (
    "record_type", "authorization_id", "effect_id", "contract_id", "permit_id", "actor",
    "issuer", "scope", "effect_state_digest", "previous_attempt", "previous_attempt_id",
    "attempt", "attempt_id", "reason", "unknown_reason", "issued_at", "expires_at",
    "mode", "algorithm", "provider", "key_id",
)

class RetryIssuerTrustError(ValueError):
    pass

def key_id_for(public_hex: str) -> str:
    return "ed25519:" + hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:32]

def signing_bytes(record: dict) -> bytes:
    return canonical_json({k: record[k] for k in SIGNED_FIELDS}).encode("utf-8")

class RetryIssuerPublicKeyring:
    def __init__(self, spec):
        if not isinstance(spec, dict) or not spec:
            raise RetryIssuerTrustError("retry issuer Ed25519 keyring must be a non-empty object")
        self._keys = {}
        for issuer, entry in spec.items():
            if not isinstance(issuer, str) or not issuer.strip() or not isinstance(entry, dict):
                raise RetryIssuerTrustError("retry issuer entry malformed")
            if set(entry) - {"key_id", "public_key", "revoked"} or not {"key_id", "public_key"} <= set(entry):
                raise RetryIssuerTrustError("retry issuer registry accepts public keys only")
            pub, kid, revoked = entry["public_key"], entry["key_id"], entry.get("revoked", False)
            if not isinstance(pub, str) or not HEX64.fullmatch(pub) or not isinstance(kid, str) or kid != key_id_for(pub):
                raise RetryIssuerTrustError("retry issuer public key or key_id invalid")
            if not isinstance(revoked, bool):
                raise RetryIssuerTrustError("retry issuer revoked flag must be boolean")
            self._keys[issuer] = (kid, pub, revoked)

    @classmethod
    def from_env(cls, environ=None):
        raw = (os.environ if environ is None else environ).get(ENV)
        if not raw:
            raise RetryIssuerTrustError(f"{ENV} is required")
        try:
            return cls(json.loads(raw))
        except (TypeError, json.JSONDecodeError) as exc:
            raise RetryIssuerTrustError(f"{ENV} is invalid JSON") from exc

    def verify(self, record):
        if Ed25519PublicKey is None:
            raise RetryIssuerTrustError("cryptography is required for Ed25519 retry verification")
        issuer, kid = record.get("issuer"), record.get("key_id")
        entry = self._keys.get(issuer)
        if not entry:
            raise RetryIssuerTrustError("retry issuer is not registered")
        expected_kid, pub, revoked = entry
        if revoked:
            raise RetryIssuerTrustError("retry issuer key is revoked")
        if kid != expected_kid:
            raise RetryIssuerTrustError("retry issuer key_id mismatch")
        sig = record.get("signature")
        if not isinstance(sig, str) or not re.fullmatch(r"[0-9a-f]{128}", sig):
            raise RetryIssuerTrustError("retry authorization signature malformed")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(sig), signing_bytes(record))
        except InvalidSignature as exc:
            raise RetryIssuerTrustError("retry authorization signature invalid") from exc

class RetryAuthorizationSigner:
    """Issuer-side signer. Load private key only from issuer-owned secret storage."""
    def __init__(self, issuer, private_key, ttl_seconds=900):
        if Ed25519PrivateKey is None or not isinstance(private_key, Ed25519PrivateKey):
            raise RetryIssuerTrustError("an Ed25519 private key is required")
        if not isinstance(issuer, str) or not issuer.strip():
            raise RetryIssuerTrustError("issuer identity required")
        if not isinstance(ttl_seconds, (int, float)) or isinstance(ttl_seconds, bool) or not 0 < ttl_seconds <= 86400:
            raise RetryIssuerTrustError("ttl_seconds must be within (0, 86400]")
        self.issuer, self._key, self.ttl_seconds = issuer, private_key, float(ttl_seconds)
        raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_key = raw.hex()
        self.key_id = key_id_for(self.public_key)

    @classmethod
    def from_pem_file(cls, issuer, path, ttl_seconds=900):
        if Ed25519PrivateKey is None:
            raise RetryIssuerTrustError("cryptography is required")
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        return cls(issuer, key, ttl_seconds)

    def sign(self, fields, *, now=None):
        if not isinstance(fields, dict) or set(fields) != set(SIGNED_FIELDS) - {"issuer", "scope", "mode", "algorithm", "issued_at", "expires_at", "key_id"}:
            raise RetryIssuerTrustError("retry request schema mismatch")
        issued = time.time() if now is None else now
        if not isinstance(issued, (int, float)) or isinstance(issued, bool):
            raise RetryIssuerTrustError("invalid issuer clock")
        record = dict(fields, issuer=self.issuer, scope=SCOPE, mode="EXPLICIT", algorithm=ALGORITHM,
                      issued_at=float(issued), expires_at=float(issued) + self.ttl_seconds,
                      record_type="RETRY_AUTHORIZATION_ED25519", key_id=self.key_id)
        record["signature"] = self._key.sign(signing_bytes(record)).hex()
        return record

__all__ = ["ENV", "ALGORITHM", "SCOPE", "SIGNED_FIELDS", "RetryIssuerTrustError", "RetryIssuerPublicKeyring", "RetryAuthorizationSigner", "key_id_for", "signing_bytes"]