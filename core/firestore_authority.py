"""Immutable Firestore authority artifacts with pinned Ed25519 issuer verification.

This is a storage and verification primitive, not a policy decision engine.
Callers must validate each artifact's domain schema and cross-bindings before
execution. Documents are content-addressed and create-only; no update path exists.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Mapping
from typing import Any

from .mutation import canonical_json

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # fail closed; never downgrade to HMAC
    InvalidSignature = Ed25519PublicKey = None

TRUST_ANCHOR_ENV = "AIOS_AUTHORITY_TRUST_ANCHOR"
AUTHORITY_COLLECTION = "aios_authority_records"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")


class AuthorityStoreError(RuntimeError):
    pass


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return canonical_json(dict(value)).encode("utf-8")


def record_digest(record: Mapping[str, Any]) -> str:
    if not isinstance(record, Mapping) or not record:
        raise AuthorityStoreError("authority record must be a non-empty object")
    return hashlib.sha256(_json_bytes(record)).hexdigest()


def _trust_anchor(environ: Mapping[str, str]) -> dict[str, dict[str, Any]]:
    raw = environ.get(TRUST_ANCHOR_ENV)
    if not raw:
        raise AuthorityStoreError("pinned Ed25519 authority trust anchor is missing; DENY")
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise AuthorityStoreError("authority trust anchor is not valid JSON; DENY") from exc
    if not isinstance(parsed, dict) or not parsed:
        raise AuthorityStoreError("authority trust anchor must be a non-empty object; DENY")
    for key_id, entry in parsed.items():
        if (not isinstance(key_id, str) or not isinstance(entry, dict)
                or set(entry) != {"public_key", "principal", "revoked"}
                or not isinstance(entry["public_key"], str)
                or not _HEX64.fullmatch(entry["public_key"])
                or not isinstance(entry["principal"], str) or not entry["principal"].strip()
                or not isinstance(entry["revoked"], bool)):
            raise AuthorityStoreError("malformed authority trust-anchor entry; DENY")
        expected_id = "ed25519:" + hashlib.sha256(bytes.fromhex(entry["public_key"])).hexdigest()[:32]
        if key_id != expected_id:
            raise AuthorityStoreError("authority trust-anchor key ID mismatch; DENY")
    return parsed


def verify_authority_signature(*, record: Mapping[str, Any], signature: Mapping[str, Any],
                               trust_anchor: Mapping[str, Mapping[str, Any]], now: int | None = None) -> bool:
    """Verify an Ed25519 envelope binding issuer, record digest and validity window."""
    if Ed25519PublicKey is None:
        raise AuthorityStoreError("cryptography/Ed25519 unavailable; DENY")
    if not isinstance(signature, Mapping) or set(signature) != {
        "type", "algorithm", "key_id", "principal", "record_digest", "issued_at", "expires_at", "signature"
    }:
        raise AuthorityStoreError("authority signature schema mismatch; DENY")
    if signature["type"] != "AIOS_AUTHORITY_SIGNATURE" or signature["algorithm"] != "Ed25519":
        raise AuthorityStoreError("authority signature type/algorithm mismatch; DENY")
    entry = trust_anchor.get(signature["key_id"])
    if not isinstance(entry, Mapping) or set(entry) != {"public_key", "principal", "revoked"}:
        raise AuthorityStoreError("authority issuer is not pinned; DENY")
    if entry["revoked"] is not False or signature["principal"] != entry["principal"]:
        raise AuthorityStoreError("authority issuer revoked or principal mismatch; DENY")
    digest = record_digest(record)
    if signature["record_digest"] != digest:
        raise AuthorityStoreError("authority signature does not bind record digest; DENY")
    issued, expires = signature["issued_at"], signature["expires_at"]
    timestamp = int(time.time()) if now is None else now
    if (isinstance(issued, bool) or not isinstance(issued, int)
            or isinstance(expires, bool) or not isinstance(expires, int)
            or issued > timestamp or expires <= timestamp or expires <= issued):
        raise AuthorityStoreError("authority signature is not currently valid; DENY")
    sig = signature["signature"]
    if not isinstance(sig, str) or not _HEX128.fullmatch(sig):
        raise AuthorityStoreError("authority signature encoding invalid; DENY")
    signed = {k: signature[k] for k in signature if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["public_key"])).verify(
            bytes.fromhex(sig), _json_bytes(signed)
        )
    except (InvalidSignature, ValueError) as exc:
        raise AuthorityStoreError("authority Ed25519 signature invalid; DENY") from exc
    return True


class FirestoreAuthorityStore:
    """Create-only content-addressed Firestore store for authority artifacts."""
    def __init__(self, client: Any, *, project_id: str, collection: str = AUTHORITY_COLLECTION):
        if not isinstance(project_id, str) or not project_id.strip():
            raise AuthorityStoreError("explicit Firestore project ID required")
        if getattr(client, "project", None) != project_id:
            raise AuthorityStoreError("Firestore client project mismatch")
        if not isinstance(collection, str) or not collection.strip():
            raise AuthorityStoreError("authority collection name required")
        self._client, self.project_id, self.collection = client, project_id, collection

    def put_immutable(self, *, record_type: str, record_id: str, record: Mapping[str, Any],
                      signature: Mapping[str, Any], trust_anchor: Mapping[str, Mapping[str, Any]],
                      now: int | None = None) -> str:
        if not isinstance(record_type, str) or not record_type.strip():
            raise AuthorityStoreError("record_type required")
        if not isinstance(record_id, str) or not record_id.strip() or "/" in record_id:
            raise AuthorityStoreError("record_id must be a non-empty Firestore-safe ID")
        verify_authority_signature(record=record, signature=signature, trust_anchor=trust_anchor, now=now)
        digest = record_digest(record)
        ref = self._client.collection(self.collection).document(digest)
        payload = {"schema_version": 1, "record_type": record_type, "record_id": record_id,
                   "record_digest": digest, "record": dict(record), "signature": dict(signature)}
        snapshot = ref.get()
        if snapshot.exists:
            existing = snapshot.to_dict()
            if existing != payload:
                raise AuthorityStoreError("content-address collision or immutable record conflict")
            return digest
        try:
            ref.create(payload)
        except Exception as exc:
            # Concurrent create: accept only byte-for-byte identical committed data.
            try:
                snapshot = ref.get()
                if snapshot.exists and snapshot.to_dict() == payload:
                    return digest
            except Exception:
                pass
            raise AuthorityStoreError("immutable authority record create failed") from exc
        return digest

    def get_verified(self, digest: str, *, trust_anchor: Mapping[str, Mapping[str, Any]],
                     expected_type: str | None = None, now: int | None = None) -> dict[str, Any]:
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            raise AuthorityStoreError("authority digest must be lowercase SHA-256 hex")
        snapshot = self._client.collection(self.collection).document(digest).get()
        if not snapshot.exists:
            raise AuthorityStoreError("authority record missing; DENY")
        payload = snapshot.to_dict()
        if (not isinstance(payload, dict) or payload.get("schema_version") != 1
                or payload.get("record_digest") != digest or not isinstance(payload.get("record"), dict)):
            raise AuthorityStoreError("authority record envelope malformed; DENY")
        if expected_type is not None and payload.get("record_type") != expected_type:
            raise AuthorityStoreError("authority record type mismatch; DENY")
        if record_digest(payload["record"]) != digest:
            raise AuthorityStoreError("authority record content hash mismatch; DENY")
        verify_authority_signature(record=payload["record"], signature=payload.get("signature"),
                                   trust_anchor=trust_anchor, now=now)
        return payload["record"]

    @classmethod
    def trust_anchor_from_env(cls, environ: Mapping[str, str] | None = None):
        return _trust_anchor(os.environ if environ is None else environ)


__all__ = ["AUTHORITY_COLLECTION", "TRUST_ANCHOR_ENV", "AuthorityStoreError",
           "FirestoreAuthorityStore", "record_digest", "verify_authority_signature"]
