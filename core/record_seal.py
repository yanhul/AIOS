"""Deployment-keyed seals for AIOS authority records.

SHA-256 content digests (``EvidenceRecord.digest``, ``receipt_id``) prove that
a record was not *accidentally* altered, but anyone who can write the AIOS
state directory can recompute them. Records that *unlock authority* (a
NOT_APPLIED reconciliation unlocks a retry; a receipt unlocks evaluation)
must therefore also carry an HMAC seal produced at the AIOS write boundary
with a deployment secret that is never stored in AIOS state.

Threat model (explicit): this defends against forged or edited JSON written
by anything that does not hold the secret (agents, workers, other repos,
a compromised state volume). It does NOT prove provider authenticity — that
needs provider-signed responses — and it does not defend against a process
that holds the secret.

Configure with ``AIOS_RECORD_SEAL_SECRET``. When it is absent, sealing raises
and every consumer that requires a seal fails closed.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any, Mapping

from .mutation import TransitionError, canonical_json

SEAL_ENV = "AIOS_RECORD_SEAL_SECRET"
ALGORITHM = "HMAC-SHA256"


class SealError(TransitionError):
    """Raised when a record cannot be sealed or its seal is not trusted."""


def _secret() -> bytes:
    value = os.environ.get(SEAL_ENV, "")
    if not value:
        raise SealError(f"{SEAL_ENV} is not configured; authority records cannot be sealed or trusted")
    return value.encode("utf-8")


def seal_available() -> bool:
    return bool(os.environ.get(SEAL_ENV, ""))


def _key_id(secret: bytes) -> str:
    return hashlib.sha256(b"aios-seal-key-id\n" + secret).hexdigest()[:16]


def _mac(secret: bytes, body: Mapping[str, Any]) -> str:
    domain = str(body.get("record_type", "")).encode("utf-8")
    return hmac.new(secret, domain + b"\n" + canonical_json(dict(body)).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def unsealed_body(record: Mapping[str, Any]) -> dict:
    return {k: v for k, v in record.items() if k != "seal"}


def seal(record: Mapping[str, Any]) -> dict:
    """Return a copy of ``record`` with a seal over every other field."""
    if not isinstance(record, Mapping) or not record.get("record_type"):
        raise SealError("only typed records can be sealed")
    secret = _secret()
    body = unsealed_body(record)
    return {**body, "seal": {"algorithm": ALGORITHM, "key_id": _key_id(secret), "mac": _mac(secret, body)}}


def require_seal(record: Mapping[str, Any], what: str = "record") -> None:
    """Fail closed unless ``record`` carries a valid seal under the current key."""
    if not isinstance(record, Mapping):
        raise SealError(f"{what} is not a record")
    stamp = record.get("seal")
    if not isinstance(stamp, Mapping) or stamp.get("algorithm") != ALGORITHM:
        raise SealError(f"{what} is not sealed by AIOS")
    secret = _secret()
    if stamp.get("key_id") != _key_id(secret):
        raise SealError(f"{what} was sealed with a different key")
    mac = stamp.get("mac")
    if not isinstance(mac, str) or not hmac.compare_digest(mac, _mac(secret, unsealed_body(record))):
        raise SealError(f"{what} seal does not match its content")


__all__ = ["SEAL_ENV", "SealError", "seal", "seal_available", "require_seal", "unsealed_body"]
