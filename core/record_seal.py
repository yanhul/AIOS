"""Deployment-keyed seals for AIOS authority records.

SHA-256 content digests (``EvidenceRecord.digest``, ``receipt_id``) prove that
a record was not *accidentally* altered, but anyone who can write the AIOS
state directory can recompute them. Records that *unlock authority* (a
NOT_APPLIED reconciliation unlocks a retry; a receipt unlocks evaluation)
must therefore also carry an HMAC seal produced at the AIOS write boundary
with a deployment secret that is never stored in AIOS state.

Threat model (explicit): this defends against forged or edited JSON written
by anything that does not hold the secret (agents, workers, other repos,
a compromised state volume). It does NOT prove provider authenticity — that is
``core.provider_trust`` (provider-signed attestations) — and it does not defend against a process
that holds the secret.

Configure with ``AIOS_RECORD_SEAL_SECRET``. When it is absent or blank, sealing
raises and every consumer that requires a seal fails closed. Writers of authority
records (receipts, reconciliations, execution claims) never fall back to an
unsealed record.

Key rotation: new seals always use the current secret. During a rotation
window, set ``AIOS_RECORD_SEAL_PREVIOUS_SECRETS`` (comma-separated) to the
retired secrets: records sealed by them still *verify*, and ``reseal()``
re-stamps a verified record under the current key. Remove a previous secret
only after its records are resealed; until then fail-closed applies.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any, Mapping

from .mutation import TransitionError, canonical_json

SEAL_ENV = "AIOS_RECORD_SEAL_SECRET"
PREVIOUS_SEAL_ENV = "AIOS_RECORD_SEAL_PREVIOUS_SECRETS"
ALGORITHM = "HMAC-SHA256"


class SealError(TransitionError):
    """Raised when a record cannot be sealed or its seal is not trusted."""


def _secret_problem(value: str) -> str | None:
    """Why ``value`` cannot be used as the deployment seal key, or None if it can."""
    if not value:
        return f"{SEAL_ENV} is not configured; authority records cannot be sealed or trusted"
    if not value.strip("\x00 \t\r\n\v\f"):
        # A blank/whitespace/NUL-only key is a broken deployment (empty secret file,
        # unrendered template), not a secret: never seal authority records with it.
        return f"{SEAL_ENV} is invalid (blank); authority records cannot be sealed or trusted"
    return None


def _secret() -> bytes:
    value = os.environ.get(SEAL_ENV, "")
    problem = _secret_problem(value)
    if problem:
        raise SealError(problem)
    return value.encode("utf-8")


def _verification_secrets() -> dict[str, bytes]:
    """key_id -> secret for the current key plus explicitly retired keys."""
    current = _secret()
    keys = {_key_id(current): current}
    for raw in os.environ.get(PREVIOUS_SEAL_ENV, "").split(","):
        raw = raw.strip()
        if raw:
            keys.setdefault(_key_id(raw.encode("utf-8")), raw.encode("utf-8"))
    return keys


def seal_available() -> bool:
    """True iff ``seal()`` would use a valid deployment key. Never a reason to skip sealing authority records."""
    return _secret_problem(os.environ.get(SEAL_ENV, "")) is None


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
    """Fail closed unless ``record`` carries a valid seal under a trusted key.

    Trusted keys are the current secret plus retired secrets explicitly listed
    in ``AIOS_RECORD_SEAL_PREVIOUS_SECRETS`` (rotation window only).
    """
    if not isinstance(record, Mapping):
        raise SealError(f"{what} is not a record")
    stamp = record.get("seal")
    if not isinstance(stamp, Mapping) or stamp.get("algorithm") != ALGORITHM:
        raise SealError(f"{what} is not sealed by AIOS")
    secret = _verification_secrets().get(stamp.get("key_id"))
    if secret is None:
        raise SealError(f"{what} was sealed with a different key")
    mac = stamp.get("mac")
    if not isinstance(mac, str) or not hmac.compare_digest(mac, _mac(secret, unsealed_body(record))):
        raise SealError(f"{what} seal does not match its content")


def reseal(record: Mapping[str, Any], what: str = "record") -> dict:
    """Verify ``record`` (current or retired key), then re-seal it under the current key."""
    require_seal(record, what)
    return seal(unsealed_body(record))


__all__ = ["SEAL_ENV", "PREVIOUS_SEAL_ENV", "reseal", "SealError", "seal", "seal_available", "require_seal", "unsealed_body"]
