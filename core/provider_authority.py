"""Provider-side receipt signing (audit F-04).

A provider (or the AIOS adapter that directly supervises a local provider
process) signs what it observed with its own deployment-issued key. The key
is supplied by the deployment to the provider side only, e.g. via
``AIOS_PROVIDER_SIGNING_KEYS`` (JSON ``{"<provider>": "<secret>"}``) in the
provider's environment. The verifier side holds ``AIOS_PROVIDER_KEYRING``.
Neither is ever stored in AIOS state or passed to the executing agent.

Without a signer a receipt stays unauthenticated and ``core.runtime`` records
the effect as UNKNOWN (non-authoritative) instead of OBSERVED_*.
"""
from __future__ import annotations

import dataclasses
import json
import os
import secrets
import time

from .effect_authority import (
    MAX_PROVIDER_RECEIPT_TTL_SECONDS, PROVIDER_RECEIPT_TYPE, provider_receipt_body, provider_receipt_signature,
)

PROVIDER_SIGNING_KEYS_ENV = "AIOS_PROVIDER_SIGNING_KEYS"
DEFAULT_RECEIPT_TTL_SECONDS = 300


class ProviderReceiptSigner:
    def __init__(self, provider: str, secret: str, ttl_seconds: float = DEFAULT_RECEIPT_TTL_SECONDS):
        if not isinstance(provider, str) or not provider.strip():
            raise ValueError("provider must be a non-empty string")
        if not isinstance(secret, str) or len(secret) < 16:
            raise ValueError("provider signing secret must be a string of at least 16 characters")
        if not isinstance(ttl_seconds, (int, float)) or not 0 < ttl_seconds <= MAX_PROVIDER_RECEIPT_TTL_SECONDS:
            raise ValueError("ttl_seconds out of range")
        self.provider = provider
        self._secret = secret.encode("utf-8")
        self.ttl_seconds = float(ttl_seconds)

    @classmethod
    def from_env(cls, provider: str, environ=None):
        raw = (os.environ if environ is None else environ).get(PROVIDER_SIGNING_KEYS_ENV)
        if not raw:
            return None
        try:
            keys = json.loads(raw)
        except ValueError as exc:
            raise ValueError(f"{PROVIDER_SIGNING_KEYS_ENV} is not valid JSON") from exc
        if not isinstance(keys, dict) or provider not in keys:
            return None
        return cls(provider, keys[provider])

    def __repr__(self):  # never leak the key
        return f"ProviderReceiptSigner(provider={self.provider!r})"

    def sign(self, *, effect: dict, attempt_id: str, provider_operation_id: str, outcome: str,
             observation: dict, now: float | None = None) -> dict:
        issued_at = float(time.time() if now is None else now)
        auth = {
            "type": PROVIDER_RECEIPT_TYPE, "receipt_id": "PR-" + secrets.token_hex(16),
            "contract_id": effect["contract_id"], "permit_id": effect["permit_id"],
            "issued_at": issued_at, "expires_at": issued_at + self.ttl_seconds, "algorithm": "HMAC-SHA256",
        }
        body = provider_receipt_body(
            receipt_id=auth["receipt_id"], effect_id=effect["effect_id"], contract_id=auth["contract_id"],
            permit_id=auth["permit_id"], attempt_id=attempt_id, provider=self.provider,
            provider_operation_id=provider_operation_id, outcome=outcome, observation=observation,
            issued_at=issued_at, expires_at=auth["expires_at"])
        auth["signature"] = provider_receipt_signature(self._secret, body)
        return auth


def authenticate_receipt(receipt, effect: dict, signer: ProviderReceiptSigner | None, now: float | None = None):
    """Return ``receipt`` signed by ``signer``; unchanged (unauthenticated) if no signer."""
    if signer is None:
        return receipt
    if signer.provider != receipt.provider:
        raise ValueError("signer provider does not match receipt provider")
    auth = signer.sign(effect=effect, attempt_id=receipt.attempt_id,
                       provider_operation_id=receipt.provider_operation_id, outcome=receipt.outcome,
                       observation=receipt.observation, now=now)
    return dataclasses.replace(receipt, authentication=auth)


__all__ = ["ProviderReceiptSigner", "authenticate_receipt", "PROVIDER_SIGNING_KEYS_ENV"]
