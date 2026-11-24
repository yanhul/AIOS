"""Verify TRY's durable proposal-operation receipts before AIOS reconciliation.

The receipt is Ed25519 authenticated by a deployment-pinned TRY public key.
The signing private key remains inside the TRY Worker; AIOS holds only the
public verification key. The bearer transport token is not a trust anchor.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import re
import time
from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .mutation import TransitionError, canonical_json

RECEIPT_TYPE = "TRY_PROPOSAL_OPERATION_RECEIPT_V1"
RECEIPT_ISSUER = "try.repair"
RECEIPT_SCOPE = "try.operation.receipt.verify"
KEYRING_ENV = "AIOS_TRY_OPERATION_KEYRING"
SIGNED_FIELDS = (
    "type", "issuer", "key_id", "receipt_id", "request_id", "request_digest",
    "repository", "sha", "attempt", "status", "execution_state", "failure_code",
    "proposal_digest", "issued_at", "expires_at", "algorithm",
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT_ID = re.compile(r"^TR-[0-9a-f]{32}$")
_MAX_TTL = 900
_CLOCK_SKEW = 60


class TryOperationReceiptError(TransitionError):
    pass


class TryOperationReceiptKeyring:
    """Deployment-pinned Ed25519 public key for the TRY receipt issuer."""

    def __init__(self, issuers: Mapping[str, object]):
        if not isinstance(issuers, Mapping) or RECEIPT_ISSUER not in issuers:
            raise ValueError("TRY operation receipt issuer is not pinned")
        entry = issuers[RECEIPT_ISSUER]
        if not isinstance(entry, Mapping) or set(entry) - {"public_key", "key_id", "scopes", "revoked"}:
            raise ValueError("TRY operation receipt key entry is malformed")
        public_key = entry.get("public_key")
        key_id = entry.get("key_id")
        scopes = entry.get("scopes", [])
        revoked = entry.get("revoked", False)
        if not isinstance(public_key, str) or len(public_key) != 44:
            raise ValueError("TRY operation receipt public_key is missing or malformed")
        try:
            decoded_public_key = base64.b64decode(public_key, validate=True)
            if len(decoded_public_key) != 32:
                raise ValueError("Ed25519 public key must be exactly 32 bytes")
            self.public_key = Ed25519PublicKey.from_public_bytes(decoded_public_key)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("TRY operation receipt public_key is invalid") from exc
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("TRY operation receipt key_id is missing")
        if not isinstance(scopes, list) or RECEIPT_SCOPE not in scopes:
            raise ValueError("TRY operation receipt verification scope is missing")
        if not isinstance(revoked, bool):
            raise ValueError("TRY operation receipt revoked flag is invalid")
        self.key_id = key_id
        self.revoked = revoked

    @classmethod
    def from_env(cls, environ=None):
        raw = (os.environ if environ is None else environ).get(KEYRING_ENV)
        if not raw:
            raise TryOperationReceiptError(f"{KEYRING_ENV} is not configured")
        try:
            return cls(json.loads(raw))
        except (ValueError, TypeError) as exc:
            raise TryOperationReceiptError(f"{KEYRING_ENV} is invalid: {exc}") from exc


def receipt_digest(receipt: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_json(dict(receipt)).encode("utf-8")).hexdigest()


def verify_try_operation_receipt(receipt, *, request_id, request_digest, repository, sha, attempt,
                                 keyring=None, now=None):
    if not isinstance(receipt, Mapping) or set(receipt) != set(SIGNED_FIELDS) | {"signature"}:
        raise TryOperationReceiptError("TRY operation receipt schema mismatch")
    record = dict(receipt)
    if (record.get("type") != RECEIPT_TYPE or record.get("issuer") != RECEIPT_ISSUER
            or record.get("algorithm") != "Ed25519"
            or not isinstance(record.get("receipt_id"), str) or not _RECEIPT_ID.fullmatch(record["receipt_id"])
            or not isinstance(record.get("signature"), str) or len(record["signature"]) != 88):
        raise TryOperationReceiptError("TRY operation receipt identity/signature is malformed")
    if keyring is None:
        keyring = TryOperationReceiptKeyring.from_env()
    if not isinstance(keyring, TryOperationReceiptKeyring) or keyring.revoked:
        raise TryOperationReceiptError("TRY operation receipt trust anchor unavailable or revoked")
    if record.get("key_id") != keyring.key_id:
        raise TryOperationReceiptError("TRY operation receipt key_id is not pinned")
    for key, value in (("request_id", request_id), ("request_digest", request_digest),
                       ("repository", repository), ("sha", sha.lower()), ("attempt", attempt)):
        if record.get(key) != value:
            raise TryOperationReceiptError(f"TRY operation receipt {key} binding mismatch")
    for key in ("request_digest",):
        if not isinstance(record.get(key), str) or not _HEX64.fullmatch(record[key]):
            raise TryOperationReceiptError(f"TRY operation receipt {key} is malformed")
    for key in ("issued_at", "expires_at"):
        value = record.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise TryOperationReceiptError("TRY operation receipt validity window is invalid")
    if record["expires_at"] <= record["issued_at"] or record["expires_at"] - record["issued_at"] > _MAX_TTL:
        raise TryOperationReceiptError("TRY operation receipt validity window is invalid")
    current_time = time.time() if now is None else now
    if isinstance(current_time, bool) or not isinstance(current_time, (int, float)) or not math.isfinite(current_time):
        raise TryOperationReceiptError("TRY operation receipt verification clock is invalid")
    if current_time > record["expires_at"] or record["issued_at"] > current_time + _CLOCK_SKEW:
        raise TryOperationReceiptError("TRY operation receipt is expired or issued in the future")
    signed = {key: record[key] for key in SIGNED_FIELDS}
    try:
        signature = base64.b64decode(record["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError("Ed25519 signature must be exactly 64 bytes")
        keyring.public_key.verify(signature, canonical_json(signed).encode("utf-8"))
    except (ValueError, binascii.Error, InvalidSignature) as exc:
        raise TryOperationReceiptError("TRY operation receipt signature is invalid") from exc
    state = record.get("status")
    execution_state = record.get("execution_state")
    if state == "COMPLETED":
        if execution_state != "COMPLETED" or not isinstance(record.get("proposal_digest"), str) or not _HEX64.fullmatch(record["proposal_digest"]):
            raise TryOperationReceiptError("TRY COMPLETED receipt lacks proposal binding")
    elif state == "FAILED":
        if execution_state != "NOT_SUBMITTED" or record.get("failure_code") not in {
            "provider_not_configured", "provider_model_not_configured"
        }:
            raise TryOperationReceiptError("TRY FAILED receipt does not prove pre-submission rejection")
    elif state == "UNKNOWN":
        if execution_state != "IN_PROGRESS_OR_AMBIGUOUS":
            raise TryOperationReceiptError("TRY UNKNOWN receipt execution state is invalid")
    else:
        raise TryOperationReceiptError("TRY operation receipt status is invalid")
    return {
        "receipt": record,
        "receipt_digest": receipt_digest(record),
        "status": state,
        "execution_state": execution_state,
        "proven_not_submitted": state == "FAILED" and execution_state == "NOT_SUBMITTED",
    }


__all__ = ["TryOperationReceiptError", "TryOperationReceiptKeyring", "verify_try_operation_receipt",
           "receipt_digest", "RECEIPT_ISSUER", "RECEIPT_SCOPE", "KEYRING_ENV"]
