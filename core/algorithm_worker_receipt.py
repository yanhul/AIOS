"""AIOS verification of signed TRY algorithm-worker execution provenance."""
from __future__ import annotations
import base64, binascii, json, math, os, re, time
from collections.abc import Mapping
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .mutation import TransitionError, canonical_json

RECEIPT_TYPE = "TRY_ALGORITHM_EXECUTION_RECEIPT_V1"
RECEIPT_ISSUER = "try.algorithm_executor"
RECEIPT_SCOPE = "try.algorithm.execution.receipt.verify"
KEYRING_ENV = "AIOS_TRY_ALGORITHM_KEYRING"
SIGNED_FIELDS = (
    "type", "issuer", "key_id", "receipt_id", "contract_id", "permit_id",
    "execution_id", "effect_id", "dispatch_id", "dispatch_digest", "attempt_id", "attempt_number", "worker_id",
    "worker_build_sha256", "executor_revision", "executor_sha256",
    "spec_sha256", "input_sha256", "artifact_sha256", "output_sha256",
    "status", "execution_state", "issued_at", "expires_at", "algorithm",
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_GIT_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_RECEIPT_ID = re.compile(r"^TA-[0-9a-f]{32}$")
_MAX_TTL, _CLOCK_SKEW = 900, 60


class AlgorithmWorkerReceiptError(TransitionError):
    pass


class AlgorithmWorkerKeyring:
    """Deployment-pinned Ed25519 public key for the algorithm worker issuer."""
    def __init__(self, issuers: Mapping[str, object]):
        if not isinstance(issuers, Mapping) or RECEIPT_ISSUER not in issuers:
            raise ValueError("algorithm worker receipt issuer is not pinned")
        entry = issuers[RECEIPT_ISSUER]
        if not isinstance(entry, Mapping) or set(entry) - {"public_key", "key_id", "scopes", "revoked"}:
            raise ValueError("algorithm worker receipt key entry is malformed")
        encoded, key_id = entry.get("public_key"), entry.get("key_id")
        scopes, revoked = entry.get("scopes", []), entry.get("revoked", False)
        if not isinstance(encoded, str):
            raise ValueError("algorithm worker public key is missing")
        try:
            raw = base64.b64decode(encoded, validate=True)
            if len(raw) != 32:
                raise ValueError("Ed25519 public key must be 32 bytes")
            self.public_key = Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("algorithm worker public key is invalid") from exc
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("algorithm worker key_id is missing")
        if not isinstance(scopes, list) or RECEIPT_SCOPE not in scopes:
            raise ValueError("algorithm worker receipt scope is missing")
        if not isinstance(revoked, bool):
            raise ValueError("algorithm worker revoked flag is invalid")
        self.key_id, self.revoked = key_id, revoked

    @classmethod
    def from_env(cls, environ=None):
        raw = (os.environ if environ is None else environ).get(KEYRING_ENV)
        if not raw:
            raise AlgorithmWorkerReceiptError(f"{KEYRING_ENV} is not configured")
        try:
            return cls(json.loads(raw))
        except (ValueError, TypeError) as exc:
            raise AlgorithmWorkerReceiptError(f"{KEYRING_ENV} is invalid: {exc}") from exc


def _digest(value):
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def verify_algorithm_worker_receipt(receipt, *, expected, keyring=None, now=None):
    """Verify signature and immutable bindings reconstructed from AIOS records."""
    if not isinstance(receipt, Mapping) or set(receipt) != set(SIGNED_FIELDS) | {"signature"}:
        raise AlgorithmWorkerReceiptError("algorithm worker receipt schema mismatch")
    required = {
        "contract_id", "permit_id", "execution_id", "effect_id", "dispatch_id", "dispatch_digest", "attempt_id", "attempt_number",
        "worker_id", "worker_build_sha256", "executor_revision", "executor_sha256",
        "spec_sha256", "input_sha256",
    }
    if not isinstance(expected, Mapping) or not required.issubset(expected):
        raise AlgorithmWorkerReceiptError("persisted expected bindings are incomplete")
    record = dict(receipt)
    if (record.get("type") != RECEIPT_TYPE or record.get("issuer") != RECEIPT_ISSUER
            or record.get("algorithm") != "Ed25519"
            or not isinstance(record.get("receipt_id"), str)
            or not _RECEIPT_ID.fullmatch(record["receipt_id"])
            or not isinstance(record.get("signature"), str)):
        raise AlgorithmWorkerReceiptError("algorithm worker receipt identity/signature is malformed")
    if keyring is None:
        keyring = AlgorithmWorkerKeyring.from_env()
    if not isinstance(keyring, AlgorithmWorkerKeyring) or keyring.revoked:
        raise AlgorithmWorkerReceiptError("algorithm worker receipt trust anchor unavailable or revoked")
    if record.get("key_id") != keyring.key_id:
        raise AlgorithmWorkerReceiptError("algorithm worker receipt key_id is not pinned")
    for field in required:
        if record.get(field) != expected[field]:
            raise AlgorithmWorkerReceiptError(f"algorithm worker receipt {field} binding mismatch")
    if isinstance(record.get("attempt_number"), bool) or not isinstance(record.get("attempt_number"), int) or record["attempt_number"] < 1:
        raise AlgorithmWorkerReceiptError("algorithm worker attempt_number is invalid")
    if not isinstance(record.get("worker_id"), str) or not record["worker_id"].strip():
        raise AlgorithmWorkerReceiptError("algorithm worker identity is invalid")
    for field in ("dispatch_digest", "worker_build_sha256", "executor_sha256", "spec_sha256", "input_sha256"):
        if not _digest(record.get(field)):
            raise AlgorithmWorkerReceiptError(f"algorithm worker {field} is malformed")
    if not isinstance(record.get("executor_revision"), str) or not _GIT_REVISION.fullmatch(record["executor_revision"]):
        raise AlgorithmWorkerReceiptError("algorithm worker executor_revision is malformed")
    status, execution_state = record.get("status"), record.get("execution_state")
    if status == "COMPLETED":
        if execution_state != "COMPLETED" or not _digest(record.get("artifact_sha256")) or not _digest(record.get("output_sha256")):
            raise AlgorithmWorkerReceiptError("COMPLETED receipt lacks artifact/output binding")
    elif status == "UNKNOWN":
        if execution_state != "IN_PROGRESS_OR_AMBIGUOUS" or record.get("artifact_sha256") is not None or record.get("output_sha256") is not None:
            raise AlgorithmWorkerReceiptError("UNKNOWN receipt execution state is invalid")
    else:
        raise AlgorithmWorkerReceiptError("algorithm worker receipt status is invalid")
    for field in ("issued_at", "expires_at"):
        value = record.get(field)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise AlgorithmWorkerReceiptError("algorithm worker receipt validity window is invalid")
    if record["expires_at"] <= record["issued_at"] or record["expires_at"] - record["issued_at"] > _MAX_TTL:
        raise AlgorithmWorkerReceiptError("algorithm worker receipt validity window is invalid")
    current = time.time() if now is None else now
    if isinstance(current, bool) or not isinstance(current, (int, float)) or not math.isfinite(current):
        raise AlgorithmWorkerReceiptError("algorithm worker verification clock is invalid")
    if current > record["expires_at"] or record["issued_at"] > current + _CLOCK_SKEW:
        raise AlgorithmWorkerReceiptError("algorithm worker receipt is expired or issued in the future")
    signed = {field: record[field] for field in SIGNED_FIELDS}
    try:
        signature = base64.b64decode(record["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError("Ed25519 signature must be 64 bytes")
        keyring.public_key.verify(signature, canonical_json(signed).encode("utf-8"))
    except (ValueError, binascii.Error, InvalidSignature) as exc:
        raise AlgorithmWorkerReceiptError("algorithm worker receipt signature is invalid") from exc
    return {
        "status": "INDEPENDENTLY_AUTHENTICATED" if status == "COMPLETED" else "UNKNOWN",
        "receipt_id": record["receipt_id"], "worker_id": record["worker_id"],
        "execution_id": record["execution_id"], "attempt_id": record["attempt_id"],
        "attempt_number": record["attempt_number"],
        "artifact_sha256": record["artifact_sha256"], "output_sha256": record["output_sha256"],
        "retry_authorized": False, "promotion": "NOT_AUTHORIZED",
    }


__all__ = ["AlgorithmWorkerReceiptError", "AlgorithmWorkerKeyring",
           "verify_algorithm_worker_receipt", "RECEIPT_ISSUER", "RECEIPT_SCOPE",
           "KEYRING_ENV", "SIGNED_FIELDS"]
