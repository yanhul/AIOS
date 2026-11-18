"""HMAC binding for same-run pipeline artifacts."""
from __future__ import annotations
import hashlib
import hmac
from typing import Any, Mapping

ATTESTATION_TYPE = "AIOS_PIPELINE_ARTIFACT_ATTESTATION"


def _message(kind: str, run_id: str, digest: str) -> bytes:
    return f"{ATTESTATION_TYPE}\n{kind}\n{run_id}\n{digest}".encode("utf-8")


def attest_artifact(kind: str, run_id: str, digest: str, secret: str) -> dict[str, str]:
    if not all(isinstance(v, str) and v.strip() for v in (kind, run_id, digest)):
        raise ValueError("artifact kind, run_id, and digest are required")
    if not isinstance(secret, str) or len(secret) < 16:
        raise ValueError("artifact signing secret must contain at least 16 characters")
    signature = hmac.new(secret.encode("utf-8"), _message(kind, run_id, digest), hashlib.sha256).hexdigest()
    return {"type": ATTESTATION_TYPE, "algorithm": "HMAC-SHA256", "kind": kind,
            "run_id": run_id, "digest": digest, "signature": signature}


def verify_artifact_attestation(kind: str, run_id: str, digest: str,
                                attestation: Mapping[str, Any] | None, secret: str) -> bool:
    if not isinstance(secret, str) or len(secret) < 16 or not isinstance(attestation, Mapping):
        return False
    if set(attestation) != {"type", "algorithm", "kind", "run_id", "digest", "signature"}:
        return False
    if (attestation.get("type") != ATTESTATION_TYPE or
            attestation.get("algorithm") != "HMAC-SHA256" or
            attestation.get("kind") != kind or attestation.get("run_id") != run_id or
            attestation.get("digest") != digest):
        return False
    expected = hmac.new(secret.encode("utf-8"), _message(kind, run_id, digest), hashlib.sha256).hexdigest()
    return isinstance(attestation.get("signature"), str) and hmac.compare_digest(attestation["signature"], expected)


__all__ = ["ATTESTATION_TYPE", "attest_artifact", "verify_artifact_attestation"]
