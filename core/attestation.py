"""External authority attestation for AIOS execution permits.

The contract/permit objects define what is allowed. This module adds an
optional deployment-bound authenticity proof so downstream runtimes can
reject copied or locally fabricated permit records.

The secret is supplied by the deployment (for example an environment secret)
and is never stored in AIOS state or exposed to agents. Governing policy,
contract criteria, and terminal conditions remain outside this module.
"""
from __future__ import annotations

import hashlib
import hmac

from .contract import verify_permit

ATTESTATION_TYPE = "EXECUTION_PERMIT_ATTESTATION"


def _message(contract_id: str, permit_id: str, issuer: str) -> bytes:
    return f"{contract_id}\n{permit_id}\n{issuer}".encode("utf-8")


def issue_attestation(contract: dict, permit: dict, secret: str) -> dict:
    """Create an authenticity proof for an already valid permit."""
    if not isinstance(secret, str) or not secret:
        raise ValueError("attestation secret must be non-empty")
    verify_permit(contract, permit)
    msg = _message(permit["contract_id"], permit["permit_id"], permit["issuer"])
    signature = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return {
        "attestation_type": ATTESTATION_TYPE,
        "contract_id": permit["contract_id"],
        "permit_id": permit["permit_id"],
        "issuer": permit["issuer"],
        "algorithm": "HMAC-SHA256",
        "signature": signature,
    }


def verify_attestation(contract: dict, permit: dict, attestation: dict, secret: str) -> bool:
    """Fail closed unless permit binding and external attestation both verify."""
    if not isinstance(secret, str) or not secret:
        raise ValueError("attestation secret must be non-empty")
    verify_permit(contract, permit)
    required = {
        "attestation_type", "contract_id", "permit_id", "issuer",
        "algorithm", "signature",
    }
    if set(attestation) != required:
        raise ValueError("attestation schema mismatch")
    if attestation["attestation_type"] != ATTESTATION_TYPE:
        raise ValueError("attestation type mismatch")
    if attestation["algorithm"] != "HMAC-SHA256":
        raise ValueError("attestation algorithm mismatch")
    if (attestation["contract_id"], attestation["permit_id"], attestation["issuer"]) != (
        permit["contract_id"], permit["permit_id"], permit["issuer"]
    ):
        raise ValueError("attestation is not bound to permit")
    msg = _message(permit["contract_id"], permit["permit_id"], permit["issuer"])
    expected = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(attestation["signature"], expected):
        raise ValueError("attestation signature mismatch")
    return True


__all__ = ["ATTESTATION_TYPE", "issue_attestation", "verify_attestation"]
