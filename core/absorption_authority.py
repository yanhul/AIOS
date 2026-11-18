"""Fail-closed Ed25519 approval, permit signing, and lineage verification.

This module is deliberately separate from the legacy HMAC attestation path.
The signer API accepts immutable data only and never executes candidate code.
Human approval keys and permit-signing keys are separate trust domains.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Mapping

from .mutation import canonical_json

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
except ImportError:  # fail closed; never fall back to HMAC
    InvalidSignature = serialization = Ed25519PrivateKey = Ed25519PublicKey = None

ALGORITHM = "Ed25519"
APPROVAL_TYPE = "AIOS_ABSORPTION_POLICY_APPROVAL"
PERMIT_TYPE = "AIOS_ABSORPTION_PERMIT"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")


class AbsorptionAuthorizationError(ValueError):
    """Approval, policy, key, or lineage validation failed."""


def _require_crypto():
    if Ed25519PrivateKey is None:
        raise AbsorptionAuthorizationError("cryptography/Ed25519 unavailable; DENY")


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return canonical_json(dict(value)).encode("utf-8")


def _key_id(public_key_hex: str) -> str:
    if not isinstance(public_key_hex, str) or not _HEX64.fullmatch(public_key_hex):
        raise AbsorptionAuthorizationError("public key must be 32-byte lowercase hex")
    return "ed25519:" + hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:32]


def _public_hex(private_key) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def policy_digest(policy: Mapping[str, Any]) -> str:
    clean = dict(policy)
    clean.pop("policy_digest", None)
    return "sha256:" + hashlib.sha256(_json_bytes(clean)).hexdigest()


def _validate_policy(policy: Mapping[str, Any]) -> str:
    if not isinstance(policy, Mapping):
        raise AbsorptionAuthorizationError("policy missing; DENY")
    if policy.get("policy_type") != "GOVERNING_POLICY":
        raise AbsorptionAuthorizationError("wrong policy type; DENY")
    digest = policy_digest(policy)
    declared = policy.get("policy_digest")
    if declared is not None and declared != digest:
        raise AbsorptionAuthorizationError("policy digest mismatch; DENY")
    decision = policy.get("decision")
    approval = policy.get("approval")
    if not isinstance(decision, Mapping) or decision.get("default") != "DENY":
        raise AbsorptionAuthorizationError("policy must retain default DENY")
    effects = decision.get("allowed_effects")
    if (not isinstance(effects, list) or not effects or
            any(not isinstance(effect, str) or not effect.strip() for effect in effects) or
            len(set(effects)) != len(effects)):
        raise AbsorptionAuthorizationError("policy effects must be a non-empty unique string list; DENY")
    if not isinstance(approval, Mapping) or approval.get("required") is not True:
        raise AbsorptionAuthorizationError("human approval requirement missing; DENY")
    if policy.get("status") != "APPROVED" or approval.get("status") != "APPROVED":
        raise AbsorptionAuthorizationError("policy is not approved; DENY")
    return digest


def _signed_payload(record: Mapping[str, Any]) -> bytes:
    unsigned = dict(record)
    unsigned.pop("signature", None)
    return _json_bytes(unsigned)


def create_approval_attestation(*, policy: Mapping[str, Any], repository: str,
                                target_branch: str, approver: str, expires_at: int,
                                approval_private_key) -> dict:
    """Create a human approval record. The private key belongs to governance, not CI."""
    _require_crypto()
    if not all(isinstance(x, str) and x.strip() for x in
               (repository, target_branch, approver)):
        raise AbsorptionAuthorizationError("approval identity/scope missing; DENY")
    digest = policy_digest(policy)
    effects = policy.get("decision", {}).get("allowed_effects")
    if not isinstance(effects, list) or not effects:
        raise AbsorptionAuthorizationError("cannot approve an empty-effect policy")
    if isinstance(expires_at, bool) or not isinstance(expires_at, int) or expires_at <= int(time.time()):
        raise AbsorptionAuthorizationError("approval expiry must be a future UTC epoch")
    record = {
        "type": APPROVAL_TYPE, "algorithm": ALGORITHM,
        "key_id": _key_id(_public_hex(approval_private_key)),
        "approver": approver, "policy_digest": digest, "repository": repository,
        "target_branch": target_branch, "allowed_effects": sorted(effects),
        "approved_at": int(time.time()), "expires_at": expires_at,
    }
    record["signature"] = approval_private_key.sign(_signed_payload(record)).hex()
    return record


def _verify_signed_record(record: Mapping[str, Any], keyring: Mapping[str, Any],
                          *, expected_type: str, now: int) -> str:
    _require_crypto()
    if not isinstance(record, Mapping) or record.get("type") != expected_type:
        raise AbsorptionAuthorizationError("signed record type mismatch; DENY")
    required = {"type", "algorithm", "key_id", "signature"}
    if not required.issubset(record) or record.get("algorithm") != ALGORITHM:
        raise AbsorptionAuthorizationError("signed record schema/algorithm invalid; DENY")
    if not isinstance(keyring, Mapping) or not keyring:
        raise AbsorptionAuthorizationError("trust keyring unavailable; DENY")
    entry = keyring.get(record["key_id"])
    if not isinstance(entry, Mapping) or set(entry) != {"public_key", "revoked", "principal"}:
        raise AbsorptionAuthorizationError("issuer is not allowlisted or principal binding is missing; DENY")
    if not isinstance(entry.get("principal"), str) or not entry["principal"].strip():
        raise AbsorptionAuthorizationError("allowlisted principal is missing; DENY")
    if entry.get("revoked") is not False:
        raise AbsorptionAuthorizationError("issuer key revoked or revocation unknown; DENY")
    pub = entry.get("public_key")
    if _key_id(pub) != record["key_id"]:
        raise AbsorptionAuthorizationError("key id/public key mismatch; DENY")
    signature = record.get("signature")
    if not isinstance(signature, str) or not _HEX128.fullmatch(signature):
        raise AbsorptionAuthorizationError("signature malformed; DENY")
    expiry = record.get("expires_at")
    if isinstance(expiry, bool) or not isinstance(expiry, int) or expiry <= now:
        raise AbsorptionAuthorizationError("approval/permit expired; DENY")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(
            bytes.fromhex(signature), _signed_payload(record)
        )
    except (InvalidSignature, ValueError) as exc:
        raise AbsorptionAuthorizationError("signature invalid; DENY") from exc
    return record["key_id"], entry["principal"]


def verify_approval_attestation(*, policy: Mapping[str, Any], approval: Mapping[str, Any],
                                governance_keyring: Mapping[str, Any], repository: str,
                                target_branch: str, now: int | None = None) -> bool:
    timestamp = int(time.time()) if now is None else now
    digest = _validate_policy(policy)
    _, authorized_principal = _verify_signed_record(
        approval, governance_keyring, expected_type=APPROVAL_TYPE, now=timestamp
    )
    approved_at = approval.get("approved_at")
    if isinstance(approved_at, bool) or not isinstance(approved_at, int) or approved_at > timestamp:
        raise AbsorptionAuthorizationError("approval timestamp is invalid or in the future; DENY")
    if approval.get("approver") != authorized_principal:
        raise AbsorptionAuthorizationError("approver does not match governance key allowlist; DENY")
    expected = {
        "policy_digest": digest, "repository": repository,
        "target_branch": target_branch,
        "allowed_effects": sorted(policy["decision"]["allowed_effects"]),
    }
    for field, value in expected.items():
        if approval.get(field) != value:
            raise AbsorptionAuthorizationError(f"approval {field} binding mismatch; DENY")
    if not isinstance(approval.get("approver"), str) or not approval["approver"].strip():
        raise AbsorptionAuthorizationError("approver identity missing; DENY")
    return True


def verify_lineage(*, lineage: Mapping[str, Any], expected_repository: str,
                   expected_run_id: str, expected_commit_sha: str,
                   expected_artifacts: Mapping[str, str]) -> bool:
    """Compare immutable run metadata and every artifact digest to trusted expectations."""
    if not isinstance(lineage, Mapping) or not isinstance(expected_artifacts, Mapping) or not expected_artifacts:
        raise AbsorptionAuthorizationError("lineage or artifact manifest missing; DENY")
    expected = {"repository": expected_repository, "run_id": expected_run_id,
                "source_commit_sha": expected_commit_sha}
    for field, value in expected.items():
        if not isinstance(value, str) or not value or lineage.get(field) != value:
            raise AbsorptionAuthorizationError(f"lineage {field} mismatch; DENY")
    actual = lineage.get("artifacts")
    if not isinstance(actual, Mapping) or set(actual) != set(expected_artifacts):
        raise AbsorptionAuthorizationError("artifact set mismatch; DENY")
    for name, digest in expected_artifacts.items():
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            raise AbsorptionAuthorizationError("expected artifact digest malformed; DENY")
        if actual.get(name) != digest:
            raise AbsorptionAuthorizationError(f"artifact digest mismatch: {name}; DENY")
    return True


def sign_absorption_permit(*, policy: Mapping[str, Any], approval: Mapping[str, Any],
                           governance_keyring: Mapping[str, Any], repository: str,
                           target_branch: str, lineage: Mapping[str, Any],
                           expected_run_id: str, expected_commit_sha: str,
                           expected_artifacts: Mapping[str, str], target_apply_run_id: str, permit_private_key,
                           now: int | None = None) -> dict:
    """Signer entry point. It signs only after independently checking policy, approval and lineage."""
    _require_crypto()
    timestamp = int(time.time()) if now is None else now
    verify_approval_attestation(policy=policy, approval=approval,
                                governance_keyring=governance_keyring,
                                repository=repository, target_branch=target_branch, now=timestamp)
    verify_lineage(lineage=lineage, expected_repository=repository,
                   expected_run_id=expected_run_id, expected_commit_sha=expected_commit_sha,
                   expected_artifacts=expected_artifacts)
    digest = _validate_policy(policy)
    if not isinstance(target_apply_run_id, str) or not target_apply_run_id.strip():
        raise AbsorptionAuthorizationError("target apply run identity missing; DENY")
    record = {
        "type": PERMIT_TYPE, "algorithm": ALGORITHM,
        "key_id": _key_id(_public_hex(permit_private_key)),
        "policy_digest": digest, "repository": repository, "target_branch": target_branch,
        "allowed_effects": sorted(policy["decision"]["allowed_effects"]),
        "run_id": expected_run_id, "target_apply_run_id": target_apply_run_id,
        "source_commit_sha": expected_commit_sha,
        "artifact_digests": dict(sorted(expected_artifacts.items())),
        "approval_key_id": approval["key_id"], "issued_at": timestamp,
        "expires_at": min(approval["expires_at"], timestamp + 900),
    }
    record["signature"] = permit_private_key.sign(_signed_payload(record)).hex()
    return record


def verify_absorption_permit(*, permit: Mapping[str, Any], permit_keyring: Mapping[str, Any],
                             policy: Mapping[str, Any], repository: str, target_branch: str,
                             run_id: str, source_commit_sha: str,
                             artifact_digests: Mapping[str, str], target_apply_run_id: str,
                             now: int | None = None) -> bool:
    timestamp = int(time.time()) if now is None else now
    digest = _validate_policy(policy)
    _verify_signed_record(permit, permit_keyring, expected_type=PERMIT_TYPE, now=timestamp)
    expected = {
        "policy_digest": digest, "repository": repository, "target_branch": target_branch,
        "run_id": run_id, "target_apply_run_id": target_apply_run_id,
        "source_commit_sha": source_commit_sha,
        "artifact_digests": dict(sorted(artifact_digests.items())),
        "allowed_effects": sorted(policy["decision"]["allowed_effects"]),
    }
    for field, value in expected.items():
        if permit.get(field) != value:
            raise AbsorptionAuthorizationError(f"permit {field} binding mismatch; DENY")
    return True


__all__ = ["AbsorptionAuthorizationError", "create_approval_attestation",
           "verify_approval_attestation", "verify_lineage", "sign_absorption_permit",
           "verify_absorption_permit", "policy_digest", "APPROVAL_TYPE", "PERMIT_TYPE"]
