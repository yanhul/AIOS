"""Verification of externally issued, Ed25519-signed AIOS authority bundles.

The issuer lives outside AIOS. This module is verifier-only: it never creates
keys, capabilities, policies, contracts, permits, or signatures.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contract import validate_contract, verify_permit
from .mutation import canonical_json
from .policy_registry import policy_digest

BUNDLE_TYPE = "AIOS_EXTERNAL_AUTHORITY_BUNDLE"
BUNDLE_ALGORITHM = "Ed25519"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")


class AuthorityBundleError(ValueError):
    """An authority bundle is missing, malformed, untrusted, or misbound."""


def key_id_for(public_key_hex: str) -> str:
    if not isinstance(public_key_hex, str) or not _HEX64.fullmatch(public_key_hex):
        raise AuthorityBundleError("trust anchor public key must be 32-byte lowercase hex")
    return "ed25519:" + hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:32]


def _signed_bytes(payload: dict[str, Any]) -> bytes:
    return canonical_json(payload).encode("utf-8")


def verify_authority_bundle(
    envelope: dict[str, Any],
    *,
    trusted_issuer: str,
    trusted_public_key_hex: str,
    expected_repository: str,
    expected_run_id: int,
    expected_base_sha: str,
    expected_source_branch: str,
    expected_store_commit: str,
) -> dict[str, Any]:
    """Verify signature, authority semantics, and immutable source/store bindings."""
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise AuthorityBundleError("bundle envelope schema mismatch")
    payload, signature = envelope["payload"], envelope["signature"]
    if not isinstance(payload, dict) or not isinstance(signature, dict):
        raise AuthorityBundleError("bundle payload/signature must be objects")
    if set(signature) != {"algorithm", "key_id", "value"}:
        raise AuthorityBundleError("signature schema mismatch")
    if signature["algorithm"] != BUNDLE_ALGORITHM:
        raise AuthorityBundleError("unsupported authority signature algorithm")
    key_id = key_id_for(trusted_public_key_hex)
    if signature["key_id"] != key_id:
        raise AuthorityBundleError("authority signing key is not the pinned trust anchor")
    if not isinstance(signature["value"], str) or not _HEX128.fullmatch(signature["value"]):
        raise AuthorityBundleError("Ed25519 signature is malformed")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_public_key_hex)).verify(
            bytes.fromhex(signature["value"]), _signed_bytes(payload)
        )
    except (InvalidSignature, ValueError) as exc:
        raise AuthorityBundleError("authority bundle signature verification failed") from exc

    required = {
        "bundle_type", "schema_version", "issuer", "repository", "source_run",
        "target", "issued_at", "expires_at", "authority_records",
    }
    if set(payload) != required:
        raise AuthorityBundleError("authority payload schema mismatch")
    if payload["bundle_type"] != BUNDLE_TYPE or payload["schema_version"] != 1:
        raise AuthorityBundleError("unsupported authority bundle type/version")
    if payload["issuer"] != trusted_issuer:
        raise AuthorityBundleError("issuer identity mismatch")
    if payload["repository"] != expected_repository:
        raise AuthorityBundleError("repository binding mismatch")
    run = payload["source_run"]
    target = payload["target"]
    if not isinstance(run, dict) or set(run) != {"id", "workflow_path", "event", "conclusion", "head_sha", "head_branch"}:
        raise AuthorityBundleError("source run schema mismatch")
    if run["id"] != expected_run_id or run["conclusion"] != "failure":
        raise AuthorityBundleError("source run ID/conclusion mismatch")
    if run["head_sha"] != expected_base_sha or run["head_branch"] != expected_source_branch:
        raise AuthorityBundleError("source run SHA/branch mismatch")
    if run["workflow_path"] not in {".github/workflows/ci.yml", ".github/workflows/g4a-ci.yml"}:
        raise AuthorityBundleError("source workflow is not approved")
    if run["event"] not in {"push", "pull_request", "workflow_dispatch"}:
        raise AuthorityBundleError("source event is not eligible")
    if not isinstance(target, dict) or set(target) != {"base_sha", "store_commit"}:
        raise AuthorityBundleError("target binding schema mismatch")
    if target["base_sha"] != expected_base_sha or target["store_commit"] != expected_store_commit:
        raise AuthorityBundleError("immutable target/store commit binding mismatch")
    if not _HEX64.fullmatch(expected_base_sha) or not _HEX40.fullmatch(expected_store_commit):
        raise AuthorityBundleError("expected commit SHA is malformed")
    if not isinstance(payload["issued_at"], int) or not isinstance(payload["expires_at"], int):
        raise AuthorityBundleError("bundle validity timestamps must be integer epoch seconds")
    if payload["expires_at"] <= payload["issued_at"]:
        raise AuthorityBundleError("bundle validity interval is invalid")

    records = payload["authority_records"]
    if not isinstance(records, dict) or set(records) != {"capability_registry", "policy", "contract", "permit"}:
        raise AuthorityBundleError("authority records schema mismatch")
    contract, permit, policy, registry = (
        records["contract"], records["permit"], records["policy"], records["capability_registry"]
    )
    try:
        validate_contract(contract)
        verify_permit(contract, permit)
    except (TypeError, ValueError, KeyError) as exc:
        raise AuthorityBundleError(f"contract/permit validation failed: {exc}") from exc
    if not isinstance(policy, dict):
        raise AuthorityBundleError("governing policy must be an object")
    policy_body = dict(policy)
    digest = policy_body.pop("policy_digest", None)
    if digest != contract["policy_digest"] or policy_digest(policy_body) != digest:
        raise AuthorityBundleError("governing policy content digest mismatch")
    if not isinstance(registry, dict) or registry.get("schema_version") != 1:
        raise AuthorityBundleError("capability registry schema mismatch")
    caps = registry.get("capabilities")
    if not isinstance(caps, list):
        raise AuthorityBundleError("capability registry capabilities missing")
    active = [
        c for c in caps if isinstance(c, dict)
        and c.get("capability_id") == "repo_patch" and c.get("version") == "1"
        and c.get("status") == "ACTIVE"
    ]
    if len(active) != 1 or "repo_patch@1" not in contract["capabilities"]:
        raise AuthorityBundleError("issuer did not authorize exactly the required repo_patch@1 capability")
    return payload


_HEX40 = re.compile(r"[0-9a-f]{40}")


__all__ = ["AuthorityBundleError", "BUNDLE_TYPE", "key_id_for", "verify_authority_bundle"]
