"""Verification of externally issued, Ed25519-signed AIOS authority bundles.

The issuer lives outside AIOS. This module is verifier-only: it never creates
keys, capabilities, policies, contracts, permits, or signatures.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
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


def load_trust_anchor(path: str | Path, issuer: str) -> str:
    """Load a committed, explicit trust anchor; UNPROVISIONED never verifies."""
    try:
        spec = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AuthorityBundleError("authority trust-anchor file is unavailable or malformed") from exc
    if not isinstance(spec, dict) or spec.get("schema_version") != 1:
        raise AuthorityBundleError("authority trust-anchor schema mismatch")
    entry = (spec.get("issuers") or {}).get(issuer)
    if not isinstance(entry, dict) or entry.get("status") != "ACTIVE":
        raise AuthorityBundleError("external authority issuer is not provisioned/ACTIVE")
    public_key = entry.get("public_key_hex")
    if entry.get("key_id") != key_id_for(public_key):
        raise AuthorityBundleError("committed authority trust-anchor key ID mismatch")
    return public_key


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
    now: int | None = None,
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
    branch = run["head_branch"]
    if branch != "main" and not (
        isinstance(branch, str) and branch.startswith("aios/autorepair/")
        and len(branch) > len("aios/autorepair/")
    ):
        raise AuthorityBundleError("source branch is outside the issuer allowlist")
    if not isinstance(target, dict) or set(target) != {"base_sha"}:
        raise AuthorityBundleError("target binding schema mismatch")
    if target["base_sha"] != expected_base_sha:
        raise AuthorityBundleError("immutable target/store commit binding mismatch")
    if not isinstance(expected_base_sha, str) or not _HEX40.fullmatch(expected_base_sha):
        raise AuthorityBundleError("expected source base commit SHA is malformed")
    if not isinstance(expected_store_commit, str) or not _HEX40.fullmatch(expected_store_commit):
        raise AuthorityBundleError("expected immutable store commit SHA is malformed")
    if not isinstance(payload["issued_at"], int) or not isinstance(payload["expires_at"], int):
        raise AuthorityBundleError("bundle validity timestamps must be integer epoch seconds")
    current = int(time.time()) if now is None else now
    if payload["expires_at"] <= payload["issued_at"] or current < payload["issued_at"] or current >= payload["expires_at"]:
        raise AuthorityBundleError("bundle is not currently valid or validity interval is invalid")
    if not isinstance(expected_store_commit, str) or not _HEX40.fullmatch(expected_store_commit):
        raise AuthorityBundleError("expected immutable store commit SHA is malformed")

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
    if (
        policy_body.get("policy_type") != "GOVERNING_POLICY"
        or policy_body.get("issuer") != trusted_issuer
        or policy_body.get("repository") != expected_repository
        or policy_body.get("source_run_id") != expected_run_id
        or policy_body.get("base_sha") != expected_base_sha
        or policy_body.get("allowed_effects") != ["external_effect"]
        or policy_body.get("allowed_capabilities") != ["repo_patch@1"]
        or policy_body.get("max_attempts") != 3
        or policy_body.get("require_observed_success") is not True
        or not isinstance(policy_body.get("denied_paths"), list)
        or not {".github/workflows/", ".aios/", "secrets/"}.issubset(set(policy_body["denied_paths"]))
    ):
        raise AuthorityBundleError("governing policy exceeds or mismatches the approved issuer scope")
    if (
        contract.get("actor") != "ci-repair-worker"
        or contract.get("scope") != "repository"
        or contract.get("capabilities") != ["repo_patch@1"]
        or contract.get("allowed_effects") != ["external_effect"]
        or contract.get("max_attempts") != 3
        or "OBSERVED" not in contract.get("evidence_required", [])
    ):
        raise AuthorityBundleError("execution contract exceeds the approved repair scope")
    if permit.get("issuer") != trusted_issuer:
        raise AuthorityBundleError("permit issuer identity does not match signed bundle issuer")
    if not isinstance(registry, dict) or registry.get("schema_version") != 1:
        raise AuthorityBundleError("capability registry schema mismatch")
    if registry.get("persisted_by") != trusted_issuer:
        raise AuthorityBundleError("capability registry persistence issuer mismatch")
    caps = registry.get("capabilities")
    if not isinstance(caps, list) or len(caps) != 1 or not isinstance(caps[0], dict):
        raise AuthorityBundleError("capability registry must contain exactly one scoped capability")
    capability = caps[0]
    if (
        capability.get("capability_id") != "repo_patch"
        or capability.get("version") != "1"
        or capability.get("owner") != trusted_issuer
        or capability.get("kind") != "external_effect"
        or capability.get("status") != "ACTIVE"
        or capability.get("permissions") != ["repository_patch"]
        or capability.get("environments") != ["github-actions"]
        or capability.get("verification_methods") != ["independent_full_suite"]
        or capability.get("evidence_requirements") != ["OBSERVED_SUCCESS"]
    ):
        raise AuthorityBundleError("issuer did not authorize the exact approved repo_patch@1 capability")
    return payload


_HEX40 = re.compile(r"[0-9a-f]{40}")


__all__ = ["AuthorityBundleError", "BUNDLE_TYPE", "key_id_for", "load_trust_anchor", "verify_authority_bundle"]


def import_verified_authority_bundle(
    envelope: dict[str, Any],
    *,
    aios_dir: str | Path,
    trust_anchor_path: str | Path,
    trusted_issuer: str,
    expected_repository: str,
    expected_run_id: int,
    expected_base_sha: str,
    expected_source_branch: str,
    expected_store_commit: str,
    now: int | None = None,
) -> dict[str, Any]:
    """Verify then atomically materialize the exact signed records into AIOS state.

    No record is written until signature, scope, registry, policy, contract and
    permit have passed preflight. Existing conflicting identities fail closed.
    """
    from .authority import authorize, load_contract, load_permit
    from .capabilities import CapabilityRegistry
    from .contract import contract_identity, issue_permit
    from .mutation import commit_batch
    from .policy_registry import POLICIES_DIR
    import os

    public_key = load_trust_anchor(trust_anchor_path, trusted_issuer)
    payload = verify_authority_bundle(
        envelope,
        trusted_issuer=trusted_issuer,
        trusted_public_key_hex=public_key,
        expected_repository=expected_repository,
        expected_run_id=expected_run_id,
        expected_base_sha=expected_base_sha,
        expected_source_branch=expected_source_branch,
        expected_store_commit=expected_store_commit,
        now=now,
    )
    records = payload["authority_records"]
    registry_record = records["capability_registry"]
    policy_record = records["policy"]
    contract = records["contract"]
    permit = records["permit"]

    # Validate using AIOS's own parsers and identity functions before any write.
    registry_path = Path(aios_dir) / "capabilities" / "capability_registry.json"
    registry = CapabilityRegistry()
    if registry_record.get("schema_version") != 1 or registry_record.get("persisted_by") != trusted_issuer:
        raise AuthorityBundleError("capability registry provenance/schema mismatch")
    if not isinstance(registry_record.get("capabilities"), list) or not isinstance(registry_record.get("edges"), list):
        raise AuthorityBundleError("capability registry collections malformed")
    from .capabilities import Capability, CapabilityEdge
    for raw in registry_record["capabilities"]:
        registry.register(Capability.from_dict(raw))
    for raw in registry_record["edges"]:
        registry.add_edge(CapabilityEdge.from_dict(raw))
    if registry.snapshot() != {"capabilities": registry_record["capabilities"], "edges": registry_record["edges"]}:
        raise AuthorityBundleError("capability registry is not canonical")
    if policy_record.get("policy_digest") != contract.get("policy_digest"):
        raise AuthorityBundleError("policy/contract digest binding mismatch")
    policy_body = dict(policy_record)
    policy_body.pop("policy_digest", None)
    if policy_digest(policy_body) != contract["policy_digest"]:
        raise AuthorityBundleError("policy digest does not match AIOS canonical policy")
    validate_contract(contract)
    if issue_permit(contract, trusted_issuer) != permit:
        raise AuthorityBundleError("permit is not the deterministic AIOS-issued permit for this contract")

    cid = contract_identity(contract)
    pid = permit["permit_id"]
    root = Path(aios_dir)
    entries = [
        ("capabilities/capability_registry.json", registry_record),
        (f"{POLICIES_DIR}/{contract['policy_digest']}.json", policy_record),
        (f"authority/contracts/{cid}.json", {**contract, "record_type": "EXECUTION_CONTRACT", "contract_id": cid}),
        (f"authority/permits/{pid}.json", permit),
    ]
    for relative, record in entries:
        target = root / relative
        if target.exists():
            try:
                existing = json.loads(target.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise AuthorityBundleError(f"existing AIOS authority record is unreadable: {relative}") from exc
            if canonical_json(existing) != canonical_json(record):
                raise AuthorityBundleError(f"conflicting existing AIOS authority record: {relative}")

    # Re-check every destination while commit_batch holds AIOS's mutation lock.
    # The earlier preflight is only an early diagnostic; this locked check closes
    # the TOCTOU window between inspection and the atomic write.
    def _locked_precondition(locked_root: str) -> None:
        locked_base = Path(locked_root)
        for relative, record in entries:
            target = locked_base / relative
            if not target.exists():
                continue
            try:
                existing = json.loads(target.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise AuthorityBundleError(
                    f"existing AIOS authority record is unreadable: {relative}"
                ) from exc
            if canonical_json(existing) != canonical_json(record):
                raise AuthorityBundleError(
                    f"conflicting existing AIOS authority record: {relative}"
                )

    # One AIOS transaction prevents a partially imported capability/policy/contract/permit set.
    pending = [(relative, record) for relative, record in entries if not (root / relative).exists()]
    if pending:
        commit_batch(str(root), pending, precondition=_locked_precondition)

    # Independent readback through normal AIOS authority loaders and authorization.
    try:
        loaded_contract = load_contract(str(root), cid)
        loaded_permit = load_permit(str(root), pid)
        authorize(str(root), cid, pid)
    except Exception as exc:
        raise AuthorityBundleError(f"AIOS post-commit authority readback failed: {exc}") from exc
    if canonical_json(loaded_contract) != canonical_json(contract) or canonical_json(loaded_permit) != canonical_json(permit):
        raise AuthorityBundleError("AIOS post-commit readback differs from signed authority bundle")
    return {
        "state": "AUTHORITY_IMPORTED_AND_READ_BACK",
        "contract_id": cid,
        "permit_id": pid,
        "policy_digest": contract["policy_digest"],
        "capability_registry_path": str(registry_path),
        "store_commit": expected_store_commit,
    }
