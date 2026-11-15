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
from .attestation import verify_attestation
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



def verify_immutable_store_object(
    envelope: dict[str, Any],
    *,
    repository: str,
    bundle_commit: str,
    signed_store_parent: str,
    bundle_path: str,
    github_token: str,
) -> dict[str, str]:
    """Verify a bundle against the actual GitHub commit, tree, and blob objects.

    The signed parent SHA comes from the verified envelope. The bundle commit
    and path are locators only: their relationship and contents are fetched
    independently from GitHub's Git database API.
    """
    import base64
    import urllib.error
    import urllib.request

    if not isinstance(repository, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise AuthorityBundleError("store repository identifier is malformed")
    if not isinstance(bundle_commit, str) or not _HEX40.fullmatch(bundle_commit):
        raise AuthorityBundleError("bundle-containing commit SHA is malformed")
    if not isinstance(signed_store_parent, str) or not _HEX40.fullmatch(signed_store_parent):
        raise AuthorityBundleError("signed store parent SHA is malformed")
    if not isinstance(bundle_path, str) or not bundle_path.startswith("authority/issued/") or ".." in bundle_path.split("/"):
        raise AuthorityBundleError("immutable bundle path is outside the issued-bundle namespace")
    if not isinstance(github_token, str) or not github_token.strip():
        raise AuthorityBundleError("GitHub read token is required for immutable store verification")

    def get_json(url: str) -> dict[str, Any]:
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                value = json.loads(response.read())
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise AuthorityBundleError("GitHub immutable store evidence could not be fetched") from exc
        if not isinstance(value, dict):
            raise AuthorityBundleError("GitHub immutable store response is malformed")
        return value

    root = f"https://api.github.com/repos/{repository}"
    commit = get_json(f"{root}/git/commits/{bundle_commit}")
    parents = commit.get("parents")
    tree_sha = (commit.get("tree") or {}).get("sha")
    if not isinstance(parents, list) or len(parents) != 1 or (parents[0] or {}).get("sha") != signed_store_parent:
        raise AuthorityBundleError("bundle commit is not a direct child of the signed store parent")
    if not isinstance(tree_sha, str) or not _HEX40.fullmatch(tree_sha):
        raise AuthorityBundleError("bundle commit tree SHA is malformed")

    # The issuer storage commit must be a single-purpose commit: exactly one
    # direct child of the signed parent, adding only this immutable bundle.
    # This prevents piggybacking workflow/policy/source changes into the
    # commit that is being accepted as the storage event.
    comparison = get_json(f"{root}/compare/{signed_store_parent}...{bundle_commit}")
    changed_files = comparison.get("files")
    if (
        comparison.get("status") != "ahead"
        or comparison.get("ahead_by") != 1
        or comparison.get("total_commits") != 1
        or not isinstance(changed_files, list)
        or len(changed_files) != 1
        or not isinstance(changed_files[0], dict)
        or changed_files[0].get("filename") != bundle_path
        or changed_files[0].get("status") != "added"
    ):
        raise AuthorityBundleError("bundle commit must add only the exact issued bundle to the signed parent")

    tree = get_json(f"{root}/git/trees/{tree_sha}?recursive=1")
    if tree.get("truncated") is True or not isinstance(tree.get("tree"), list):
        raise AuthorityBundleError("GitHub bundle tree is truncated or malformed")
    matches = [entry for entry in tree["tree"] if isinstance(entry, dict) and entry.get("path") == bundle_path]
    if len(matches) != 1 or matches[0].get("type") != "blob":
        raise AuthorityBundleError("exact immutable bundle path is missing or ambiguous")
    blob_sha = matches[0].get("sha")
    if not isinstance(blob_sha, str) or not _HEX40.fullmatch(blob_sha):
        raise AuthorityBundleError("immutable bundle blob SHA is malformed")

    blob = get_json(f"{root}/git/blobs/{blob_sha}")
    if blob.get("encoding") != "base64" or not isinstance(blob.get("content"), str):
        raise AuthorityBundleError("GitHub immutable bundle blob encoding is unsupported")
    try:
        content = base64.b64decode("".join(blob["content"].split()), validate=True)
    except (ValueError, TypeError) as exc:
        raise AuthorityBundleError("GitHub immutable bundle blob is malformed") from exc
    actual_blob_sha = hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()
    if actual_blob_sha != blob_sha:
        raise AuthorityBundleError("GitHub immutable bundle blob hash mismatch")
    try:
        stored_envelope = json.loads(content)
    except (UnicodeDecodeError, ValueError) as exc:
        raise AuthorityBundleError("stored immutable bundle is not valid JSON") from exc
    if stored_envelope != envelope:
        raise AuthorityBundleError("stored immutable bundle content differs from the verified envelope")
    return {
        "repository": repository,
        "signed_store_parent": signed_store_parent,
        "bundle_commit": bundle_commit,
        "bundle_path": bundle_path,
        "bundle_blob_sha": blob_sha,
    }



def verify_issuer_receipt(
    *,
    trusted_issuer: str,
    trusted_public_key_hex: str,
    repository: str,
    bundle_commit: str,
    bundle_path: str,
    bundle_blob_sha: str,
    expected_store_parent: str,
    expected_source_run_id: int,
    expected_source_target_sha: str,
    receipt_commit: str,
    receipt_path: str,
    github_token: str,
) -> dict[str, str]:
    """Verify the issuer-signed post-commit receipt and its immutable Git object."""
    import base64
    import urllib.error
    import urllib.request

    for name, value in (("bundle commit", bundle_commit), ("receipt commit", receipt_commit),
                        ("bundle blob", bundle_blob_sha)):
        if not isinstance(value, str) or not _HEX40.fullmatch(value):
            raise AuthorityBundleError(f"{name} SHA is malformed")
    expected_receipt_path = bundle_path.replace("authority/issued/", "authority/receipts/", 1)
    if receipt_path != expected_receipt_path or not receipt_path.endswith(".json"):
        raise AuthorityBundleError("issuer receipt path does not match the issued bundle identity")
    if not isinstance(github_token, str) or not github_token.strip():
        raise AuthorityBundleError("GitHub read token is required for issuer receipt verification")

    def get_json(url: str) -> dict[str, Any]:
        request = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                value = json.loads(response.read())
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise AuthorityBundleError("GitHub issuer receipt evidence could not be fetched") from exc
        if not isinstance(value, dict):
            raise AuthorityBundleError("GitHub issuer receipt response is malformed")
        return value

    root = f"https://api.github.com/repos/{repository}"
    commit = get_json(f"{root}/git/commits/{receipt_commit}")
    parents = commit.get("parents")
    tree_sha = (commit.get("tree") or {}).get("sha")
    if not isinstance(parents, list) or len(parents) != 1 or (parents[0] or {}).get("sha") != bundle_commit:
        raise AuthorityBundleError("issuer receipt commit is not a direct child of the bundle commit")
    comparison = get_json(f"{root}/compare/{bundle_commit}...{receipt_commit}")
    files = comparison.get("files")
    if (comparison.get("status") != "ahead" or comparison.get("ahead_by") != 1
            or comparison.get("total_commits") != 1 or not isinstance(files, list) or len(files) != 1
            or not isinstance(files[0], dict) or files[0].get("filename") != receipt_path
            or files[0].get("status") != "added"):
        raise AuthorityBundleError("receipt commit must add only the exact signed issuer receipt")
    if not isinstance(tree_sha, str) or not _HEX40.fullmatch(tree_sha):
        raise AuthorityBundleError("issuer receipt tree SHA is malformed")
    tree = get_json(f"{root}/git/trees/{tree_sha}?recursive=1")
    if tree.get("truncated") is True or not isinstance(tree.get("tree"), list):
        raise AuthorityBundleError("issuer receipt tree is truncated or malformed")
    matches = [entry for entry in tree["tree"] if isinstance(entry, dict) and entry.get("path") == receipt_path]
    if len(matches) != 1 or matches[0].get("type") != "blob":
        raise AuthorityBundleError("exact immutable issuer receipt path is missing or ambiguous")
    blob_sha = matches[0].get("sha")
    if not isinstance(blob_sha, str) or not _HEX40.fullmatch(blob_sha):
        raise AuthorityBundleError("issuer receipt blob SHA is malformed")
    blob = get_json(f"{root}/git/blobs/{blob_sha}")
    if blob.get("encoding") != "base64" or not isinstance(blob.get("content"), str):
        raise AuthorityBundleError("issuer receipt blob encoding is unsupported")
    try:
        content = base64.b64decode("".join(blob["content"].split()), validate=True)
        receipt = json.loads(content)
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        raise AuthorityBundleError("issuer receipt blob is malformed") from exc
    actual_sha = hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()
    if actual_sha != blob_sha:
        raise AuthorityBundleError("issuer receipt blob hash mismatch")
    if not isinstance(receipt, dict) or set(receipt) != {"payload", "signature"}:
        raise AuthorityBundleError("issuer receipt envelope schema mismatch")
    payload, signature = receipt["payload"], receipt["signature"]
    required = {"receipt_type", "schema_version", "issuer", "repository", "bundle_commit",
                "bundle_path", "bundle_blob_sha", "signed_store_parent", "source_run_id",
                "source_target_sha", "issuer_workflow_run_id"}
    if not isinstance(payload, dict) or set(payload) != required:
        raise AuthorityBundleError("issuer receipt payload schema mismatch")
    if (payload["receipt_type"] != "AIOS_AUTHORITY_ISSUANCE_RECEIPT" or payload["schema_version"] != 1
            or payload["issuer"] != trusted_issuer or payload["repository"] != repository
            or payload["bundle_commit"] != bundle_commit or payload["bundle_path"] != bundle_path
            or payload["bundle_blob_sha"] != bundle_blob_sha
            or payload["signed_store_parent"] != expected_store_parent
            or payload["source_run_id"] != expected_source_run_id
            or payload["source_target_sha"] != expected_source_target_sha
            or type(payload["issuer_workflow_run_id"]) is not int
            or payload["issuer_workflow_run_id"] < 1):
        raise AuthorityBundleError("issuer receipt is misbound to the immutable bundle/source run")
    if (not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "value"}
            or signature["algorithm"] != BUNDLE_ALGORITHM
            or signature["key_id"] != key_id_for(trusted_public_key_hex)
            or not isinstance(signature["value"], str) or not _HEX128.fullmatch(signature["value"])):
        raise AuthorityBundleError("issuer receipt signature metadata is invalid")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_public_key_hex)).verify(
            bytes.fromhex(signature["value"]), _signed_bytes(payload))
    except (InvalidSignature, ValueError) as exc:
        raise AuthorityBundleError("issuer receipt signature verification failed") from exc
    return {"receipt_commit": receipt_commit, "receipt_path": receipt_path,
            "receipt_blob_sha": blob_sha, "bundle_commit": bundle_commit,
            "bundle_blob_sha": bundle_blob_sha}

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
    attestation_secret: str,
    now: int | None = None,
) -> dict[str, Any]:
    """Verify signature, HMAC permit attestation, authority semantics and source/store bindings."""
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
        "target", "store_commit", "approval", "issued_at", "expires_at", "authority_records",
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
    approval = payload["approval"]
    if not isinstance(approval, dict) or set(approval) != {
        "pr_number", "pr_url", "head_sha", "base_branch", "reviewer",
        "review_state", "review_id", "review_submitted_at",
    }:
        raise AuthorityBundleError("independent PR approval schema mismatch")
    if (
        type(approval["pr_number"]) is not int or approval["pr_number"] < 1
        or approval["head_sha"] != run["head_sha"]
        or approval["head_sha"] != expected_base_sha
        or approval["base_branch"] != "main"
        or not isinstance(approval["reviewer"], str)
        or not approval["reviewer"].strip()
        or approval["reviewer"].lower() == "yanhul"
        or approval["review_state"] != "APPROVED"
        or type(approval["review_id"]) is not int or approval["review_id"] < 1
        or not isinstance(approval["review_submitted_at"], str)
        or not approval["review_submitted_at"]
    ):
        raise AuthorityBundleError("independent PR approval is missing, stale, or misbound")
    if not isinstance(target, dict) or set(target) != {"base_sha"}:
        raise AuthorityBundleError("target binding schema mismatch")
    if target["base_sha"] != expected_base_sha:
        raise AuthorityBundleError("immutable target/store commit binding mismatch")
    if not isinstance(expected_base_sha, str) or not _HEX40.fullmatch(expected_base_sha):
        raise AuthorityBundleError("expected source base commit SHA is malformed")
    if not isinstance(expected_store_commit, str) or not _HEX40.fullmatch(expected_store_commit):
        raise AuthorityBundleError("expected immutable store commit SHA is malformed")
    if not isinstance(payload["store_commit"], str) or not _HEX40.fullmatch(payload["store_commit"]):
        raise AuthorityBundleError("signed immutable store commit SHA is malformed")
    if payload["store_commit"] != expected_store_commit:
        raise AuthorityBundleError("signed store commit does not match expected immutable store commit")
    if not isinstance(payload["issued_at"], int) or not isinstance(payload["expires_at"], int):
        raise AuthorityBundleError("bundle validity timestamps must be integer epoch seconds")
    current = int(time.time()) if now is None else now
    if payload["expires_at"] <= payload["issued_at"] or current < payload["issued_at"] or current >= payload["expires_at"]:
        raise AuthorityBundleError("bundle is not currently valid or validity interval is invalid")
    records = payload["authority_records"]
    if not isinstance(records, dict) or set(records) != {"capability_registry", "policy", "contract", "permit", "attestation"}:
        raise AuthorityBundleError("authority records schema mismatch")
    contract, permit, policy, registry, attestation = (
        records["contract"], records["permit"], records["policy"], records["capability_registry"], records["attestation"]
    )
    try:
        validate_contract(contract)
        verify_permit(contract, permit)
        verify_attestation(contract, permit, attestation, attestation_secret)
    except (TypeError, ValueError, KeyError) as exc:
        raise AuthorityBundleError(f"contract/permit/attestation validation failed: {exc}") from exc
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


__all__ = ["AuthorityBundleError", "BUNDLE_TYPE", "key_id_for", "load_trust_anchor", "verify_authority_bundle", "verify_immutable_store_object", "verify_issuer_receipt"]


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
    expected_store_repository: str,
    expected_bundle_commit: str,
    expected_bundle_path: str,
    expected_receipt_commit: str,
    expected_receipt_path: str,
    github_token: str,
    attestation_secret: str,
    now: int | None = None,
) -> dict[str, Any]:
    """Verify then atomically materialize the exact signed records into AIOS state.

    No record is written until signature, scope, registry, policy, contract and
    permit have passed preflight. Existing conflicting identities fail closed.
    """
    from .authority import authorize, load_contract, load_permit, load_attestation
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
        attestation_secret=attestation_secret,
        now=now,
    )
    expected_path = f"authority/issued/{expected_run_id}-{expected_base_sha}.json"
    if expected_bundle_path != expected_path:
        raise AuthorityBundleError("immutable bundle path does not match the expected run and source SHA")
    store_proof = verify_immutable_store_object(
        envelope,
        repository=expected_store_repository,
        bundle_commit=expected_bundle_commit,
        signed_store_parent=expected_store_commit,
        bundle_path=expected_bundle_path,
        github_token=github_token,
    )
    receipt_proof = verify_issuer_receipt(
        trusted_issuer=trusted_issuer,
        trusted_public_key_hex=public_key,
        repository=expected_store_repository,
        bundle_commit=store_proof["bundle_commit"],
        bundle_path=store_proof["bundle_path"],
        bundle_blob_sha=store_proof["bundle_blob_sha"],
        expected_store_parent=expected_store_commit,
        expected_source_run_id=expected_run_id,
        expected_source_target_sha=expected_base_sha,
        receipt_commit=expected_receipt_commit,
        receipt_path=expected_receipt_path,
        github_token=github_token,
    )

    records = payload["authority_records"]
    registry_record = records["capability_registry"]
    policy_record = records["policy"]
    contract = records["contract"]
    permit = records["permit"]
    attestation = records["attestation"]

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
        (f"authority/attestations/{pid}.json", attestation),
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
        loaded_attestation = load_attestation(str(root), pid)
        verify_attestation(loaded_contract, loaded_permit, loaded_attestation, attestation_secret)
    except Exception as exc:
        raise AuthorityBundleError(f"AIOS post-commit authority readback failed: {exc}") from exc
    if (canonical_json(loaded_contract) != canonical_json(contract)
            or canonical_json(loaded_permit) != canonical_json(permit)
            or canonical_json(loaded_attestation) != canonical_json(attestation)):
        raise AuthorityBundleError("AIOS post-commit readback differs from signed authority bundle")
    return {
        "state": "AUTHORITY_IMPORTED_AND_READ_BACK",
        "contract_id": cid,
        "permit_id": pid,
        "policy_digest": contract["policy_digest"],
        "capability_registry_path": str(registry_path),
        "signed_store_parent": store_proof["signed_store_parent"],
        "bundle_commit": store_proof["bundle_commit"],
        "bundle_path": store_proof["bundle_path"],
        "bundle_blob_sha": store_proof["bundle_blob_sha"],
        "receipt_commit": receipt_proof["receipt_commit"],
        "receipt_path": receipt_proof["receipt_path"],
        "receipt_blob_sha": receipt_proof["receipt_blob_sha"],
    }
