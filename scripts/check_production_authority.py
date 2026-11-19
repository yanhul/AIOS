"""Fail-closed production authority and independent-reviewer deployment gate.

All trust anchors are supplied by the deployment secret manager. This script
validates configuration; it never creates keys, signs on behalf of a reviewer,
or writes secrets to the repository.
"""
from __future__ import annotations

import json
import os
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from core.provider_ed25519 import ProviderPublicKeyring

AUTHORITY_SECRET = "AIOS_AUTHORITY_ATTESTATION_SECRET"
PROVIDER_RING = "AIOS_PROVIDER_KEYRING"
RETRY_RING = "AIOS_RETRY_ISSUER_KEYRING"
PROVIDER_ED25519_RING = "AIOS_PROVIDER_ED25519_KEYRING"
REVIEWER_KEYRING = "AIOS_DEPLOYMENT_REVIEWER_KEYRING"
REVIEWER_ATTESTATION = "AIOS_DEPLOYMENT_REVIEWER_ATTESTATION"


class ProductionAuthorityConfigError(ValueError):
    pass


def _json_object(env, name):
    try:
        value = json.loads(env[name])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ProductionAuthorityConfigError(f"{name} is missing or invalid JSON") from exc
    if not isinstance(value, dict) or not value:
        raise ProductionAuthorityConfigError(f"{name} must be a non-empty JSON object")
    return value


def validate_production_authority(env=None, *, now=None):
    env = os.environ if env is None else env
    if env.get("AIOS_REQUIRE_EXECUTION_LINEAGE", "").lower() != "true":
        raise ProductionAuthorityConfigError("AIOS_REQUIRE_EXECUTION_LINEAGE must be true")
    secret = env.get(AUTHORITY_SECRET, "")
    if not isinstance(secret, str) or len(secret) < 32:
        raise ProductionAuthorityConfigError(f"{AUTHORITY_SECRET} must be a deployment secret of at least 32 characters")

    try:
        providers = json.loads(env.get(PROVIDER_RING, "{}"))
    except (TypeError, json.JSONDecodeError) as exc:
        raise ProductionAuthorityConfigError(f"{PROVIDER_RING} is invalid JSON") from exc
    if not isinstance(providers, dict):
        raise ProductionAuthorityConfigError(f"{PROVIDER_RING} must be a JSON object")
    for provider, entry in providers.items():
        if not isinstance(provider, str) or not isinstance(entry, dict):
            raise ProductionAuthorityConfigError("provider keyring entry is malformed")
        if not isinstance(entry.get("revoked", False), bool):
            raise ProductionAuthorityConfigError(f"provider revoked flag for {provider} must be boolean")
        if entry.get("revoked", False):
            continue
        scopes = entry.get("scopes", [])
        if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
            raise ProductionAuthorityConfigError(f"provider scopes for {provider} must be a list of strings")
        if not isinstance(entry.get("secret"), str) or len(entry["secret"]) < 32:
            raise ProductionAuthorityConfigError(f"active provider key for {provider} must be at least 32 characters")
        if "provider.receipt.sign" not in scopes:
            raise ProductionAuthorityConfigError(f"active provider {provider} lacks provider.receipt.sign scope")
    retry = _json_object(env, RETRY_RING)
    active_issuers = []
    for issuer, entry in retry.items():
        if not isinstance(issuer, str) or not isinstance(entry, dict):
            raise ProductionAuthorityConfigError("retry issuer keyring entry is malformed")
        if not isinstance(entry.get("revoked", False), bool):
            raise ProductionAuthorityConfigError(f"retry issuer revoked flag for {issuer} must be boolean")
        if entry.get("revoked", False):
            continue
        scopes = entry.get("scopes", [])
        if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
            raise ProductionAuthorityConfigError(f"retry issuer scopes for {issuer} must be a list of strings")
        if not isinstance(entry.get("secret"), str) or len(entry["secret"]) < 32:
            raise ProductionAuthorityConfigError(f"active retry issuer key for {issuer} must be at least 32 characters")
        if "effect.retry.approve" not in scopes:
            raise ProductionAuthorityConfigError(f"active retry issuer {issuer} lacks effect.retry.approve scope")
        active_issuers.append(issuer)
    if not active_issuers:
        raise ProductionAuthorityConfigError("retry issuer keyring has no active issuer")

    public_ring = _json_object(env, PROVIDER_ED25519_RING)
    try:
        ProviderPublicKeyring(public_ring)
    except ValueError as exc:
        raise ProductionAuthorityConfigError(f"{PROVIDER_ED25519_RING} is invalid: {exc}") from exc
    minimind = public_ring.get("minimind")
    if not isinstance(minimind, dict) or minimind.get("revoked", False):
        raise ProductionAuthorityConfigError("active Ed25519 public key for minimind is required")
    if set(minimind) - {"key_id", "public_key", "revoked"}:
        raise ProductionAuthorityConfigError("minimind Ed25519 keyring contains forbidden fields")
    try:
        public = bytes.fromhex(minimind.get("public_key", ""))
        if len(public) != 32:
            raise ValueError("wrong key length")
        Ed25519PublicKey.from_public_bytes(public)
    except (TypeError, ValueError) as exc:
        raise ProductionAuthorityConfigError("minimind Ed25519 public key must be 32-byte hex") from exc

    executor = env.get("AIOS_DEPLOYMENT_EXECUTOR_ID", "")
    reviewer_keyring = _json_object(env, REVIEWER_KEYRING)
    repository = env.get("GITHUB_REPOSITORY", "")
    commit = env.get("GITHUB_SHA", "")
    environment = env.get("AIOS_DEPLOYMENT_ENVIRONMENT", "")
    if not all(isinstance(x, str) and x.strip() for x in (executor, repository, commit, environment)):
        raise ProductionAuthorityConfigError("deployment executor, environment and deployed repository/commit are required")

    attestation = _json_object(env, REVIEWER_ATTESTATION)
    expected = {"repository", "commit", "environment", "executor_id", "reviewer_id", "issued_at", "expires_at", "signature"}
    if set(attestation) != expected:
        raise ProductionAuthorityConfigError("independent reviewer attestation schema mismatch")
    reviewer_id = attestation["reviewer_id"]
    if not isinstance(reviewer_id, str) or not reviewer_id.strip() or reviewer_id == executor:
        raise ProductionAuthorityConfigError("reviewer must be a named principal distinct from executor")
    if reviewer_id in active_issuers:
        raise ProductionAuthorityConfigError("reviewer and retry issuer must be separate principals")
    reviewer_entry = reviewer_keyring.get(reviewer_id)
    if not isinstance(reviewer_entry, dict) or reviewer_entry.get("revoked", False):
        raise ProductionAuthorityConfigError("reviewer identity is not registered or has been revoked")
    if set(reviewer_entry) - {"public_key", "revoked"}:
        raise ProductionAuthorityConfigError("reviewer trust entry contains unsupported fields")
    try:
        reviewer_pub = bytes.fromhex(reviewer_entry.get("public_key", ""))
        if len(reviewer_pub) != 32:
            raise ValueError("wrong key length")
        reviewer = Ed25519PublicKey.from_public_bytes(reviewer_pub)
    except (TypeError, ValueError) as exc:
        raise ProductionAuthorityConfigError("registered reviewer public key must be 32-byte Ed25519 hex") from exc
    for key, value in (("repository", repository), ("commit", commit),
                       ("environment", environment), ("executor_id", executor)):
        if attestation[key] != value:
            raise ProductionAuthorityConfigError(f"reviewer attestation {key} does not match deployment")
    issued, expires = attestation["issued_at"], attestation["expires_at"]
    current = time.time() if now is None else now
    if (not isinstance(issued, (int, float)) or isinstance(issued, bool)
            or not isinstance(expires, (int, float)) or isinstance(expires, bool)
            or not issued <= current <= expires or expires - issued > 86400):
        raise ProductionAuthorityConfigError("reviewer attestation is expired, future-dated or exceeds 24h")
    signature = attestation["signature"]
    if not isinstance(signature, str):
        raise ProductionAuthorityConfigError("reviewer signature is missing")
    payload = {key: attestation[key] for key in expected - {"signature"}}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    try:
        reviewer.verify(bytes.fromhex(signature), canonical)
    except Exception as exc:
        raise ProductionAuthorityConfigError("independent reviewer signature verification failed") from exc
    return {
        "ready": True,
        "reviewer_id": reviewer_id,
        "executor_id": executor,
        "environment": environment,
        "active_retry_issuers": sorted(active_issuers),
        "active_provider_hmac_count": sum(1 for v in providers.values() if not v.get("revoked", False)),
        "ed25519_providers": sorted(public_ring),
    }


if __name__ == "__main__":
    try:
        result = validate_production_authority()
    except ProductionAuthorityConfigError as exc:
        raise SystemExit(f"PRODUCTION_AUTHORITY_BLOCKED: {exc}")
    print(json.dumps(result, sort_keys=True))
