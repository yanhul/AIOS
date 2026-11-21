import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from core.provider_ed25519 import key_id_for
from core.retry_ed25519 import key_id_for as retry_key_id_for

from scripts.check_production_authority import (
    ProductionAuthorityConfigError, validate_production_authority,
)


def _valid_env(now=1000):
    reviewer_key = Ed25519PrivateKey.generate()
    raw_public = reviewer_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    provider_key = Ed25519PrivateKey.generate()
    provider_public = provider_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    retry_key = Ed25519PrivateKey.generate()
    retry_public = retry_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    att = {
        "repository": "yanhul/AIOS", "commit": "a" * 40, "environment": "production",
        "executor_id": "runtime:prod", "reviewer_id": "human:security-reviewer",
        "issued_at": now - 10, "expires_at": now + 300,
    }
    canonical = json.dumps(att, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    att["signature"] = reviewer_key.sign(canonical).hex()
    return {
        "AIOS_REQUIRE_EXECUTION_LINEAGE": "true",
        "AIOS_AUTHORITY_ATTESTATION_SECRET": "A" * 40,
        "AIOS_PROVIDER_KEYRING": json.dumps({
            "provider-x": {"secret": "P" * 40, "scopes": ["provider.receipt.sign"], "revoked": False}
        }),
        "AIOS_RETRY_ISSUER_ED25519_KEYRING": json.dumps({
            "issuer:independent": {"key_id": retry_key_id_for(retry_public), "public_key": retry_public, "revoked": False}
        }),
        "AIOS_PROVIDER_ED25519_KEYRING": json.dumps({
            "minimind": {"key_id": key_id_for(provider_public), "public_key": provider_public}
        }),
        "AIOS_DEPLOYMENT_EXECUTOR_ID": "runtime:prod",
        "AIOS_DEPLOYMENT_ENVIRONMENT": "production",
        "AIOS_DEPLOYMENT_REVIEWER_KEYRING": json.dumps({
            "human:security-reviewer": {"public_key": raw_public, "revoked": False}
        }),
        "AIOS_DEPLOYMENT_REVIEWER_ATTESTATION": json.dumps(att),
        "GITHUB_REPOSITORY": "yanhul/AIOS",
        "GITHUB_SHA": "a" * 40,
    }, reviewer_key


def test_production_authority_requires_real_distinct_reviewer_signature():
    env, _ = _valid_env()
    result = validate_production_authority(env, now=1000)
    assert result["ready"] is True
    assert result["reviewer_id"] != result["executor_id"]


def test_production_authority_rejects_missing_lineage_gate():
    env, _ = _valid_env()
    env["AIOS_REQUIRE_EXECUTION_LINEAGE"] = "false"
    with pytest.raises(ProductionAuthorityConfigError, match="AIOS_REQUIRE_EXECUTION_LINEAGE"):
        validate_production_authority(env, now=1000)


def test_production_authority_rejects_reviewer_signature_tampering():
    env, _ = _valid_env()
    att = json.loads(env["AIOS_DEPLOYMENT_REVIEWER_ATTESTATION"])
    att["reviewer_id"] = "runtime:prod"
    env["AIOS_DEPLOYMENT_REVIEWER_ATTESTATION"] = json.dumps(att)
    with pytest.raises(ProductionAuthorityConfigError, match="reviewer must be"):
        validate_production_authority(env, now=1000)


def test_production_authority_rejects_expired_reviewer_attestation():
    env, _ = _valid_env()
    with pytest.raises(ProductionAuthorityConfigError, match="expired"):
        validate_production_authority(env, now=2000)


def test_production_authority_rejects_legacy_hmac_retry_keyring():
    env, _ = _valid_env()
    env["AIOS_RETRY_ISSUER_KEYRING"] = json.dumps({"legacy": {"secret": "x" * 40, "scopes": ["effect.retry.approve"]}})
    with pytest.raises(ProductionAuthorityConfigError, match="legacy HMAC"):
        validate_production_authority(env, now=1000)