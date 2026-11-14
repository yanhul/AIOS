import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.authority_bundle import (
    AuthorityBundleError, key_id_for, load_trust_anchor, verify_authority_bundle,
)
from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import CONTRACT_TYPE
from core.mutation import canonical_json
from core.policy_registry import persist_policy


def fixture_bundle(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    registry = CapabilityRegistry()
    registry.register(Capability("repo_patch", "1", "issuer", "external_effect", status="ACTIVE"))
    registry.persist(state, actor="issuer")
    policy = {"policy_type": "GOVERNING_POLICY", "name": "fixture", "allowed_effects": ["external_effect"]}
    digest = persist_policy(state, policy)
    contract = {
        "contract_type": CONTRACT_TYPE, "task_id": "ci-repair-123",
        "scope": "repository", "actor": "ci-repair-worker",
        "capabilities": ["repo_patch@1"], "input_digest": "sha256:" + "a" * 64,
        "allowed_effects": ["external_effect"], "evidence_required": ["OBSERVED"],
        "max_attempts": 3, "terminal_states": ["OBSERVED_SUCCESS", "OBSERVED_FAILURE"],
        "policy_digest": digest,
    }
    stored = persist_contract(state, contract)
    permit = persist_permit(state, stored, issuer="yanhul/aios-authority-store")
    contract_record = dict(contract)
    policy_record = dict(policy, policy_digest=digest)
    envelope_payload = {
        "bundle_type": "AIOS_EXTERNAL_AUTHORITY_BUNDLE", "schema_version": 1,
        "issuer": "yanhul/aios-authority-store", "repository": "yanhul/AIOS",
        "source_run": {"id": 123, "workflow_path": ".github/workflows/ci.yml",
                       "event": "push", "conclusion": "failure",
                       "head_sha": "a" * 40, "head_branch": "main"},
        "target": {"base_sha": "a" * 40}, "issued_at": 1000, "expires_at": 2000,
        "authority_records": {
            "capability_registry": registry.snapshot(),
            "policy": policy_record, "contract": contract_record, "permit": permit,
        },
    }
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    kid = key_id_for(public)
    envelope = {"payload": envelope_payload, "signature": {
        "algorithm": "Ed25519", "key_id": kid,
        "value": private.sign(canonical_json(envelope_payload).encode()).hex(),
    }}
    return envelope, public, kid


def verify(envelope, public, **overrides):
    args = dict(
        trusted_issuer="yanhul/aios-authority-store",
        trusted_public_key_hex=public, expected_repository="yanhul/AIOS",
        expected_run_id=123, expected_base_sha="a" * 40,
        expected_source_branch="main", expected_store_commit="b" * 40, now=1500,
    )
    args.update(overrides)
    return verify_authority_bundle(envelope, **args)


def test_valid_external_bundle_verifies(tmp_path):
    envelope, public, _ = fixture_bundle(tmp_path)
    result = verify(envelope, public)
    assert result["authority_records"]["permit"]["issuer"] == "yanhul/aios-authority-store"


def test_signature_tampering_is_rejected(tmp_path):
    envelope, public, _ = fixture_bundle(tmp_path)
    envelope["payload"]["target"]["base_sha"] = "c" * 40
    with pytest.raises(AuthorityBundleError, match="signature"):
        verify(envelope, public)


def test_wrong_run_sha_and_store_commit_are_rejected(tmp_path):
    envelope, public, _ = fixture_bundle(tmp_path)
    with pytest.raises(AuthorityBundleError, match="source run ID"):
        verify(envelope, public, expected_run_id=999)
    with pytest.raises(AuthorityBundleError, match="source run SHA"):
        verify(envelope, public, expected_base_sha="c" * 40)
    with pytest.raises(AuthorityBundleError, match="store commit SHA"):
        verify(envelope, public, expected_store_commit="not-a-commit")


def test_expired_bundle_is_rejected(tmp_path):
    envelope, public, _ = fixture_bundle(tmp_path)
    with pytest.raises(AuthorityBundleError, match="not currently valid"):
        verify(envelope, public, now=2000)


def test_contract_policy_or_capability_tampering_is_rejected(tmp_path):
    envelope, public, _ = fixture_bundle(tmp_path)
    envelope["payload"]["authority_records"]["permit"]["actor"] = "attacker"
    envelope["signature"]["value"] = "0" * 128
    with pytest.raises(AuthorityBundleError, match="signature"):
        verify(envelope, public)


def test_unprovisioned_trust_anchor_fails_closed(tmp_path):
    path = tmp_path / "trust.json"
    path.write_text(json.dumps({"schema_version": 1, "issuers": {
        "yanhul/aios-authority-store": {"status": "UNPROVISIONED", "key_id": None, "public_key_hex": None}
    }}))
    with pytest.raises(AuthorityBundleError, match="not provisioned"):
        load_trust_anchor(path, "yanhul/aios-authority-store")


def test_active_trust_anchor_must_pin_matching_key(tmp_path):
    envelope, public, kid = fixture_bundle(tmp_path)
    path = tmp_path / "trust.json"
    path.write_text(json.dumps({"schema_version": 1, "issuers": {
        "yanhul/aios-authority-store": {"status": "ACTIVE", "key_id": kid, "public_key_hex": public}
    }}))
    assert load_trust_anchor(path, "yanhul/aios-authority-store") == public
