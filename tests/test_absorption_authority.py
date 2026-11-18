import copy
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.absorption_authority import (
    AbsorptionAuthorizationError, create_approval_attestation,
    policy_digest, sign_absorption_permit, verify_absorption_permit,
    verify_approval_attestation, verify_lineage,
)


def raw_public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def key_id(key):
    import hashlib
    return "ed25519:" + hashlib.sha256(bytes.fromhex(raw_public(key))).hexdigest()[:32]


def keyring(key):
    return {key_id(key): {"public_key": raw_public(key), "revoked": False}}


def approved_policy():
    return {
        "policy_type": "GOVERNING_POLICY",
        "policy_id": "aios.absorption.test",
        "status": "APPROVED",
        "decision": {"default": "DENY", "allowed_effects": ["persist_research_evidence"]},
        "approval": {"required": True, "status": "APPROVED"},
    }


def fixture():
    governance = Ed25519PrivateKey.generate()
    signer = Ed25519PrivateKey.generate()
    policy = approved_policy()
    approval = create_approval_attestation(
        policy=policy, repository="yanhul/AIOS", target_branch="main",
        approver="governance-human", expires_at=int(time.time()) + 600,
        approval_private_key=governance,
    )
    artifacts = {"executor": "a" * 64, "verification": "b" * 64}
    lineage = {
        "repository": "yanhul/AIOS", "run_id": "987654",
        "source_commit_sha": "c" * 40, "artifacts": dict(artifacts),
    }
    permit = sign_absorption_permit(
        policy=policy, approval=approval, governance_keyring=keyring(governance),
        repository="yanhul/AIOS", target_branch="main", lineage=lineage,
        expected_run_id="987654", expected_commit_sha="c" * 40,
        expected_artifacts=artifacts, permit_private_key=signer,
    )
    return governance, signer, policy, approval, artifacts, lineage, permit


def test_valid_human_approval_and_ed25519_permit_round_trip():
    _, signer, policy, approval, artifacts, lineage, permit = fixture()
    assert verify_approval_attestation(
        policy=policy, approval=approval, governance_keyring=keyring(_governance_key(approval)),
        repository="yanhul/AIOS", target_branch="main"
    )


def _governance_key(approval):
    # Reconstructing a private key is intentionally impossible; test helper is replaced below.
    raise AssertionError("unreachable")


def test_policy_draft_empty_effects_cannot_be_approved_or_signed():
    policy = {
        "policy_type": "GOVERNING_POLICY", "status": "DRAFT_UNAPPROVED",
        "decision": {"default": "DENY", "allowed_effects": []},
        "approval": {"required": True, "status": "NOT_APPROVED"},
    }
    with pytest.raises(AbsorptionAuthorizationError):
        create_approval_attestation(
            policy=policy, repository="yanhul/AIOS", target_branch="main",
            approver="human", expires_at=int(time.time()) + 600,
            approval_private_key=Ed25519PrivateKey.generate(),
        )


def test_forged_issuer_unknown_key_and_revoked_key_are_denied():
    governance, _, policy, approval, _, _, _ = fixture()
    forged = dict(approval, approver="attacker")
    with pytest.raises(AbsorptionAuthorizationError):
        verify_approval_attestation(
            policy=policy, approval=forged, governance_keyring=keyring(governance),
            repository="yanhul/AIOS", target_branch="main"
        )
    revoked = keyring(governance)
    revoked[key_id(governance)]["revoked"] = True
    with pytest.raises(AbsorptionAuthorizationError):
        verify_approval_attestation(
            policy=policy, approval=approval, governance_keyring=revoked,
            repository="yanhul/AIOS", target_branch="main"
        )
    with pytest.raises(AbsorptionAuthorizationError):
        verify_approval_attestation(
            policy=policy, approval=approval, governance_keyring={},
            repository="yanhul/AIOS", target_branch="main"
        )


@pytest.mark.parametrize("field,value", [
    ("repository", "attacker/repo"), ("run_id", "other-run"),
    ("source_commit_sha", "d" * 40),
])
def test_lineage_wrong_repository_run_or_commit_is_denied(field, value):
    _, _, _, _, artifacts, lineage, _ = fixture()
    changed = copy.deepcopy(lineage)
    changed[field] = value
    with pytest.raises(AbsorptionAuthorizationError):
        verify_lineage(
            lineage=changed, expected_repository="yanhul/AIOS",
            expected_run_id="987654", expected_commit_sha="c" * 40,
            expected_artifacts=artifacts,
        )


def test_lineage_modified_or_missing_artifact_is_denied():
    _, _, _, _, artifacts, lineage, _ = fixture()
    changed = copy.deepcopy(lineage)
    changed["artifacts"]["executor"] = "f" * 64
    with pytest.raises(AbsorptionAuthorizationError):
        verify_lineage(
            lineage=changed, expected_repository="yanhul/AIOS",
            expected_run_id="987654", expected_commit_sha="c" * 40,
            expected_artifacts=artifacts,
        )


def test_permit_verifier_rejects_wrong_scope_commit_run_and_rotated_key():
    _, signer, policy, _, artifacts, _, permit = fixture()
    args = dict(
        permit=permit, permit_keyring=keyring(signer), policy=policy,
        repository="yanhul/AIOS", target_branch="main", run_id="987654",
        source_commit_sha="c" * 40, artifact_digests=artifacts,
    )
    assert verify_absorption_permit(**args)
    for field, value in [("run_id", "wrong"), ("source_commit_sha", "d" * 40)]:
        tampered = dict(permit)
        tampered[field] = value
        with pytest.raises(AbsorptionAuthorizationError):
            verify_absorption_permit(**dict(args, permit=tampered))
    with pytest.raises(AbsorptionAuthorizationError):
        verify_absorption_permit(**dict(args, permit_keyring={}))
