import json
from pathlib import Path


POLICY_PATH = Path(__file__).resolve().parents[1] / "policies" / "absorption-default-deny.v1.json"


def load_policy():
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def test_absorption_policy_is_unapproved_and_default_deny():
    policy = load_policy()
    assert policy["policy_type"] == "GOVERNING_POLICY"
    assert policy["status"] == "DRAFT_UNAPPROVED"
    assert policy["decision"]["default"] == "DENY"
    assert policy["decision"]["allowed_effects"] == []
    assert policy["approval"]["required"] is True
    assert policy["approval"]["status"] == "NOT_APPROVED"
    assert policy["approval"]["signature"] is None


def test_absorption_policy_explicitly_denies_mutation_and_promotion():
    policy = load_policy()
    denied = set(policy["decision"]["denied_effects"])
    assert {
        "source_mutation",
        "policy_mutation",
        "capability_registry_mutation",
        "automatic_promotion",
        "production_execution",
        "permit_issuance",
        "artifact_materialization",
    } <= denied
    constraints = policy["constraints"]
    assert constraints["source_mutation"] is False
    assert constraints["policy_mutation"] is False
    assert constraints["automatic_promotion"] is False
    assert constraints["production_authorization"] is False


def test_signer_requires_independent_approval_and_revalidation():
    signer = load_policy()["signer_requirements"]
    assert signer["algorithm"] == "Ed25519"
    assert signer["signing_without_valid_approval"] == "DENY"
    assert signer["signer_must_not_execute_candidate_code"] is True
    assert "policy_digest" in signer["signer_must_revalidate"]
    assert "approval_attestation" in signer["signer_must_revalidate"]
