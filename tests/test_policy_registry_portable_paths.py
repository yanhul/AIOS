from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.policy_registry import persist_policy, policy_digest, resolve_policy


def test_policy_artifact_filename_is_portable_and_resolvable(tmp_path: Path):
    policy = {
        "policy_type": "GOVERNING_POLICY",
        "task": "ci-repair",
        "allowed_effects": ["external_effect"],
    }

    digest = persist_policy(tmp_path, policy)
    artifact = tmp_path / "policies" / (digest.removeprefix("sha256:") + ".json")

    assert digest == policy_digest(policy)
    assert artifact.is_file()
    assert ":" not in artifact.name
    assert resolve_policy(tmp_path, digest)["policy_digest"] == digest


def test_policy_resolver_rejects_noncanonical_digest(tmp_path: Path):
    with pytest.raises(ValueError, match="canonical sha256"):
        resolve_policy(tmp_path, "sha256:../outside")


def test_policy_resolver_rejects_tampered_content(tmp_path: Path):
    policy = {
        "policy_type": "GOVERNING_POLICY",
        "task": "ci-repair",
        "allowed_effects": ["external_effect"],
    }
    digest = persist_policy(tmp_path, policy)
    artifact = tmp_path / "policies" / (digest.removeprefix("sha256:") + ".json")
    record = json.loads(artifact.read_text(encoding="utf-8"))
    record["allowed_effects"] = ["untrusted_effect"]
    artifact.write_text(json.dumps(record), encoding="utf-8")

    with pytest.raises(ValueError, match="content hash mismatch"):
        resolve_policy(tmp_path, digest)


def test_policy_resolver_rejects_non_boolean_receipt_requirement(tmp_path: Path):
    policy = {
        "policy_type": "GOVERNING_POLICY",
        "require_execution_receipt": "yes",
    }
    digest = persist_policy(tmp_path, policy)
    with pytest.raises(ValueError, match="must be boolean"):
        resolve_policy(tmp_path, digest)


def test_policy_resolver_validates_and_preserves_acceptance_predicates(tmp_path: Path):
    policy = {
        "policy_type": "GOVERNING_POLICY",
        "acceptance_predicates": [{
            "predicate_id": "verified", "path": "verification.verified",
            "operator": "eq", "expected": True,
        }],
    }
    digest = persist_policy(tmp_path, policy)
    assert resolve_policy(tmp_path, digest)["acceptance_predicates"] == policy["acceptance_predicates"]

    malformed = {"policy_type": "GOVERNING_POLICY", "acceptance_predicates": ["not-a-predicate"]}
    malformed_digest = persist_policy(tmp_path, malformed)
    with pytest.raises(ValueError, match="must be a mapping"):
        resolve_policy(tmp_path, malformed_digest)
