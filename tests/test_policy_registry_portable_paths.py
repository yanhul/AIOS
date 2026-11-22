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
