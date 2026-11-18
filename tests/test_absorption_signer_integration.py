import json
from pathlib import Path

import pytest

from core.absorption_authority import AbsorptionAuthorizationError
from core.absorption_effect_guard import authorize_absorption_effect
import core.absorption_effect_guard as effect_guard


ROOT = Path(__file__).resolve().parents[1]


def test_checked_in_policy_and_empty_keyrings_fail_closed():
    policy = json.loads((ROOT / "policies/absorption-default-deny.v1.json").read_text())
    governance = json.loads((ROOT / "policies/absorption-governance-keyring.json").read_text())
    permit_keys = json.loads((ROOT / "policies/absorption-permit-keyring.json").read_text())
    assert governance == {}
    assert permit_keys == {}
    with pytest.raises(AbsorptionAuthorizationError, match="non-empty unique string list"):
        authorize_absorption_effect(
            permit={}, permit_keyring=permit_keys, policy=policy,
            repository="yanhul/AIOS", target_branch="main", run_id="1",
            source_commit_sha="a" * 40, artifact_digests={"artifact.json": "b" * 64},
            effect="materialize_absorbed_registry",
        )


def test_valid_signature_still_denied_without_durable_atomic_replay_store(monkeypatch):
    monkeypatch.setattr(effect_guard, "verify_absorption_permit", lambda **kwargs: True)
    policy = {
        "decision": {
            "default": "DENY",
            "allowed_effects": ["materialize_absorbed_registry"],
        }
    }
    with pytest.raises(AbsorptionAuthorizationError, match="durable atomic one-time permit-consumption backend"):
        authorize_absorption_effect(
            permit={"signature": "cryptographically-verified-by-test"},
            permit_keyring={"test": {}}, policy=policy,
            repository="yanhul/AIOS", target_branch="main", run_id="42",
            source_commit_sha="a" * 40, artifact_digests={"artifact.json": "b" * 64},
            effect="materialize_absorbed_registry",
        )


def test_signer_preflight_runs_before_any_private_key_secret_is_exposed():
    import yaml

    workflow = yaml.load(
        (ROOT / ".github/workflows/aios-absorption-signer.yml").read_text(),
        Loader=yaml.BaseLoader,
    )
    job = workflow["jobs"]["signer"]
    steps = job["steps"]
    secret_steps = [
        index for index, step in enumerate(steps)
        if "secrets.AIOS_ABSORPTION_PERMIT_PRIVATE_KEY" in json.dumps(step)
    ]
    preflight_steps = [
        index for index, step in enumerate(steps)
        if step.get("name") == "Preflight signer inputs before secret access"
    ]
    assert len(secret_steps) == 1
    assert len(preflight_steps) == 1
    assert preflight_steps[0] < secret_steps[0]
    assert "AIOS_ABSORPTION_PERMIT_PRIVATE_KEY" not in json.dumps(steps[preflight_steps[0]])


def test_signer_workflow_scopes_private_key_to_single_protected_job_step():
    import yaml

    workflow = yaml.load(
        (ROOT / ".github/workflows/aios-absorption-signer.yml").read_text(),
        Loader=yaml.BaseLoader,
    )
    assert set(workflow["jobs"]) == {"signer"}
    job = workflow["jobs"]["signer"]
    assert job["environment"] == "production"
    secret_refs = []
    for step in job["steps"]:
        serialized = json.dumps(step)
        if "AIOS_ABSORPTION_PERMIT_PRIVATE_KEY" in serialized:
            secret_refs.append(step)
    assert len(secret_refs) == 1
    assert "secrets.AIOS_ABSORPTION_PERMIT_PRIVATE_KEY" in json.dumps(secret_refs[0])
    checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout"))
    assert checkout["with"]["ref"] == "main"
