import json
from pathlib import Path

import pytest

from core.absorption_authority import AbsorptionAuthorizationError
from core.absorption_effect_guard import authorize_absorption_effect
import core.absorption_effect_guard as effect_guard


ROOT = Path(__file__).resolve().parents[1]


def test_checked_in_policy_and_empty_keyrings_fail_closed(monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "apply-42")
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
            target_apply_run_id="apply-42", effect="materialize_absorbed_registry",
        )


def test_valid_signature_still_denied_without_durable_replay_store_credentials(monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "apply-42")
    monkeypatch.setattr(effect_guard, "verify_absorption_permit", lambda **kwargs: True)
    policy = {
        "decision": {
            "default": "DENY",
            "allowed_effects": ["materialize_absorbed_registry"],
        }
    }
    with pytest.raises(AbsorptionAuthorizationError, match="GITHUB_TOKEN with contents:write is required"):
        authorize_absorption_effect(
            permit={"signature": "cryptographically-verified-by-test"},
            permit_keyring={"test": {}}, policy=policy,
            repository="yanhul/AIOS", target_branch="main", run_id="42",
            source_commit_sha="a" * 40, artifact_digests={"artifact.json": "b" * 64},
            target_apply_run_id="apply-42", effect="materialize_absorbed_registry",
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


def _signed_bundle():
    import hashlib

    def digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    run_id = "source-run-1"
    executor = {
        "kind": "AIOS_ABSORPTION_EXECUTOR", "run_id": run_id, "overall": "PASS",
        "records": [{"candidate_id": "c1", "run_id": run_id,
                     "external_code_copy": False, "external_code_execution": False}],
    }
    verified_records = [{"candidate_id": "c1", "run_id": run_id}]
    verification = {
        "kind": "AIOS_ABSORPTION_INDEPENDENT_VERIFICATION", "run_id": run_id,
        "overall": "PASS", "records": verified_records, "failures": [],
        "independent_tests": {"passed": True, "digest": "a" * 64},
    }
    verification["digest"] = digest({"verified": verified_records, "failures": []})
    implementation, probes = {"overall": "PASS"}, {"runtime": True}
    runtime = {
        "kind": "AIOS_ABSORPTION_RUNTIME_PROOF", "run_id": run_id, "overall": "PASS",
        "implementation": implementation, "probes": probes,
        "digest": digest({"implementation": implementation, "probes": probes}),
    }
    promotion = {
        "kind": "AIOS_ABSORPTION_PROMOTION", "run_id": run_id, "overall": "PASS",
        "input_verification_digest": verification["digest"],
        "input_runtime_digest": runtime["digest"], "blocked": [],
        "decisions": [{"candidate_id": "c1", "run_id": run_id,
                       "allowed": True, "verdict": "PROMOTE"}],
    }
    promotion["digest"] = digest(promotion)
    return {
        "absorption-executor.json": executor,
        "absorption-verification.json": verification,
        "absorption-runtime-proof.json": runtime,
        "absorption-promotion.json": promotion,
    }


def test_signer_validates_all_artifact_semantics_before_signing():
    from research.absorption_signer import validate_artifact_bundle

    assert validate_artifact_bundle(_signed_bundle(), source_run_id="source-run-1")


def test_signer_rejects_tampered_runtime_proof_before_signing():
    from research.absorption_signer import validate_artifact_bundle

    artifacts = _signed_bundle()
    artifacts["absorption-runtime-proof.json"]["probes"]["runtime"] = False
    with pytest.raises(RuntimeError, match="runtime proof contains failed or missing probes"):
        validate_artifact_bundle(artifacts, source_run_id="source-run-1")


def test_apply_workflow_is_protected_and_binds_exact_apply_run():
    import yaml

    workflow = yaml.load(
        (ROOT / ".github/workflows/aios-absorption-apply.yml").read_text(),
        Loader=yaml.BaseLoader,
    )
    job = workflow["jobs"]["apply"]
    assert job["environment"] == "production"
    assert job["permissions"]["actions"] == "write"
    assert job["permissions"]["contents"] == "write"
    steps = job["steps"]
    dispatch = next(step for step in steps if step.get("name") == "Dispatch protected permit signer")
    assert "aios-absorption-signer.yml/dispatches" in dispatch["run"]
    assert "target_apply_run_id" in dispatch["run"]
    wait = next(step for step in steps if step.get("name") == "Wait for permit signed for this apply run")
    assert "TARGET_APPLY_RUN_ID" in json.dumps(wait)
    apply_step = next(step for step in steps if step.get("name") == "Apply with Ed25519 permit and durable replay ledger")
    assert "GITHUB_TOKEN" in json.dumps(apply_step["env"])
    assert "AIOS_TARGET_APPLY_RUN_ID" in json.dumps(apply_step["env"])


def test_effect_guard_rejects_permit_for_another_workflow_run(monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "actual-run-7")
    monkeypatch.setattr(effect_guard, "verify_absorption_permit", lambda **kwargs: True)
    with pytest.raises(AbsorptionAuthorizationError, match="current GitHub workflow run"):
        authorize_absorption_effect(
            permit={"signature": "signed"}, permit_keyring={"test": {}},
            policy={"decision": {"default": "DENY", "allowed_effects": ["effect-x"]}},
            repository="owner/repo", target_branch="main", run_id="source-1",
            source_commit_sha="a" * 40, artifact_digests={"a.json": "b" * 64},
            target_apply_run_id="different-run", effect="effect-x",
        )
