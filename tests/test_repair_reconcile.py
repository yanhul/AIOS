"""Regression tests for authority -> patch -> receipt -> tests -> reconcile repair lineage."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from core.agent_repair_worker import AgentRepairWorker, ProposedFile
from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import CONTRACT_TYPE
from core.effect_authority import _effect_rel
from core.mutation import TransitionError
from core.policy_registry import persist_policy
from core.repair_reconcile import patch_digest, reconcile_repair, compute_test_evidence_digest
from tests.provider_keys import KEYRING_JSON, SIGNING_KEYS_JSON


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=True).stdout.strip()


def _case(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOS_AUTHORITY_ATTESTATION_SECRET", "test-authority-attestation-secret")
    monkeypatch.setenv("AIOS_PROVIDER_SIGNING_KEYS", SIGNING_KEYS_JSON)
    monkeypatch.setenv("AIOS_PROVIDER_KEYRING", KEYRING_JSON)
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "conftest.py").write_text(
        "import os\n"
        "def pytest_sessionstart(session):\n"
        "    assert 'AIOS_AUTHORITY_ATTESTATION_SECRET' not in os.environ\n"
        "    assert 'AIOS_PROVIDER_SIGNING_KEYS' not in os.environ\n"
        "    assert 'AIOS_PROVIDER_KEYRING' not in os.environ\n",
        encoding="utf-8",
    )
    (repo / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "tests" / "test_repaired.py").write_text(
        "from module import VALUE\ndef test_repaired_value():\n    assert VALUE == 2\n", encoding="utf-8"
    )
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "repair-test@example.invalid")
    _git(repo, "config", "user.name", "AIOS repair test")
    _git(repo, "add", "module.py", "conftest.py", "tests/test_repaired.py")
    _git(repo, "commit", "-qm", "base")
    base = _git(repo, "rev-parse", "HEAD")
    run_id = 731042
    repository = "owner/repo"
    aios = tmp_path / "authority-store"
    aios.mkdir()
    actor = "ci-repair-worker"

    registry = CapabilityRegistry()
    registry.register(Capability("repo_patch", "1", "AIOS", "external_effect",
                                 inputs=("patch",), outputs=("observation",), status="ACTIVE"))
    registry.persist(aios, actor=actor)
    policy_digest = persist_policy(aios, {
        "policy_type": "GOVERNING_POLICY", "task": "ci-repair", "allowed_effects": ["external_effect"],
    })
    contract = {
        "contract_type": CONTRACT_TYPE, "task_id": f"ci-repair-{run_id}", "scope": "repository",
        "actor": actor, "capabilities": ["repo_patch@1"],
        "input_digest": "sha256:" + __import__("hashlib").sha256(
            f"ci-failure:{repository}:{run_id}:{base}".encode()
        ).hexdigest(),
        "allowed_effects": ["external_effect"], "evidence_required": ["OBSERVED"],
        "max_attempts": 3, "terminal_states": ["OBSERVED_SUCCESS", "OBSERVED_FAILURE"],
        "policy_digest": policy_digest,
    }
    stored = persist_contract(aios, contract)
    permit = persist_permit(aios, stored, issuer="ci-repair-test-authority")
    files = [ProposedFile("module.py", "VALUE = 2\n")]
    worker = AgentRepairWorker(
        repo, object(), allowed_test_commands=(("python", "-m", "pytest", "-q"),),
        aios_dir=aios, contract_id=stored["contract_id"], permit_id=permit["permit_id"],
        actor=actor,
    )
    effect = worker.apply_via_aios(
        base_sha=base, files=files, logical_operation_id=f"repair-test:{run_id}:1",
    )
    tested = worker.test()
    proposal = {"schema": 2, "run_id": run_id, "repository": repository, "base_sha": base, "attempt": 1,
                "files": [{"path": x.path, "content": x.content} for x in files]}
    test = {
        "status": tested.status, "run_id": run_id, "repository": repository, "base_sha": base,
        "patch_digest": patch_digest(proposal["files"]),
        "evidence_refs": list(tested.evidence_refs), "results": list(tested.details.get("results", [])),
    }
    test["digest"] = compute_test_evidence_digest(test)
    effects = [{"attempt": 1, "effect_id": effect["effect_id"]}]
    kwargs = dict(
        contract_id=stored["contract_id"], permit_id=permit["permit_id"], actor=actor,
        repository=repository, run_id=run_id, base_sha=base, effects=effects, proposals=[proposal], test=test,
    )
    return aios, kwargs, effect


def test_repair_reconcile_accepts_verified_full_chain(tmp_path, monkeypatch):
    aios, kwargs, _ = _case(tmp_path, monkeypatch)
    assert kwargs["test"]["status"] == "PASS"
    result = reconcile_repair(aios, **kwargs)
    assert result["status"] == "RECONCILED"
    assert result["effects"][0]["state"] == "OBSERVED_SUCCESS"
    assert result["changed_paths"] == ["module.py"]


def test_repair_reconcile_rejects_unknown_effect_even_if_tests_pass(tmp_path, monkeypatch):
    aios, kwargs, effect = _case(tmp_path, monkeypatch)
    path = aios / _effect_rel(effect["effect_id"])
    record = json.loads(path.read_text(encoding="utf-8"))
    record["state"] = "UNKNOWN"
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(TransitionError, match="not OBSERVED_SUCCESS"):
        reconcile_repair(aios, **kwargs)


def test_repair_reconcile_rejects_expired_provider_receipt(tmp_path, monkeypatch):
    aios, kwargs, effect = _case(tmp_path, monkeypatch)
    observed = json.loads((aios / _effect_rel(effect["effect_id"])).read_text(encoding="utf-8"))
    expires_at = observed["provider_observation"]["provider_authentication"]["expires_at"]
    import core.effect_authority as effect_authority
    monkeypatch.setattr(effect_authority.time, "time", lambda: float(expires_at) + 1.0)
    with pytest.raises(TransitionError, match="provider receipt has expired"):
        reconcile_repair(aios, **kwargs)


def test_repair_reconcile_rejects_changed_proposal_after_receipt(tmp_path, monkeypatch):
    aios, kwargs, _ = _case(tmp_path, monkeypatch)
    kwargs["proposals"][0]["files"][0]["content"] = "VALUE = 999\n"
    with pytest.raises(TransitionError, match="does not bind the proposal patch/base"):
        reconcile_repair(aios, **kwargs)


def test_repair_reconcile_rejects_tampered_test_evidence(tmp_path, monkeypatch):
    aios, kwargs, _ = _case(tmp_path, monkeypatch)
    kwargs["test"]["results"][0]["returncode"] = 1
    with pytest.raises(TransitionError, match="test command is not trusted"):
        reconcile_repair(aios, **kwargs)
