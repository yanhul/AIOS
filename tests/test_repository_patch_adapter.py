from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from core.agent_repair_worker import ProposedFile
from core.repository_patch_adapter import RepositoryPatchAdapter


def init_repo(tmp_path: Path) -> str:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "AIOS Test"], cwd=tmp_path, check=True)
    (tmp_path / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "module.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=tmp_path, check=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True,
        capture_output=True, check=True
    ).stdout.strip()


def test_adapter_rejects_protected_paths(tmp_path):
    base = init_repo(tmp_path)
    adapter = RepositoryPatchAdapter(tmp_path)

    with pytest.raises(ValueError, match="protected"):
        adapter.register(
            "EF-test",
            (ProposedFile(".github/workflows/ci.yml", "evil"),),
            base_sha=base,
        )


def test_adapter_rejects_stale_base_before_register(tmp_path):
    init_repo(tmp_path)
    adapter = RepositoryPatchAdapter(tmp_path)

    with pytest.raises(RuntimeError, match="stale repair base"):
        adapter.register(
            "EF-test",
            (ProposedFile("module.py", "VALUE = 2\n"),),
            base_sha="0" * 40,
        )


def test_adapter_requires_owned_dirty_paths(tmp_path):
    base = init_repo(tmp_path)
    (tmp_path / "other.py").write_text("UNOWNED = True\n", encoding="utf-8")
    adapter = RepositoryPatchAdapter(tmp_path)

    with pytest.raises(RuntimeError, match="unowned dirty"):
        adapter.register(
            "EF-test",
            (ProposedFile("module.py", "VALUE = 2\n"),),
            base_sha=base,
        )


def test_adapter_executes_atomic_provider_operation_and_emits_evidence(tmp_path):
    base = init_repo(tmp_path)
    adapter = RepositoryPatchAdapter(tmp_path)
    adapter.register(
        "EF-test",
        (ProposedFile("module.py", "VALUE = 2\n"),),
        base_sha=base,
    )

    receipt = adapter.execute(
        contract={"capabilities": ["repo_patch"]},
        effect={"effect_id": "EF-test"},
        attempt_id="EF-test:attempt:1",
    )

    assert receipt.provider == "repo_patch"
    assert receipt.effect_id == "EF-test"
    assert receipt.attempt_id == "EF-test:attempt:1"
    assert receipt.outcome == "OBSERVED_SUCCESS"
    assert receipt.observation["patch_digest"]
    assert receipt.observation["evidence"]["provider"] == "repo_patch"
    assert receipt.observation["evidence"]["digest"]
    assert (tmp_path / "module.py").read_text(encoding="utf-8") == "VALUE = 2\n"


def test_adapter_integrates_with_real_aios_runtime(tmp_path):
    from core.authority import persist_contract, persist_permit
    from core.capabilities import Capability, CapabilityRegistry
    from core.policy_registry import persist_policy
    from core.contract import CONTRACT_TYPE

    repo = tmp_path / "repo"
    repo.mkdir()
    base = init_repo(repo)
    aios = tmp_path / "aios"
    aios.mkdir()

    registry = CapabilityRegistry()
    registry.register(Capability(
        "repo_patch", "1", "AIOS", "external_effect",
        inputs=("patch",), outputs=("observation",), status="ACTIVE",
    ))
    registry.persist(aios, actor="test-suite")

    policy = {
        "policy_type": "GOVERNING_POLICY",
        "task": "repair",
        "allowed_effects": ["external_effect"],
    }
    policy_digest = persist_policy(aios, policy)

    contract = {
        "contract_type": CONTRACT_TYPE,
        "task_id": "repair-test",
        "scope": "repository",
        "actor": "repair-worker",
        "capabilities": ["repo_patch@1"],
        "input_digest": "sha256:test-input",
        "allowed_effects": ["external_effect"],
        "evidence_required": ["OBSERVED"],
        "max_attempts": 2,
        "terminal_states": ["OBSERVED_SUCCESS", "OBSERVED_FAILURE"],
        "policy_digest": policy_digest,
    }
    stored = persist_contract(aios, contract)
    permit = persist_permit(aios, stored, issuer="test-authority")

    from core.repository_patch_adapter import apply_via_aios

    result = apply_via_aios(
        aios_dir=aios,
        contract_id=stored["contract_id"],
        permit_id=permit["permit_id"],
        logical_operation_id="repair-integration",
        actor="repair-worker",
        repository_root=repo,
        files=(ProposedFile("module.py", "VALUE = 2\n"),),
        base_sha=base,
    )

    assert result["state"] == "OBSERVED_SUCCESS"
    assert result["provider"] == "repo_patch"
    assert result["evidence"]["provider"] == "repo_patch"
    assert result["evidence"]["level"] == "OBSERVED"
    assert (repo / "module.py").read_text(encoding="utf-8") == "VALUE = 2\n"
