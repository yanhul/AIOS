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
