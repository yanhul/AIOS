from __future__ import annotations

import subprocess

import pytest

from scripts.ci_repair_test_hygiene import (
    TEST_GENERATED_TRACKED_PATHS,
    restore_test_generated_artifacts,
)


def _git(root, *args):
    proc = subprocess.run(
        ["git", *args], cwd=root, text=True, capture_output=True, check=True,
    )
    return proc.stdout.strip()


def _repo(root):
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Test")


def test_test_hygiene_restores_only_known_tracked_artifacts(tmp_path):
    root = tmp_path
    _repo(root)
    artifact = "research/artifacts/absorption.json"
    unrelated = "src/repair.py"
    (root / artifact).parent.mkdir(parents=True)
    (root / artifact).write_text("baseline", encoding="utf-8")
    (root / unrelated).parent.mkdir(parents=True)
    (root / unrelated).write_text("baseline", encoding="utf-8")
    _git(root, "add", artifact, unrelated)
    _git(root, "commit", "-qm", "baseline")

    (root / artifact).write_text("test output", encoding="utf-8")
    (root / unrelated).write_text("proposed repair", encoding="utf-8")

    restored = restore_test_generated_artifacts(lambda *args: _git(root, *args))
    assert restored == (artifact,)
    assert (root / artifact).read_text(encoding="utf-8") == "baseline"
    assert (root / unrelated).read_text(encoding="utf-8") == "proposed repair"
    assert set(_git(root, "diff", "--name-only").splitlines()) == {unrelated}
    assert TEST_GENERATED_TRACKED_PATHS == frozenset({
        "research/artifacts/absorption-promotion.json",
        "research/artifacts/absorption-repair.json",
        "research/artifacts/absorption-runtime-proof.json",
        "research/artifacts/absorption.json",
    })


def test_test_hygiene_fails_closed_if_generated_artifact_is_staged(tmp_path):
    root = tmp_path
    _repo(root)
    artifact = "research/artifacts/absorption.json"
    (root / artifact).parent.mkdir(parents=True)
    (root / artifact).write_text("baseline", encoding="utf-8")
    _git(root, "add", artifact)
    _git(root, "commit", "-qm", "baseline")
    (root / artifact).write_text("staged output", encoding="utf-8")
    _git(root, "add", artifact)

    with pytest.raises(SystemExit, match="were staged"):
        restore_test_generated_artifacts(lambda *args: _git(root, *args))
