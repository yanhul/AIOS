from __future__ import annotations

import pytest

from scripts.ci_repair_publish import (
    require_exact_publish_scope, require_matching_source_digest, verify_pass_artifact,
)


def _pass_artifact(digest: str) -> dict:
    return {
        "schema": 3,
        "run_id": 77,
        "base_sha": "a" * 40,
        "attempts": [1],
        "content_sha256": digest,
        "test": {"status": "PASS", "evidence_refs": ["test:0:0"]},
    }


def test_publish_rejects_pass_artifact_when_recreated_source_tree_changed():
    tested_digest = "1" * 64
    changed_source_digest = "2" * 64
    artifact = _pass_artifact(tested_digest)

    # The artifact says PASS, but the tree reconstructed at publish differs.
    # Publisher must compare the digest, not trust status/evidence_refs.
    selected_digest = verify_pass_artifact(
        artifact, run_id=77, base_sha="a" * 40, pass_attempt=1,
    )
    assert selected_digest == tested_digest
    with pytest.raises(SystemExit, match="source tree differs"):
        require_matching_source_digest(selected_digest, changed_source_digest)


def test_publish_rejects_unbound_or_non_pass_artifact():
    artifact = _pass_artifact("1" * 64)
    artifact["base_sha"] = "b" * 40
    with pytest.raises(SystemExit, match="not bound"):
        verify_pass_artifact(artifact, run_id=77, base_sha="a" * 40, pass_attempt=1)

    artifact = _pass_artifact("1" * 64)
    artifact["test"]["status"] = "FAIL"
    with pytest.raises(SystemExit, match="does not report PASS"):
        verify_pass_artifact(artifact, run_id=77, base_sha="a" * 40, pass_attempt=1)


def test_publish_blocks_pre_staged_unrelated_file():
    with pytest.raises(SystemExit, match="index/worktree scope mismatch"):
        require_exact_publish_scope(
            {"src/fix.py"}, unstaged=set(),
            staged={"src/fix.py", "unrelated/secret.txt"}, untracked=set(),
        )


def test_publish_requires_exact_staged_set_and_clean_worktree():
    require_exact_publish_scope(
        {"src/fix.py"}, unstaged=set(), staged={"src/fix.py"}, untracked=set(),
    )
    with pytest.raises(SystemExit, match="index/worktree scope mismatch"):
        require_exact_publish_scope(
            {"src/fix.py"}, unstaged={"src/extra.py"},
            staged={"src/fix.py"}, untracked=set(),
        )



def test_autonomous_repair_workflow_is_wired_to_ci_and_exact_head_gates():
    from pathlib import Path

    workflow = (Path(__file__).parents[1] / ".github" / "workflows" /
                "ci-autonomous-repair.yml").read_text(encoding="utf-8")
    assert 'workflows: ["CI", "G4A CI"]' in workflow
    assert "workflow_run:" in workflow
    assert "types: [completed]" in workflow
    assert "pushed_sha" in workflow
    assert 'select(.headSha == $sha)' in workflow
    assert 'gh pr ready "$branch"' in workflow
    assert 'gh pr create --draft' in workflow


def test_test_hygiene_restores_only_four_known_tracked_artifacts(tmp_path):
    import subprocess

    from scripts.ci_repair_test_hygiene import (
        TEST_GENERATED_TRACKED_PATHS, restore_test_generated_artifacts,
    )

    root = tmp_path
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)

    artifact = "research/artifacts/absorption.json"
    unrelated = "src/repair.py"
    (root / artifact).parent.mkdir(parents=True)
    (root / artifact).write_text("baseline", encoding="utf-8")
    (root / unrelated).parent.mkdir(parents=True)
    (root / unrelated).write_text("baseline", encoding="utf-8")
    subprocess.run(["git", "add", artifact, unrelated], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "baseline"], cwd=root, check=True)

    (root / artifact).write_text("test output", encoding="utf-8")
    (root / unrelated).write_text("proposed repair", encoding="utf-8")

    def git(*args):
        proc = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=True)
        return proc.stdout.strip()

    restored = restore_test_generated_artifacts(git)
    assert restored == (artifact,)
    assert (root / artifact).read_text(encoding="utf-8") == "baseline"
    assert (root / unrelated).read_text(encoding="utf-8") == "proposed repair"
    assert set(git("diff", "--name-only").splitlines()) == {unrelated}
    assert TEST_GENERATED_TRACKED_PATHS == frozenset({
        "research/artifacts/absorption-promotion.json",
        "research/artifacts/absorption-repair.json",
        "research/artifacts/absorption-runtime-proof.json",
        "research/artifacts/absorption.json",
    })


def test_test_hygiene_fails_closed_if_generated_artifact_is_staged(tmp_path):
    import subprocess

    from scripts.ci_repair_test_hygiene import restore_test_generated_artifacts

    root = tmp_path
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
    artifact = "research/artifacts/absorption.json"
    (root / artifact).parent.mkdir(parents=True)
    (root / artifact).write_text("baseline", encoding="utf-8")
    subprocess.run(["git", "add", artifact], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "baseline"], cwd=root, check=True)
    (root / artifact).write_text("staged output", encoding="utf-8")
    subprocess.run(["git", "add", artifact], cwd=root, check=True)

    def git(*args):
        proc = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=True)
        return proc.stdout.strip()

    with pytest.raises(SystemExit, match="were staged"):
        restore_test_generated_artifacts(git)
