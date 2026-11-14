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
