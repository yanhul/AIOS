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


from scripts.ci_repair_publish import (
    require_exact_publish_scope,
    require_matching_source_digest,
    verify_pass_artifact,
)


@pytest.mark.parametrize("field,value", [
    ("schema", 2),
    ("run_id", 99),
    ("base_sha", "wrong"),
])
def test_pass_artifact_rejects_wrong_binding(field, value):
    obj = {
        "schema": 3, "run_id": 42, "base_sha": "a" * 40,
        "attempts": [1, 2], "content_sha256": "b" * 64,
        "test": {"status": "PASS", "evidence_refs": ["pytest://pass"]},
    }
    obj[field] = value
    with pytest.raises(SystemExit, match="not bound"):
        verify_pass_artifact(obj, run_id=42, base_sha="a" * 40, pass_attempt=2)


def test_pass_artifact_rejects_non_pass_and_wrong_attempt():
    obj = {
        "schema": 3, "run_id": 42, "base_sha": "a" * 40,
        "attempts": [1], "content_sha256": "b" * 64,
        "test": {"status": "FAIL", "evidence_refs": ["pytest://fail"]},
    }
    with pytest.raises(SystemExit, match="does not report PASS"):
        verify_pass_artifact(obj, run_id=42, base_sha="a" * 40, pass_attempt=1)
    obj["test"]["status"] = "PASS"
    with pytest.raises(SystemExit, match="attempt sequence"):
        verify_pass_artifact(obj, run_id=42, base_sha="a" * 40, pass_attempt=2)


def test_pass_artifact_rejects_invalid_attempt_sequences():
    base = {
        "schema": 3, "run_id": 42, "base_sha": "a" * 40,
        "attempts": [1, 2], "content_sha256": "b" * 64,
        "test": {"status": "PASS", "evidence_refs": ["pytest://pass"]},
    }
    for attempts in ([2, 2], [1, "2"], [], [1, 3]):
        obj = {**base, "attempts": attempts}
        with pytest.raises(SystemExit, match="attempt sequence"):
            verify_pass_artifact(obj, run_id=42, base_sha="a" * 40, pass_attempt=2)


def test_pass_artifact_rejects_missing_evidence_refs():
    obj = {
        "schema": 3, "run_id": 42, "base_sha": "a" * 40,
        "attempts": [1], "content_sha256": "b" * 64,
        "test": {"status": "PASS", "evidence_refs": []},
    }
    with pytest.raises(SystemExit, match="no valid test evidence"):
        verify_pass_artifact(obj, run_id=42, base_sha="a" * 40, pass_attempt=1)


def test_pass_artifact_rejects_malformed_digest():
    obj = {
        "schema": 3, "run_id": 42, "base_sha": "a" * 40,
        "attempts": [1], "content_sha256": "not-a-digest",
        "test": {"status": "PASS", "evidence_refs": ["pytest://pass"]},
    }
    with pytest.raises(SystemExit, match="invalid content_sha256"):
        verify_pass_artifact(obj, run_id=42, base_sha="a" * 40, pass_attempt=1)


def test_pass_artifact_accepts_exact_binding():
    digest = "b" * 64
    obj = {
        "schema": 3, "run_id": 42, "base_sha": "a" * 40,
        "attempts": [1, 2], "content_sha256": digest,
        "test": {"status": "PASS", "evidence_refs": ["pytest://pass"]},
    }
    assert verify_pass_artifact(obj, run_id=42, base_sha="a" * 40, pass_attempt=2) == digest


def test_publish_requires_exact_staged_scope():
    expected = {"src/fix.py", "tests/test_fix.py"}
    require_exact_publish_scope(
        expected, unstaged=[], staged=sorted(expected), untracked=[],
    )
    with pytest.raises(SystemExit, match="scope mismatch"):
        require_exact_publish_scope(
            expected, unstaged=[], staged=["src/fix.py"], untracked=["extra.txt"],
        )
    with pytest.raises(SystemExit, match="scope mismatch"):
        require_exact_publish_scope(
            expected, unstaged=["src/fix.py"], staged=sorted(expected), untracked=[],
        )


def test_publish_rejects_source_digest_mismatch():
    require_matching_source_digest("expected", "expected")
    with pytest.raises(SystemExit, match="differs"):
        require_matching_source_digest("expected", "actual")
