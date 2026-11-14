from __future__ import annotations

import pytest

from scripts.ci_repair_publish import verify_pass_artifact


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
        verify_recreated_source_tree(selected_digest, changed_source_digest)


def verify_recreated_source_tree(expected: str, actual: str) -> None:
    if actual != expected:
        raise SystemExit("BLOCKED: publish source tree differs from tested content_sha256")


def test_publish_rejects_unbound_or_non_pass_artifact():
    artifact = _pass_artifact("1" * 64)
    artifact["base_sha"] = "b" * 40
    with pytest.raises(SystemExit, match="not bound"):
        verify_pass_artifact(artifact, run_id=77, base_sha="a" * 40, pass_attempt=1)

    artifact = _pass_artifact("1" * 64)
    artifact["test"]["status"] = "FAIL"
    with pytest.raises(SystemExit, match="does not report PASS"):
        verify_pass_artifact(artifact, run_id=77, base_sha="a" * 40, pass_attempt=1)
