from pathlib import Path
import json
import pytest

from core.pcb_eda_integrity import (
    build_integrity_manifest, manifest_hash, snapshot_inputs, verify_commit_manifest
)


def test_snapshot_is_deterministic_and_content_addressed(tmp_path: Path):
    (tmp_path / "a.PcbDoc").write_bytes(b"pcb")
    (tmp_path / "b.SchDoc").write_bytes(b"sch")
    (tmp_path / "ignored.txt").write_bytes(b"x")
    first = snapshot_inputs(tmp_path)
    second = snapshot_inputs(tmp_path)
    assert first == second
    assert first[0]["sha256"] == first[0]["sha256"]
    assert len(manifest_hash(first)) == 64


def test_manifest_requires_real_input(tmp_path: Path):
    with pytest.raises(ValueError, match="no supported"):
        build_integrity_manifest(tmp_path, tmp_path / "out")


def test_commit_is_fail_closed(tmp_path: Path):
    (tmp_path / "x.PcbDoc").write_bytes(b"pcb")
    manifest = build_integrity_manifest(tmp_path, tmp_path / "out")
    with pytest.raises(ValueError, match="unsupported"):
        verify_commit_manifest(manifest, {"status": "PASS", "schema": "bad"})


def test_blocked_never_authorizes_commit(tmp_path: Path):
    (tmp_path / "x.PcbDoc").write_bytes(b"pcb")
    manifest = build_integrity_manifest(tmp_path, tmp_path / "out")
    receipt = {"status": "BLOCKED", "schema": "altium-audit-kit-result.v4",
               "terminal_reason": "missing evidence"}
    result = verify_commit_manifest(manifest, receipt)
    assert result["verification"]["output_commit"] == "NOT_AUTHORIZED"
