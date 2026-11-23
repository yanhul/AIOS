"""Adversarial regression matrix for bounded autonomous repository repair.

These tests exercise the trusted worker boundary directly. They do not grant
provider/model code authority and do not treat a timeout as successful work.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from core.agent_repair_worker import AgentRepairWorker, ProposedFile, RepairWorkerError


class RecordingAuthority:
    def __init__(self, *, deny: bool = False):
        self.calls = []
        self.deny = deny

    def authorize_patch(self, *, base_sha, paths):
        self.calls.append((base_sha, paths))
        if self.deny:
            raise RepairWorkerError("authority denied patch")
        return "PERMIT-ADVERSARIAL-1"


def init_repo(root: Path) -> str:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "repair-test@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "AIOS adversarial test"], cwd=root, check=True)
    (root / "module.py").write_text("VALUE = 1\\n", encoding="utf-8")
    subprocess.run(["git", "add", "module.py"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True,
        capture_output=True, check=True,
    ).stdout.strip()


@pytest.mark.parametrize("path", [
    "../outside.py", "src/../../outside.py", "/tmp/outside.py",
    r"..\\outside.py", "src\\..\\..\\outside.py",
])
def test_path_traversal_is_rejected_before_authority(tmp_path, path):
    base = init_repo(tmp_path)
    authority = RecordingAuthority()
    worker = AgentRepairWorker(tmp_path, authority)

    with pytest.raises(RepairWorkerError, match="escapes repository"):
        worker.apply(base_sha=base, files=(ProposedFile(path, "owned = True\\n"),))

    assert authority.calls == []
    assert (tmp_path / "module.py").read_text(encoding="utf-8") == "VALUE = 1\\n"


def test_duplicate_patch_paths_are_rejected_before_authority(tmp_path):
    base = init_repo(tmp_path)
    authority = RecordingAuthority()
    worker = AgentRepairWorker(tmp_path, authority)

    with pytest.raises(RepairWorkerError, match="duplicate paths"):
        worker.apply(base_sha=base, files=(
            ProposedFile("module.py", "VALUE = 2\\n"),
            ProposedFile("module.py", "VALUE = 3\\n"),
        ))

    assert authority.calls == []
    assert (tmp_path / "module.py").read_text(encoding="utf-8") == "VALUE = 1\\n"


def test_unowned_dirty_path_blocks_patch_before_authority(tmp_path):
    base = init_repo(tmp_path)
    (tmp_path / "operator-change.txt").write_text("human work\\n", encoding="utf-8")
    authority = RecordingAuthority()
    worker = AgentRepairWorker(tmp_path, authority)

    with pytest.raises(RepairWorkerError, match="unowned dirty paths"):
        worker.apply(base_sha=base, files=(ProposedFile("module.py", "VALUE = 2\\n"),))

    assert authority.calls == []
    assert (tmp_path / "module.py").read_text(encoding="utf-8") == "VALUE = 1\\n"


def test_authority_denial_leaves_repository_unchanged(tmp_path):
    base = init_repo(tmp_path)
    authority = RecordingAuthority(deny=True)
    worker = AgentRepairWorker(tmp_path, authority)

    with pytest.raises(RepairWorkerError, match="authority denied"):
        worker.apply(base_sha=base, files=(ProposedFile("module.py", "VALUE = 2\\n"),))

    assert authority.calls == [(base, ("module.py",))]
    assert (tmp_path / "module.py").read_text(encoding="utf-8") == "VALUE = 1\\n"


def test_symlink_cannot_escape_repository(tmp_path):
    base = init_repo(tmp_path)
    outside = tmp_path.parent / "outside-repair-target.py"
    outside.write_text("SAFE = True\\n", encoding="utf-8")
    link = tmp_path / "escape.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable on this runner")
    authority = RecordingAuthority()
    worker = AgentRepairWorker(tmp_path, authority)

    with pytest.raises(RepairWorkerError, match="escapes repository"):
        worker.apply(base_sha=base, files=(ProposedFile("escape.py", "SAFE = False\\n"),), allowed_dirty_paths=frozenset({"escape.py"}))

    assert authority.calls == []
    assert outside.read_text(encoding="utf-8") == "SAFE = True\\n"


def test_trusted_test_process_receives_no_authority_secrets(tmp_path, monkeypatch):
    init_repo(tmp_path)
    monkeypatch.setenv("AIOS_AUTHORITY_ATTESTATION_SECRET", "must-not-leak")
    monkeypatch.setenv("PROVIDER_TOKEN", "must-not-leak")
    command = (
        "python", "-c",
        "import os; assert 'AIOS_AUTHORITY_ATTESTATION_SECRET' not in os.environ; "
        "assert 'PROVIDER_TOKEN' not in os.environ",
    )
    worker = AgentRepairWorker(tmp_path, RecordingAuthority(), allowed_test_commands=(command,))

    result = worker.test()

    assert result.status == "PASS"


def test_test_timeout_propagates_and_never_becomes_pass(tmp_path):
    init_repo(tmp_path)
    command = ("python", "-c", "import time; time.sleep(2)")
    worker = AgentRepairWorker(
        tmp_path, RecordingAuthority(),
        allowed_test_commands=(command,), timeout_seconds=1,
    )

    result = worker.test()

    assert result.action == "TEST"
    assert result.status == "FAIL"
    assert result.details["failure_kind"] == "TIMEOUT"
    assert result.details["results"][0]["returncode"] == 124

def test_empty_test_allowlist_fails_closed(tmp_path):
    init_repo(tmp_path)
    worker = AgentRepairWorker(tmp_path, RecordingAuthority())

    with pytest.raises(RepairWorkerError, match="no trusted test command"):
        worker.test()
