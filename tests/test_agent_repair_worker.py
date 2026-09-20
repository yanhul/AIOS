from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from core.agent_repair_worker import (
    AgentRepairWorker,
    ProposedFile,
    RepairProposal,
    RepairWorkerError,
)


class FakeAuthority:
    def __init__(self):
        self.calls = []

    def authorize_patch(self, *, base_sha, paths):
        self.calls.append((base_sha, paths))
        return "PERMIT-REPAIR-1"


class FakeProposer:
    def __init__(self, files):
        self.files = files

    def propose(self, *, failure, repository_snapshot):
        return RepairProposal(
            root_cause="known test failure",
            proposed_fix="replace broken implementation",
            files=tuple(self.files),
            regression_tests=("trusted",),
        )


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


def test_worker_requires_authority_before_mutation(tmp_path):
    base = init_repo(tmp_path)
    authority = FakeAuthority()
    worker = AgentRepairWorker(
        tmp_path,
        authority,
        allowed_test_commands=(("python", "-c", "assert open('module.py').read().strip() == 'VALUE = 2'"),),
    )

    applied = worker.apply(
        base_sha=base,
        files=(ProposedFile("module.py", "VALUE = 2\n"),),
    )

    assert applied.status == "APPLIED"
    assert authority.calls == [(base, ("module.py",))]
    assert (tmp_path / "module.py").read_text(encoding="utf-8") == "VALUE = 2\n"


def test_worker_refuses_protected_paths(tmp_path):
    base = init_repo(tmp_path)
    worker = AgentRepairWorker(tmp_path, FakeAuthority())

    with pytest.raises(RepairWorkerError, match="protected"):
        worker.apply(
            base_sha=base,
            files=(ProposedFile(".github/workflows/ci.yml", "evil"),),
        )


def test_worker_refuses_stale_base(tmp_path):
    base = init_repo(tmp_path)
    worker = AgentRepairWorker(tmp_path, FakeAuthority())

    with pytest.raises(RepairWorkerError, match="stale repair base"):
        worker.apply(
            base_sha="0" * 40,
            files=(ProposedFile("module.py", "VALUE = 2\n"),),
        )


def test_worker_never_accepts_untrusted_test_command(tmp_path):
    init_repo(tmp_path)
    trusted = ("python", "-c", "assert True")
    worker = AgentRepairWorker(
        tmp_path, FakeAuthority(), allowed_test_commands=(trusted,)
    )

    with pytest.raises(RepairWorkerError, match="allowlist"):
        worker.test((("python", "-c", "open('owned').write('bad')"),))


def test_worker_reports_test_failure_without_claiming_pass(tmp_path):
    init_repo(tmp_path)
    trusted = ("python", "-c", "assert False")
    worker = AgentRepairWorker(
        tmp_path, FakeAuthority(), allowed_test_commands=(trusted,)
    )

    result = worker.test()

    assert result.status == "FAIL"
    assert result.action == "TEST"
    assert result.details["results"][0]["returncode"] != 0


def test_worker_full_repair_path(tmp_path):
    base = init_repo(tmp_path)
    trusted = ("python", "-c", "assert open('module.py').read().strip() == 'VALUE = 2'")
    worker = AgentRepairWorker(
        tmp_path, FakeAuthority(), allowed_test_commands=(trusted,)
    )

    proposal, applied, tested = worker.repair(
        base_sha=base,
        failure={"job": "pytest", "error": "VALUE mismatch"},
        repository_snapshot="module.py: VALUE = 1",
        proposer=FakeProposer((ProposedFile("module.py", "VALUE = 2\n"),)),
    )

    assert proposal.root_cause
    assert applied.status == "APPLIED"
    assert tested.status == "PASS"
