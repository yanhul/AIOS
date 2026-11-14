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


@pytest.mark.parametrize("path", [
    "nested/.git/config",
    "nested/.github/workflows/ci.yml",
    "nested/.aios/authority.json",
    "nested/tests/test_security.py",
    "nested/pytest.ini",
    "nested/core/policy_registry.py",
    "nested/core/gatekeeper.py",
    "nested/core/publisher.py",
    "nested/../.github/workflows/ci.yml",
    ".env.development", ".env.test", ".env.staging", "config/.env.production.local",
])
def test_worker_rejects_protected_paths_at_any_depth(tmp_path, path):
    base = init_repo(tmp_path)
    worker = AgentRepairWorker(tmp_path, FakeAuthority())
    with pytest.raises(RepairWorkerError, match="protected|escapes"):
        worker.apply(base_sha=base, files=(ProposedFile(path, "tampered"),))


def test_worker_unknown_mutation_blocks_followup_tests(tmp_path, monkeypatch):
    base = init_repo(tmp_path)
    worker = AgentRepairWorker(
        tmp_path, FakeAuthority(),
        allowed_test_commands=(( "python", "-c", "raise SystemExit(99)"),),
        aios_dir=str(tmp_path / "aios"),
        contract_id="contract", permit_id="permit", actor="repair-worker",
    )
    import core.repository_patch_adapter as patch_adapter
    monkeypatch.setattr(patch_adapter, "apply_via_aios", lambda **kwargs: {"state": "UNKNOWN"})
    with pytest.raises(RepairWorkerError, match="UNKNOWN"):
        worker.apply_via_aios(
            base_sha=base, files=(ProposedFile("module.py", "VALUE = 2\\n"),),
            logical_operation_id="unknown-mutation",
        )
    with pytest.raises(RepairWorkerError, match="UNKNOWN"):
        worker.test()


@pytest.mark.parametrize("path", [
    r"C:\\outside.py",
    r"C:relative.py",
    r"\\server\\share\\payload.py",
    "module.py:alternate-stream",
    "pyproject.toml",
    "nested/test_runner.py",
])
def test_worker_rejects_windows_aliases_and_test_harness_paths(tmp_path, path):
    base = init_repo(tmp_path)
    worker = AgentRepairWorker(tmp_path, FakeAuthority())
    with pytest.raises(RepairWorkerError, match="escapes|protected"):
        worker.apply(base_sha=base, files=(ProposedFile(path, "tampered"),))


def test_worker_rejects_symlinked_final_and_parent_components(tmp_path):
    base = init_repo(tmp_path)
    worker = AgentRepairWorker(tmp_path, FakeAuthority())
    (tmp_path / "alias.py").symlink_to(tmp_path / "module.py")
    (tmp_path / "alias_dir").symlink_to(tmp_path, target_is_directory=True)
    for path in ("alias.py", "alias_dir/new_module.py"):
        with pytest.raises(RepairWorkerError, match="symlink"):
            worker.apply(base_sha=base, files=(ProposedFile(path, "tampered"),),
                         allowed_dirty_paths=frozenset({"alias.py", "alias_dir"}))


def test_worker_unknown_exception_after_dispatch_blocks_tests(tmp_path, monkeypatch):
    base = init_repo(tmp_path)
    worker = AgentRepairWorker(
        tmp_path, FakeAuthority(),
        allowed_test_commands=(("python", "-c", "raise SystemExit(99)"),),
        aios_dir=str(tmp_path / "aios"), contract_id="contract",
        permit_id="permit", actor="repair-worker",
    )
    import core.repository_patch_adapter as patch_adapter
    def lost_receipt(**kwargs):
        raise TimeoutError("provider response lost after dispatch")
    monkeypatch.setattr(patch_adapter, "apply_via_aios", lost_receipt)
    with pytest.raises(RepairWorkerError, match="UNKNOWN"):
        worker.apply_via_aios(
            base_sha=base, files=(ProposedFile("module.py", "VALUE = 2\\n"),),
            logical_operation_id="lost-receipt",
        )
    with pytest.raises(RepairWorkerError, match="UNKNOWN"):
        worker.test()


def test_worker_partial_local_mutation_freezes_all_followup_actions(tmp_path, monkeypatch):
    base = init_repo(tmp_path)
    worker = AgentRepairWorker(
        tmp_path, FakeAuthority(),
        allowed_test_commands=(("python", "-c", "raise SystemExit(99)"),),
    )
    real_write = worker._atomic_write
    calls = 0

    def fail_after_first(target, content):
        nonlocal calls
        calls += 1
        if calls == 1:
            return real_write(target, content)
        raise OSError("simulated second-file write failure")

    monkeypatch.setattr(worker, "_atomic_write", fail_after_first)
    with pytest.raises(RepairWorkerError, match="UNKNOWN"):
        worker.apply(
            base_sha=base,
            files=(
                ProposedFile("module.py", "VALUE = 2\\n"),
                ProposedFile("second.py", "VALUE = 3\\n"),
            ),
        )
    with pytest.raises(RepairWorkerError, match="UNKNOWN"):
        worker.test()
    with pytest.raises(RepairWorkerError, match="UNKNOWN"):
        worker.apply(base_sha=base, files=(ProposedFile("module.py", "VALUE = 4\\n"),))

@pytest.mark.parametrize("path", ["tests./test_security.py", "nested/CON.txt", "nested/LPT1.log"])
def test_worker_rejects_windows_normalization_aliases(tmp_path, path):
    base = init_repo(tmp_path)
    worker = AgentRepairWorker(tmp_path, FakeAuthority())
    with pytest.raises(RepairWorkerError, match="protected"):
        worker.apply(base_sha=base, files=(ProposedFile(path, "tampered"),))


def test_new_worker_instance_blocks_on_durable_unknown_effect(tmp_path):
    from core.authority import persist_contract, persist_permit
    from core.capabilities import Capability, CapabilityRegistry
    from core.contract import CONTRACT_TYPE
    from core.effect_authority import create_effect, dispatch, unknown
    from core.policy_registry import persist_policy

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
    policy_digest = persist_policy(aios, {
        "policy_type": "GOVERNING_POLICY", "task": "repair",
        "allowed_effects": ["external_effect"],
    })
    contract = {
        "contract_type": CONTRACT_TYPE, "task_id": "durable-unknown-recovery",
        "scope": "repository", "actor": "repair-worker",
        "capabilities": ["repo_patch@1"], "input_digest": "sha256:test",
        "allowed_effects": ["external_effect"], "evidence_required": ["OBSERVED"],
        "max_attempts": 2,
        "terminal_states": ["OBSERVED_SUCCESS", "OBSERVED_FAILURE"],
        "policy_digest": policy_digest,
    }
    stored = persist_contract(aios, contract)
    permit = persist_permit(aios, stored, issuer="test-authority")
    effect = create_effect(
        aios, stored["contract_id"], "lost-receipt-after-dispatch",
        "repair-worker", permit["permit_id"], "external_effect",
    )
    dispatched = dispatch(
        aios, effect["effect_id"], "repair-worker",
        f"{effect['effect_id']}:attempt:1", "repo_patch",
    )
    unknown(aios, dispatched["effect_id"], "repair-worker", "simulated lost receipt")

    # A fresh process/worker has no in-memory _mutation_unknown flag.
    restarted = AgentRepairWorker(
        repo, FakeAuthority(),
        allowed_test_commands=(("python", "-c", "assert True"),),
        aios_dir=str(aios), contract_id=stored["contract_id"],
        permit_id=permit["permit_id"], actor="repair-worker",
    )
    with pytest.raises(RepairWorkerError, match="durable mutation outcome is unresolved"):
        restarted.test()
    with pytest.raises(RepairWorkerError, match="durable mutation outcome is unresolved"):
        restarted.apply(
            base_sha=base, files=(ProposedFile("module.py", "VALUE = 9\\n"),)
        )

    # Rotate to a newly issued contract/permit for the same actor. The
    # unresolved effect from the old contract must still freeze this worker.
    rotated_contract = dict(contract)
    rotated_contract["task_id"] = "durable-unknown-recovery-rotated"
    rotated_stored = persist_contract(aios, rotated_contract)
    rotated_permit = persist_permit(aios, rotated_stored, issuer="test-authority")
    rotated_worker = AgentRepairWorker(
        repo, FakeAuthority(),
        allowed_test_commands=(("python", "-c", "assert True"),),
        aios_dir=str(aios), contract_id=rotated_stored["contract_id"],
        permit_id=rotated_permit["permit_id"], actor="repair-worker",
    )
    with pytest.raises(RepairWorkerError, match="durable mutation outcome is unresolved"):
        rotated_worker.test()
