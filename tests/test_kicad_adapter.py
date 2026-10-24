# AIOS-CONTRACT: KiCad provider must bind every observation to the authorized effect and attempt.
# AIOS-REGRESSION: Reject workspace escape, unsupported operations and invalid attempt bindings.
# AIOS-OWNER: AIOS candidate kicad.eda provider boundary.
# AIOS-COVERAGE-GAP: Cover read-only inspection and bounded CLI observation without KiCad hardware.
# AIOS-BASELINE: Keep provider success distinct from electrical acceptance PASS.

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from adapters.kicad.adapter import KicadAdapter
from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.policy_registry import persist_policy
from core.runtime import execute, execute_retry_attempt


def _inputs(tmp_path: Path, *, suffix=".kicad_sch", operation="project_inspect"):
    project = tmp_path / f"design{suffix}"
    project.write_text("fixture", encoding="utf-8")
    contract = {"kicad": {"workspace_root": str(tmp_path), "project_path": project.name}}
    effect = {"effect_id": "effect-1", "attempt_id": "effect-1:attempt:1", "operation": operation}
    return project, contract, effect


def test_project_inspect_returns_bound_receipt_without_subprocess(tmp_path):
    project, contract, effect = _inputs(tmp_path)
    with patch("adapters.kicad.adapter.subprocess.run") as run:
        receipt = KicadAdapter().execute(contract=contract, effect=effect, attempt_id=effect["attempt_id"])
    run.assert_not_called()
    assert receipt.provider == "kicad.eda"
    assert receipt.effect_id == effect["effect_id"]
    assert receipt.attempt_id == effect["attempt_id"]
    assert receipt.outcome == "OBSERVED_SUCCESS"
    assert receipt.observation["project_sha256_before"] == hashlib.sha256(project.read_bytes()).hexdigest()
    assert receipt.observation["quality_verdict"] == "NOT_ASSESSED"


def test_rejects_attempt_binding_mismatch(tmp_path):
    _, contract, effect = _inputs(tmp_path)
    with pytest.raises(ValueError, match="attempt_id"):
        KicadAdapter().execute(contract=contract, effect=effect, attempt_id="other-attempt")


def test_rejects_operation_outside_allowlist(tmp_path):
    _, contract, effect = _inputs(tmp_path, operation="gerber_export")
    with pytest.raises(PermissionError, match="not allowlisted"):
        KicadAdapter().execute(contract=contract, effect=effect, attempt_id=effect["attempt_id"])


def test_rejects_project_outside_workspace(tmp_path):
    outside = tmp_path.parent / "outside.kicad_sch"
    outside.write_text("fixture", encoding="utf-8")
    contract = {"kicad": {"workspace_root": str(tmp_path), "project_path": str(outside)}}
    effect = {"effect_id": "e", "attempt_id": "a", "operation": "project_inspect"}
    with pytest.raises(PermissionError, match="escapes"):
        KicadAdapter().execute(contract=contract, effect=effect, attempt_id="a")


def test_erc_reports_process_observation_not_quality_pass(tmp_path):
    project, contract, effect = _inputs(tmp_path, operation="erc_check")
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"ok", stderr=b"")
    real_is_file = Path.is_file

    def run_and_write_report(command, **kwargs):
        report = Path(command[command.index("--output") + 1])
        report.write_text("No violations\\n", encoding="utf-8")
        return completed

    with patch("adapters.kicad.adapter.shutil.which", return_value="/usr/bin/kicad-cli"), patch(
        "adapters.kicad.adapter.Path.is_file", autospec=True,
        side_effect=lambda p: True if str(p) == "/usr/bin/kicad-cli" else real_is_file(p),
    ), patch("adapters.kicad.adapter.subprocess.run", side_effect=run_and_write_report):
        receipt = KicadAdapter().execute(contract=contract, effect=effect, attempt_id=effect["attempt_id"])
    assert receipt.outcome == "OBSERVED_SUCCESS"
    assert receipt.observation["quality_verdict"] == "NOT_ASSESSED"
    assert receipt.observation["project_sha256_before"] == receipt.observation["project_sha256_after"]


def test_nonzero_cli_exit_is_observed_failure(tmp_path):
    _, contract, effect = _inputs(tmp_path, operation="erc_check")
    completed = subprocess.CompletedProcess(args=[], returncode=2, stdout=b"", stderr=b"bad design")
    real_is_file = Path.is_file
    with patch("adapters.kicad.adapter.shutil.which", return_value="/usr/bin/kicad-cli"), patch(
        "adapters.kicad.adapter.Path.is_file", autospec=True,
        side_effect=lambda p: True if str(p) == "/usr/bin/kicad-cli" else real_is_file(p),
    ), patch("adapters.kicad.adapter.subprocess.run", return_value=completed):
        receipt = KicadAdapter().execute(contract=contract, effect=effect, attempt_id=effect["attempt_id"])
    assert receipt.outcome == "OBSERVED_FAILURE"
    assert receipt.observation["process_exit_code"] == 2


# Integration coverage: the provider is reachable only through AIOS authorization.
def _authorized_kicad(tmp_path: Path, project: Path):
    registry = CapabilityRegistry()
    registry.register(Capability("kicad.eda", "1", "test-fixture", "test", status="ACTIVE"))
    registry.persist(str(tmp_path), "test-fixture")
    policy_digest = persist_policy(str(tmp_path), {
        "policy_type": "GOVERNING_POLICY", "name": "kicad-runtime-fixture"
    })
    contract = {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": "kicad-runtime-test",
        "scope": "kicad-read-only",
        "actor": "agent:test",
        "capabilities": ["kicad.eda@1"],
        "input_digest": hashlib.sha256(project.read_bytes()).hexdigest(),
        "allowed_effects": ["external_effect"],
        "evidence_required": ["provider_receipt"],
        "max_attempts": 1,
        "terminal_states": ["SUCCESS", "FAILURE"],
        "policy_digest": policy_digest,
    }
    contract_id = contract_identity(contract)
    persist_contract(str(tmp_path), contract)
    permit = persist_permit(str(tmp_path), contract, "root")
    return contract_id, permit["permit_id"]


def test_kicad_provider_runs_through_aios_authority_and_receipt_boundary(tmp_path):
    project, _, _ = _inputs(tmp_path)
    contract_id, permit_id = _authorized_kicad(tmp_path, project)
    result = execute(str(tmp_path), contract_id, permit_id, "project_inspect", "agent:test", KicadAdapter(workspace_root=str(tmp_path), project_path=project.name))
    assert result["state"] == "OBSERVED_SUCCESS", result.get("unknown_reason", result)
    observation = result["provider_observation"]
    assert observation["provider"] == "kicad.eda"
    assert observation["attempt_id"] == result["attempt_id"]
    assert observation["observation"]["quality_verdict"] == "NOT_ASSESSED"


def test_kicad_provider_timeout_stays_unknown_and_is_not_replayed(tmp_path):
    project, _, _ = _inputs(tmp_path)
    contract_id, permit_id = _authorized_kicad(tmp_path, project)

    class AmbiguousAdapter(KicadAdapter):
        calls = 0

        def execute(self, *, contract, effect, attempt_id):
            self.calls += 1
            raise TimeoutError("simulated CLI timeout")

    adapter = AmbiguousAdapter(workspace_root=str(tmp_path), project_path=project.name)
    result = execute(str(tmp_path), contract_id, permit_id, "project_inspect", "agent:test", adapter)
    assert result["state"] == "UNKNOWN"
    assert "TimeoutError" in result["unknown_reason"]
    assert adapter.calls == 1

    # Recover the persisted effect and prove UNKNOWN cannot be dispatched again
    # without an explicit, effect/attempt-bound retry authorization.
    effects = list((tmp_path / "effects").glob("*.json"))
    assert len(effects) == 1
    effect = json.loads(effects[0].read_text(encoding="utf-8"))
    assert effect["state"] == "UNKNOWN"
    with pytest.raises(PermissionError, match="explicit retry authorization"):
        execute_retry_attempt(
            str(tmp_path), contract_id, permit_id, effect, "agent:test", adapter,
            f'{effect["effect_id"]}:attempt:2', 2,
        )
    assert adapter.calls == 1
    persisted = json.loads(effects[0].read_text(encoding="utf-8"))
    assert persisted["state"] == "UNKNOWN"
    assert persisted["attempt"] == 1



def test_source_mutation_during_cli_is_rejected(tmp_path):
    project, contract, effect = _inputs(tmp_path, operation="erc_check")
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")
    real_is_file = Path.is_file

    def mutate_source(command, **kwargs):
        project.write_text("mutated by unexpected CLI", encoding="utf-8")
        report = Path(command[command.index("--output") + 1])
        report.write_text("report", encoding="utf-8")
        return completed

    with patch("adapters.kicad.adapter.shutil.which", return_value="/usr/bin/kicad-cli"), patch(
        "adapters.kicad.adapter.Path.is_file", autospec=True,
        side_effect=lambda p: True if str(p) == "/usr/bin/kicad-cli" else real_is_file(p),
    ), patch("adapters.kicad.adapter.subprocess.run", side_effect=mutate_source):
        with pytest.raises(RuntimeError, match="changed the source project"):
            KicadAdapter().execute(contract=contract, effect=effect, attempt_id=effect["attempt_id"])


def test_cli_output_limit_fails_closed(tmp_path):
    _, contract, effect = _inputs(tmp_path, operation="erc_check")
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"1234", stderr=b"")
    real_is_file = Path.is_file
    with patch("adapters.kicad.adapter.shutil.which", return_value="/usr/bin/kicad-cli"), patch(
        "adapters.kicad.adapter.Path.is_file", autospec=True,
        side_effect=lambda p: True if str(p) == "/usr/bin/kicad-cli" else real_is_file(p),
    ), patch("adapters.kicad.adapter.subprocess.run", return_value=completed):
        with pytest.raises(ValueError, match="output exceeds configured limit"):
            KicadAdapter(max_output_bytes=3).execute(
                contract=contract, effect=effect, attempt_id=effect["attempt_id"]
            )


def test_missing_cli_fails_closed_without_receipt(tmp_path):
    _, contract, effect = _inputs(tmp_path, operation="erc_check")
    with patch("adapters.kicad.adapter.shutil.which", return_value=None):
        with pytest.raises(FileNotFoundError, match="KiCad CLI not found"):
            KicadAdapter().execute(
                contract=contract, effect=effect, attempt_id=effect["attempt_id"]
            )


def test_real_cli_timeout_through_aios_is_unknown_not_success(tmp_path):
    project, _, _ = _inputs(tmp_path, operation="erc_check")
    contract_id, permit_id = _authorized_kicad(tmp_path, project)
    real_is_file = Path.is_file
    with patch("adapters.kicad.adapter.shutil.which", return_value="/usr/bin/kicad-cli"), patch(
        "adapters.kicad.adapter.Path.is_file", autospec=True,
        side_effect=lambda p: True if str(p) == "/usr/bin/kicad-cli" else real_is_file(p),
    ), patch(
        "adapters.kicad.adapter.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["kicad-cli", "sch", "erc"], timeout=1),
    ):
        result = execute(
            str(tmp_path), contract_id, permit_id, "erc_check", "agent:test",
            KicadAdapter(workspace_root=str(tmp_path), project_path=project.name),
        )
    assert result["state"] == "UNKNOWN"
    assert "TimeoutError" in result["unknown_reason"]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"timeout_seconds": 0}, "timeout_seconds must be positive"),
        ({"timeout_seconds": -1}, "timeout_seconds must be positive"),
        ({"max_output_bytes": 0}, "max_output_bytes must be a positive integer"),
        ({"max_output_bytes": -1}, "max_output_bytes must be a positive integer"),
        ({"executable": ""}, "executable must be a non-empty string"),
    ],
)
def test_adapter_rejects_invalid_resource_bounds(kwargs, message):
    with pytest.raises(ValueError, match=message):
        KicadAdapter(**kwargs)


def test_zero_exit_without_report_is_observed_failure(tmp_path):
    _, contract, effect = _inputs(tmp_path, operation="erc_check")
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"ok", stderr=b"")
    real_is_file = Path.is_file
    with patch("adapters.kicad.adapter.shutil.which", return_value="/usr/bin/kicad-cli"), patch(
        "adapters.kicad.adapter.Path.is_file", autospec=True,
        side_effect=lambda p: True if str(p) == "/usr/bin/kicad-cli" else real_is_file(p),
    ), patch("adapters.kicad.adapter.subprocess.run", return_value=completed):
        receipt = KicadAdapter().execute(
            contract=contract, effect=effect, attempt_id=effect["attempt_id"]
        )
    assert receipt.outcome == "OBSERVED_FAILURE"
    assert receipt.observation["report_missing"] is True
    assert receipt.observation["quality_verdict"] == "NOT_ASSESSED"


def test_adapter_identity_is_fixed_to_governed_capability():
    with pytest.raises(ValueError, match="provider name is fixed to kicad.eda"):
        KicadAdapter(name="other.provider")


@pytest.mark.integration
def test_real_kicad_cli_invocation_is_observed_without_quality_promotion(tmp_path):
    """Run the installed KiCad CLI for real; malformed input must never become quality PASS."""
    import shutil

    executable = shutil.which("kicad-cli")
    if not executable:
        import os
        if os.environ.get("AIOS_REQUIRE_KICAD_CLI") == "1":
            pytest.fail("real KiCad integration job requires kicad-cli on PATH")
        pytest.skip("kicad-cli is not installed; real CLI is exercised by its dedicated workflow")
    project, contract, effect = _inputs(tmp_path, operation="erc_check")
    before = hashlib.sha256(project.read_bytes()).hexdigest()
    receipt = KicadAdapter(
        executable=executable,
        workspace_root=str(tmp_path),
        project_path=project.name,
        timeout_seconds=60,
    ).execute(contract=contract, effect=effect, attempt_id=effect["attempt_id"])
    assert receipt.provider == "kicad.eda"
    assert receipt.effect_id == effect["effect_id"]
    assert receipt.attempt_id == effect["attempt_id"]
    assert receipt.outcome in {"OBSERVED_SUCCESS", "OBSERVED_FAILURE"}
    observation = receipt.observation
    assert isinstance(observation.get("process_exit_code"), int)
    assert observation.get("stdout_sha256")
    assert observation.get("stderr_sha256")
    assert observation["project_sha256_before"] == before
    assert observation["project_sha256_after"] == before
    assert observation["quality_verdict"] == "NOT_ASSESSED"
    # This fixture is intentionally malformed: the integration proves real CLI
    # execution and receipt binding, not that an electrical design passes ERC.
    assert observation["process_exit_code"] != 0 or observation.get("report_sha256")
