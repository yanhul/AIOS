# AIOS-CONTRACT: PCB EDA adapter must validate phase-specific receipts before returning status.
# AIOS-REGRESSION: Reject malformed schematic receipts and PASS with non-zero provider exit.
# AIOS-OWNER: AIOS pcb.eda@1 adapter boundary.
# AIOS-COVERAGE-GAP: Cover direct schematic phase dispatch independently of full PCB closure.
# AIOS-BASELINE: Preserve governed adapter status and provenance contract.

import json
import subprocess

import pytest

from adapters.pcb_eda.adapter import run_kit
from core.pcb_eda import PcbEdaRequest


def schematic_receipt():
    return {
        "schema": "altium-audit-e2e-phase/v2",
        "phase": "SCHEMATIC",
        "status": "PASS",
        "evidence": {
            "required_gates": {
                "G0_INTAKE": "VERIFIED",
                "G1_PARSE": "VERIFIED",
                "G2_COMPILE": "VERIFIED",
                "G3_CONNECTIVITY": "VERIFIED",
            },
            "finding_inventory": {
                "errors": [],
                "blocking": [],
                "deferred_non_gating": [],
            },
        },
    }


def test_adapter_runs_schematic_phase_and_validates_phase_receipt(tmp_path, monkeypatch):
    kit = tmp_path / "kit"
    (kit / "tools/altium-audit").mkdir(parents=True)
    (kit / "tools/altium-audit/e2e_phase.py").write_text("# test fixture", encoding="utf-8")
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    config = tmp_path / "config.json"
    config.write_text("{}", encoding="utf-8")

    def fake_run(command, **kwargs):
        assert command[command.index("--phase") + 1] == "schematic"
        (output_dir / "phase_receipt.json").write_text(
            json.dumps(schematic_receipt()), encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("adapters.pcb_eda.adapter.subprocess.run", fake_run)
    request = PcbEdaRequest(
        task_id="schematic-test", input_dir=str(input_dir), output_dir=str(output_dir),
        kit_root=str(kit), config=str(config), phase="SCHEMATIC",
    )
    code, receipt = run_kit(request)
    assert code == 0
    assert receipt["phase"] == "SCHEMATIC"
    assert receipt["status"] == "PASS"


def test_adapter_rejects_pass_receipt_if_provider_exits_nonzero(tmp_path, monkeypatch):
    kit = tmp_path / "kit"
    (kit / "tools/altium-audit").mkdir(parents=True)
    (kit / "tools/altium-audit/e2e_phase.py").write_text("# test fixture", encoding="utf-8")
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    def fake_run(command, **kwargs):
        (output_dir / "phase_receipt.json").write_text(
            json.dumps(schematic_receipt()), encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 7, "", "provider failed")

    monkeypatch.setattr("adapters.pcb_eda.adapter.subprocess.run", fake_run)
    request = PcbEdaRequest(
        task_id="schematic-test", input_dir=str(input_dir), output_dir=str(output_dir),
        kit_root=str(kit), phase="SCHEMATIC",
    )
    with pytest.raises(ValueError, match="returned non-zero"):
        run_kit(request)


def test_adapter_blocks_missing_schematic_receipt(tmp_path, monkeypatch):
    kit = tmp_path / "kit"
    (kit / "tools/altium-audit").mkdir(parents=True)
    (kit / "tools/altium-audit/e2e_phase.py").write_text("# test fixture", encoding="utf-8")
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    monkeypatch.setattr(
        "adapters.pcb_eda.adapter.subprocess.run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "", ""),
    )
    request = PcbEdaRequest(
        task_id="schematic-test", input_dir=str(input_dir), output_dir=str(output_dir),
        kit_root=str(kit), phase="SCHEMATIC",
    )
    with pytest.raises(RuntimeError, match="no schematic phase receipt"):
        run_kit(request)
