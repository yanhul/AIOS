#!/usr/bin/env python3
"""Thin AIOS adapter for the reusable Altium Audit Kit."""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
from pathlib import Path
from core.pcb_eda import PcbEdaRequest, validate_kit_receipt, validate_schematic_receipt

CAPABILITY = "pcb.eda@1"
KIT_ENTRYPOINT = "tools/altium-audit/audit_kit.py"

def run_kit(request: PcbEdaRequest) -> tuple[int, dict]:
    request.validate()
    kit = Path(request.kit_root).resolve() / KIT_ENTRYPOINT
    if not kit.is_file():
        raise FileNotFoundError(str(kit))

    if request.phase == "SCHEMATIC":
        phase_runner = kit.parent / "e2e_phase.py"
        if not phase_runner.is_file():
            raise FileNotFoundError(str(phase_runner))
        command = [
            sys.executable, str(phase_runner), "--phase", "schematic",
            "--input", str(Path(request.input_dir).resolve()),
            "--output", str(Path(request.output_dir).resolve()),
        ]
    else:
        command = [
            sys.executable, str(kit),
            "--input", str(Path(request.input_dir).resolve()),
            "--output", str(Path(request.output_dir).resolve()),
            "--max-retries", str(request.max_retries),
        ]
        if request.repair:
            command.append("--repair")

    if request.config:
        command += ["--config", str(Path(request.config).resolve())]

    proc = subprocess.run(command, text=True, capture_output=True)
    if request.phase == "SCHEMATIC":
        summary = Path(request.output_dir) / "phase_receipt.json"
        if not summary.is_file():
            raise RuntimeError("Audit Kit produced no schematic phase receipt: " + proc.stderr[-2000:])
        receipt = json.loads(summary.read_text(encoding="utf-8"))
        validate_schematic_receipt(receipt)
        return proc.returncode, receipt

    summary = Path(request.output_dir) / "summary.json"
    if not summary.is_file():
        raise RuntimeError("Audit Kit produced no terminal receipt: " + proc.stderr[-2000:])
    receipt = json.loads(summary.read_text(encoding="utf-8"))
    validate_kit_receipt(receipt)
    return proc.returncode, receipt

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task-id", required=True)
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--kit-root", required=True, type=Path)
    ap.add_argument("--config", type=Path)
    ap.add_argument("--max-retries", type=int, default=3)
    ap.add_argument("--no-repair", action="store_true")
    ap.add_argument("--phase", choices=["PCB", "SCHEMATIC"], default="PCB")
    a = ap.parse_args()
    request = PcbEdaRequest(
        task_id=a.task_id, input_dir=str(a.input), output_dir=str(a.output),
        kit_root=str(a.kit_root), config=str(a.config) if a.config else None,
        repair=not a.no_repair, max_retries=a.max_retries, phase=a.phase,
    )
    try:
        rc, receipt = run_kit(request)
        result = {
            "capability": CAPABILITY, "task_id": request.task_id,
            "status": receipt["status"], "receipt": receipt,
            "provenance": {"adapter": CAPABILITY, "kit_root": request.kit_root, "kit_entrypoint": KIT_ENTRYPOINT},
            "provider_returncode": rc,
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if receipt["status"] == "PASS" else 2
    except Exception as exc:
        print(json.dumps({
            "capability": CAPABILITY, "task_id": request.task_id, "status": "BLOCKED",
            "reason": type(exc).__name__ + ": " + str(exc),
            "provenance": {"adapter": CAPABILITY},
        }, sort_keys=True, separators=(",", ":")))
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
