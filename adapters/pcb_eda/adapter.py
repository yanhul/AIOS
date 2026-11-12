#!/usr/bin/env python3
"""Thin AIOS adapter for the reusable Altium Audit Kit."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from adapters.bounded_process import OutputLimitExceeded, run_bounded
from core.pcb_eda import (
    PcbEdaRequest,
    validate_kit_receipt,
    validate_schematic_receipt,
)

CAPABILITY = "pcb.eda@1"
KIT_ENTRYPOINT = "tools/altium-audit/audit_kit.py"
SCHEMATIC_PHASE = "SCHEMATIC"
DEFAULT_TIMEOUT_SECONDS = 1800.0
DEFAULT_MAX_OUTPUT_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_RECEIPT_BYTES = 8 * 1024 * 1024


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _tail(data, limit: int = 2000) -> str:
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    return (data or "")[-limit:]


def _load_receipt(path: Path, max_bytes: int) -> dict:
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"Audit Kit receipt exceeds size limit ({size} > {max_bytes} bytes)")
    return json.loads(path.read_text(encoding="utf-8"))


def run_kit(request: PcbEdaRequest, *, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
            max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
            max_receipt_bytes: int = DEFAULT_MAX_RECEIPT_BYTES) -> tuple[int, dict]:
    request.validate()
    if not timeout_seconds or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    kit_root = Path(request.kit_root).resolve()
    input_dir = Path(request.input_dir).resolve()
    output_dir = Path(request.output_dir).resolve()
    if not kit_root.is_dir():
        raise FileNotFoundError(f"kit_root is not a directory: {kit_root}")
    if not input_dir.is_dir():
        raise FileNotFoundError(f"input is not a directory: {input_dir}")
    if output_dir == input_dir or _inside(output_dir, kit_root) or _inside(input_dir, output_dir):
        raise PermissionError("output directory must not overlap the input tree or the kit")
    if request.config and not Path(request.config).resolve().is_file():
        raise FileNotFoundError(f"config is not a file: {request.config}")
    output_dir.mkdir(parents=True, exist_ok=True)
    # Never accept a stale receipt from an earlier run as this run's result.
    for stale in ("phase_receipt.json", "summary.json"):
        (output_dir / stale).unlink(missing_ok=True)

    if request.phase == SCHEMATIC_PHASE:
        entrypoint = kit_root / "tools/altium-audit/e2e_phase.py"
        if not entrypoint.is_file():
            raise FileNotFoundError(str(entrypoint))
        command = [
            sys.executable, str(entrypoint), "--phase", "schematic",
            "--input", str(input_dir), "--output", str(output_dir),
        ]
    else:
        entrypoint = kit_root / KIT_ENTRYPOINT
        if not entrypoint.is_file():
            raise FileNotFoundError(str(entrypoint))
        command = [
            sys.executable, str(entrypoint),
            "--input", str(input_dir), "--output", str(output_dir),
            "--max-retries", str(request.max_retries),
        ]
        if request.repair:
            command.append("--repair")

    if request.config:
        command += ["--config", str(Path(request.config).resolve())]

    try:
        proc = run_bounded(command, timeout=timeout_seconds,
                           max_stdout_bytes=max_output_bytes, max_stderr_bytes=max_output_bytes)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"Audit Kit timed out after {timeout_seconds}s; process tree killed") from exc
    except OutputLimitExceeded as exc:
        raise ValueError(f"Audit Kit {exc.stream} exceeds output limit; process tree killed") from exc
    if request.phase == SCHEMATIC_PHASE:
        summary = output_dir / "phase_receipt.json"
        if not summary.is_file():
            raise RuntimeError(
                "Audit Kit produced no schematic phase receipt: " + _tail(proc.stderr)
            )
        receipt = _load_receipt(summary, max_receipt_bytes)
        validate_schematic_receipt(receipt)
    else:
        summary = output_dir / "summary.json"
        if not summary.is_file():
            raise RuntimeError("Audit Kit produced no terminal receipt: " + _tail(proc.stderr))
        receipt = _load_receipt(summary, max_receipt_bytes)
        validate_kit_receipt(receipt)

    if receipt.get("status") == "PASS" and proc.returncode != 0:
        raise ValueError("Audit Kit receipt claims PASS but process returned non-zero")
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
    ap.add_argument("--phase", choices=["PCB", SCHEMATIC_PHASE], default="PCB")
    ap.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    ap.add_argument("--max-output-bytes", type=int, default=DEFAULT_MAX_OUTPUT_BYTES)
    a = ap.parse_args()
    request = PcbEdaRequest(
        task_id=a.task_id,
        input_dir=str(a.input),
        output_dir=str(a.output),
        kit_root=str(a.kit_root),
        config=str(a.config) if a.config else None,
        repair=not a.no_repair,
        max_retries=a.max_retries,
        phase=a.phase,
    )
    try:
        rc, receipt = run_kit(request, timeout_seconds=a.timeout_seconds,
                              max_output_bytes=a.max_output_bytes)
        result = {
            "capability": CAPABILITY,
            "task_id": request.task_id,
            "status": receipt["status"],
            "receipt": receipt,
            "provenance": {
                "adapter": CAPABILITY,
                "kit_root": request.kit_root,
                "kit_entrypoint": (
                    "tools/altium-audit/e2e_phase.py"
                    if request.phase == SCHEMATIC_PHASE else KIT_ENTRYPOINT
                ),
                "phase": request.phase,
            },
            "provider_returncode": rc,
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if receipt["status"] == "PASS" else 2
    except Exception as exc:
        result = {
            "capability": CAPABILITY,
            "task_id": request.task_id,
            "status": "BLOCKED",
            "reason": type(exc).__name__ + ": " + str(exc),
            "provenance": {"adapter": CAPABILITY, "phase": request.phase},
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
