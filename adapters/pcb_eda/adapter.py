#!/usr/bin/env python3
"""Thin AIOS adapter for the reusable Altium Audit Kit."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from core.pcb_eda import PcbEdaRequest, validate_kit_receipt

CAPABILITY = "pcb.eda@1"
KIT_ENTRYPOINT = "tools/altium-audit/audit_kit.py"


def run_kit(request: PcbEdaRequest) -> tuple[int, dict]:
    request.validate()
    kit = Path(request.kit_root).resolve() / KIT_ENTRYPOINT
    if not kit.is_file():
        raise FileNotFoundError(f"Audit Kit entrypoint missing: {kit}")
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
    summary_path = Path(request.output_dir) / "summary.json"
    if not summary_path.is_file():
        raise RuntimeError(
            f"Audit Kit produced no terminal receipt; rc={proc.returncode}; "
            f"stderr={proc.stderr[-2000:]}"
        )
    receipt = json.loads(summary_path.read_text(encoding="utf-8"))
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
    args = ap.parse_args()

    request = PcbEdaRequest(
        task_id=args.task_id,
        input_dir=str(args.input),
        output_dir=str(args.output),
        kit_root=str(args.kit_root),
        config=str(args.config) if args.config else None,
        repair=not args.no_repair,
        max_retries=args.max_retries,
    )

    try:
        rc, receipt = run_kit(request)
        result = {
            "capability": CAPABILITY,
            "task_id": request.task_id,
            "status": receipt["status"],
            "effect": {"capability": CAPABILITY, "input": request.input_dir},
            "attempt": {"max_retries": request.max_retries},
            "receipt": receipt,
            "evidence_refs": [
                str(Path(request.output_dir) / "summary.json"),
                str(Path(request.output_dir) / "placement-routing-plan.json"),
            ],
            "provenance": {
                "adapter": CAPABILITY,
                "kit_root": request.kit_root,
                "kit_entrypoint": KIT_ENTRYPOINT,
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
            "reason": f"{type(exc).__name__}: {exc}",
            "provenance": {"adapter": CAPABILITY},
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
