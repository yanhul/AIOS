"""Bounded adapter for the independently owned PCB/EDA workload.

AIOS authorizes and verifies the operation. The external Audit Kit performs
domain work; it cannot alter AIOS policy, terminal conditions, or promotion.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .contract import PCB_CAPABILITY, validate_receipt


def _tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    files = sorted(p for p in root.rglob("*") if p.is_file())
    for path in files:
        rel = path.relative_to(root).as_posix().encode()
        h.update(rel)
        h.update(b"\\0")
        h.update(hashlib.sha256(path.read_bytes()).digest())
    return "sha256:" + h.hexdigest()


@dataclass(frozen=True)
class PcbEdaAdapter:
    """Execute one bounded PCB/EDA operation through a subprocess."""
    command: Sequence[str]
    workload_revision: str
    timeout_seconds: float = 600.0
    max_output_bytes: int = 512 * 1024

    def execute(
        self,
        *,
        contract: dict,
        effect: dict,
        attempt_id: str,
        input_dir: Path,
        output_dir: Path,
    ) -> dict:
        capabilities = contract.get("capabilities", [])
        if PCB_CAPABILITY not in capabilities:
            raise PermissionError("PCB/EDA capability is not granted by contract")
        operation = effect.get("operation")
        if operation not in {"audit", "repair", "optimize"}:
            raise ValueError("unsupported PCB/EDA operation")
        if not input_dir.is_dir():
            raise ValueError("PCB input directory does not exist")
        output_dir.mkdir(parents=True, exist_ok=True)

        input_digest = _tree_digest(input_dir)
        args = list(self.command) + [
            "--input", str(input_dir),
            "--output", str(output_dir),
        ]
        if operation in {"repair", "optimize"}:
            args.append("--repair")

        completed = subprocess.run(
            args,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=False,
            shell=False,
        )
        if len(completed.stdout) > self.max_output_bytes:
            raise ValueError("PCB/EDA stdout exceeds output limit")
        if completed.returncode not in (0, 1):
            raise RuntimeError(f"PCB/EDA workload exited with code {completed.returncode}")

        summary_path = output_dir / "summary.json"
        if not summary_path.exists():
            raise ValueError("PCB/EDA workload produced no summary.json")
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        evidence = summary.get("evidence", {}) if isinstance(summary.get("evidence"), dict) else {}
        gates = summary.get("gates", {}) if isinstance(summary.get("gates"), dict) else {}
        quality = summary.get("quality", {}) if isinstance(summary.get("quality"), dict) else {}

        status = summary.get("status")
        if status == "PASS":
            terminal = "PASS"
        elif status == "BLOCKED":
            terminal = "BLOCKED"
        else:
            terminal = "INCONCLUSIVE"

        receipt = {
            "capability": PCB_CAPABILITY,
            "task_id": contract.get("task_id", effect.get("task_id", "pcb-task")),
            "operation": operation,
            "terminal_state": terminal,
            "artifacts": {
                "input_digest": input_digest,
                "output_digest": _tree_digest(output_dir),
                "workload_revision": self.workload_revision,
            },
            "evidence": {
                "intake": {"status": "VERIFIED", "summary": summary.get("intake")},
                "connectivity": {"status": gates.get("G3_CONNECTIVITY", "UNKNOWN")},
                "placement": {"status": gates.get("G6_PLACEMENT", "UNKNOWN")},
                "routing": {
                    "status": gates.get("G7_ROUTING", "UNKNOWN"),
                    "optimization_status": quality.get("optimization_status", "NOT_PROVEN"),
                },
                "provenance": {
                    "attempt_id": attempt_id,
                    "effect_id": effect.get("effect_id"),
                    "workload_revision": self.workload_revision,
                },
            },
        }
        validate_receipt(receipt, expected_operation=operation)
        return receipt


__all__ = ["PcbEdaAdapter"]
