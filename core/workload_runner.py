"""Bounded subprocess runner for independently owned AIOS workload adapters."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Sequence

from .workload_adapter import WorkloadResult, validate_adapter_result


class WorkloadAdapterError(RuntimeError):
    pass


def run_workload_adapter(*, workload_id: str, execution_id: str,
                          command: Sequence[str], cwd: str | Path,
                          problem: str, timeout_seconds: int = 300) -> WorkloadResult:
    if not command:
        raise ValueError("command must be non-empty")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    proc = subprocess.run(
        [*command, problem], cwd=str(cwd), text=True,
        capture_output=True, timeout=timeout_seconds, check=False,
    )
    if proc.returncode != 0:
        raise WorkloadAdapterError(f"adapter exited {proc.returncode}: {proc.stderr[-2000:]}")
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise WorkloadAdapterError("adapter stdout is not valid JSON") from exc
    try:
        return validate_adapter_result(
            workload_id=workload_id,
            execution_id=execution_id,
            result=payload,
            cwd=cwd,
        )
    except ValueError as exc:
        raise WorkloadAdapterError(f"invalid adapter result: {exc}") from exc


__all__ = ["WorkloadAdapterError", "run_workload_adapter"]
