#!/usr/bin/env python3
"""CLI bridge for running an external workload through the AIOS result boundary."""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from core.workload_runner import WorkloadAdapterError, run_workload_adapter


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workload-id", required=True)
    parser.add_argument("--execution-id", required=True)
    parser.add_argument("--cwd", default=".")
    parser.add_argument("--problem", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("command is required after --")
    try:
        result = run_workload_adapter(
            workload_id=args.workload_id,
            execution_id=args.execution_id,
            command=command,
            cwd=Path(args.cwd),
            problem=args.problem,
            timeout_seconds=args.timeout_seconds,
        )
    except (WorkloadAdapterError, ValueError) as exc:
        print(f"AIOS_WORKLOAD: BLOCKED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "workload_id": result.workload_id,
        "execution_id": result.execution_id,
        "status": result.status,
        "artifact_refs": list(result.artifact_refs),
        "evidence_refs": list(result.evidence_refs),
        "verification_refs": list(result.verification_refs),
        "provenance": dict(result.provenance),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
