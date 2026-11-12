#!/usr/bin/env python3
"""Thin AIOS adapter for the reusable Altium Audit Kit."""
from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from adapters.bounded_process import OutputLimitExceeded, output_limit_error, run_bounded, timeout_error
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
RECEIPT_NAMES = ("phase_receipt.json", "summary.json")


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


def _canonical_dir(raw: str, label: str) -> Path:
    """Absolute, ``..``-free, symlink-resolved path (existing parents resolved)."""
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise ValueError(f"{label} must be a non-empty path")
    return Path(os.path.realpath(os.path.abspath(raw)))


def _overlaps(a: Path, b: Path) -> bool:
    return a == b or _inside(a, b) or _inside(b, a)


def check_path_isolation(input_dir: Path, output_dir: Path, kit_root: Path) -> None:
    """Reject equality and every ancestor/descendant relation of output vs input/kit."""
    for label, other in (("input tree", input_dir), ("kit", kit_root)):
        if _overlaps(output_dir, other):
            raise PermissionError(f"output directory must not overlap the {label} "
                                  f"(output={output_dir}, {label}={other})")


def _dir_identity(path: Path) -> tuple[int, int]:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise PermissionError(f"output directory must be a real directory, not a symlink: {path}")
    return st.st_dev, st.st_ino


def _verify_output_identity(raw: str, expected: Path, identity: tuple[int, int]) -> None:
    """TOCTOU guard: the output dir must still be the very directory we validated."""
    if _canonical_dir(raw, "output_dir") != expected or _dir_identity(expected) != identity:
        raise PermissionError("output directory was replaced or redirected during execution")


def _remove_stale(output_dir: Path, name: str) -> None:
    target = output_dir / name
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
        raise PermissionError(f"stale receipt path is a directory: {target}")
    os.unlink(target)  # unlinks a symlink itself, never its target


def _load_receipt(output_dir: Path, name: str, max_bytes: int) -> dict:
    path = output_dir / name
    if path.parent != output_dir or _canonical_dir(str(path), "receipt").parent != output_dir:
        raise PermissionError("receipt path escapes the output directory")
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise PermissionError("Audit Kit receipt must not be a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise PermissionError("Audit Kit receipt must be a regular file")
    if st.st_size > max_bytes:
        raise ValueError(f"Audit Kit receipt exceeds size limit ({st.st_size} > {max_bytes} bytes)")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as fh:
        fst = os.fstat(fh.fileno())
        if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino) or not stat.S_ISREG(fst.st_mode):
            raise PermissionError("Audit Kit receipt changed between check and open")
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"Audit Kit receipt exceeds size limit (> {max_bytes} bytes)")
    try:
        receipt = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Audit Kit receipt is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(receipt, dict):
        raise ValueError("Audit Kit receipt must be a JSON object")
    return receipt


def run_kit(request: PcbEdaRequest, *, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
            max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
            max_receipt_bytes: int = DEFAULT_MAX_RECEIPT_BYTES) -> tuple[int, dict]:
    request.validate()
    if not timeout_seconds or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if not max_receipt_bytes or max_receipt_bytes <= 0:
        raise ValueError("max_receipt_bytes must be positive")
    kit_root = _canonical_dir(request.kit_root, "kit_root")
    input_dir = _canonical_dir(request.input_dir, "input_dir")
    output_dir = _canonical_dir(request.output_dir, "output_dir")
    if not kit_root.is_dir():
        raise FileNotFoundError(f"kit_root is not a directory: {kit_root}")
    if not input_dir.is_dir():
        raise FileNotFoundError(f"input is not a directory: {input_dir}")
    check_path_isolation(input_dir, output_dir, kit_root)
    if request.config and not Path(request.config).resolve().is_file():
        raise FileNotFoundError(f"config is not a file: {request.config}")
    output_dir.mkdir(parents=True, exist_ok=True)
    # Re-validate after creation: mkdir may have followed a just-planted link.
    output_dir_created = _canonical_dir(request.output_dir, "output_dir")
    if output_dir_created != output_dir:
        raise PermissionError("output directory resolved differently after creation")
    check_path_isolation(input_dir, output_dir, kit_root)
    identity = _dir_identity(output_dir)
    # Never accept a stale receipt from an earlier run as this run's result.
    for stale in RECEIPT_NAMES:
        _remove_stale(output_dir, stale)

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
        raise timeout_error(f"Audit Kit timed out after {timeout_seconds}s", exc) from exc
    except OutputLimitExceeded as exc:
        raise output_limit_error(f"Audit Kit {exc.stream} exceeds output limit", exc) from exc
    _verify_output_identity(request.output_dir, output_dir, identity)
    name = "phase_receipt.json" if request.phase == SCHEMATIC_PHASE else "summary.json"
    if not os.path.lexists(output_dir / name):
        kind = "schematic phase receipt" if request.phase == SCHEMATIC_PHASE else "terminal receipt"
        raise RuntimeError(f"Audit Kit produced no {kind}: " + _tail(proc.stderr))
    receipt = _load_receipt(output_dir, name, max_receipt_bytes)
    if request.phase == SCHEMATIC_PHASE:
        validate_schematic_receipt(receipt)
    else:
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
