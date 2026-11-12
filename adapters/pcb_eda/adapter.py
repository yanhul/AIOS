#!/usr/bin/env python3
"""Thin AIOS adapter for the reusable Altium Audit Kit."""
from __future__ import annotations

import argparse
import errno
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


# --- Output directory capability (audit F-06) ---------------------------------
#
# The output directory is opened ONCE as a directory file descriptor right
# after validation. Stale-receipt removal and receipt loading are performed
# relative to that descriptor (``dir_fd``) with O_NOFOLLOW, and the opened
# receipt is verified with ``fstat``. A pathname is never re-resolved to *read*
# anything after this boundary; path checks after execution only detect a
# replaced/redirected directory and fail closed. Platforms without dir_fd,
# O_DIRECTORY and O_NOFOLLOW are refused (fail closed).

_DIRFD_SUPPORTED = bool(
    hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW")
    and os.open in os.supports_dir_fd and os.unlink in os.supports_dir_fd
    and os.stat in os.supports_dir_fd and os.stat in os.supports_follow_symlinks
)


def _require_dirfd_support() -> None:
    if not _DIRFD_SUPPORTED:
        raise PermissionError("platform cannot provide directory-fd receipt isolation "
                              "(dir_fd + O_DIRECTORY + O_NOFOLLOW); refusing to run (fail closed)")


def _lstat_identity(path: Path) -> tuple[int, int]:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise PermissionError(f"output directory must be a real directory, not a symlink: {path}")
    return st.st_dev, st.st_ino


def _fd_location(fd: int) -> Path | None:
    """Kernel-reported location of an open directory (Linux), else None."""
    link = f"/proc/self/fd/{fd}"
    if not os.path.islink(link):
        return None
    try:
        return Path(os.readlink(link))
    except OSError:
        return None


def _open_output_dir(raw: str, output_dir: Path, input_dir: Path, kit_root: Path) -> tuple[int, tuple[int, int]]:
    """Open and bind the validated output directory; returns (dir_fd, (dev, ino))."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(output_dir, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise PermissionError("output directory descriptor is not a directory")
        identity = (st.st_dev, st.st_ino)
        if _canonical_dir(raw, "output_dir") != output_dir or _lstat_identity(output_dir) != identity:
            raise PermissionError("output directory changed while it was being opened")
        located = _fd_location(fd)
        if located is not None:
            if located != output_dir:
                raise PermissionError(f"opened output directory is not the validated path: {located}")
            check_path_isolation(input_dir, located, kit_root)
    except BaseException:
        os.close(fd)
        raise
    return fd, identity


def _assert_output_identity(raw: str, output_dir: Path, dir_fd: int, identity: tuple[int, int]) -> None:
    """Detection only: the authorized directory must still be the one at the validated path."""
    st = os.fstat(dir_fd)
    if (st.st_dev, st.st_ino) != identity or st.st_nlink == 0:
        raise PermissionError("output directory was replaced or redirected during execution")
    try:
        same_path = (_canonical_dir(raw, "output_dir") == output_dir
                     and _lstat_identity(output_dir) == identity)
    except OSError:
        same_path = False
    if not same_path:
        raise PermissionError("output directory was replaced or redirected during execution")


def _remove_stale(dir_fd: int, name: str) -> None:
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(st.st_mode):
        raise PermissionError(f"stale receipt path is a directory: {name}")
    os.unlink(name, dir_fd=dir_fd)  # removes a symlink itself, never its target


def _read_receipt_at(dir_fd: int, name: str, max_bytes: int) -> dict:
    """Open ``name`` relative to the authorized directory fd only; never by path."""
    if os.sep in name or (os.altsep and os.altsep in name) or name in ("", ".", ".."):
        raise PermissionError("receipt name must be a single path component")
    flags = (os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0))
    try:
        fd = os.open(name, flags, dir_fd=dir_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:  # ELOOP: final component is a symlink
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise PermissionError("Audit Kit receipt must not be a symlink") from exc
        raise PermissionError(f"Audit Kit receipt cannot be opened safely: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError("Audit Kit receipt must be a regular file")
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "rb") as fh:
        if st.st_size > max_bytes:
            raise ValueError(f"Audit Kit receipt exceeds size limit ({st.st_size} > {max_bytes} bytes)")
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
    _require_dirfd_support()
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
    dir_fd, identity = _open_output_dir(request.output_dir, output_dir, input_dir, kit_root)
    try:
        return _run_bound(request, dir_fd, identity, kit_root, input_dir, output_dir,
                          timeout_seconds, max_output_bytes, max_receipt_bytes)
    finally:
        os.close(dir_fd)


def _run_bound(request, dir_fd, identity, kit_root, input_dir, output_dir,
               timeout_seconds, max_output_bytes, max_receipt_bytes):
    # Never accept a stale receipt from an earlier run as this run's result.
    for stale in RECEIPT_NAMES:
        _remove_stale(dir_fd, stale)

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
    _assert_output_identity(request.output_dir, output_dir, dir_fd, identity)
    name = "phase_receipt.json" if request.phase == SCHEMATIC_PHASE else "summary.json"
    try:
        receipt = _read_receipt_at(dir_fd, name, max_receipt_bytes)
    except FileNotFoundError:
        kind = "schematic phase receipt" if request.phase == SCHEMATIC_PHASE else "terminal receipt"
        raise RuntimeError(f"Audit Kit produced no {kind}: " + _tail(proc.stderr)) from None
    # The receipt was read from the authorized directory itself; still fail
    # closed if that directory was swapped out meanwhile.
    _assert_output_identity(request.output_dir, output_dir, dir_fd, identity)
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
