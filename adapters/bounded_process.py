"""Bounded subprocess execution shared by AIOS provider adapters.

Unlike ``subprocess.run(capture_output=True)``, output limits are enforced
*while* the child runs: each stream is read in chunks and the whole process
tree is killed as soon as stdout or stderr exceeds its cap, so a runaway
provider cannot exhaust adapter memory. Timeouts also kill the process tree
(POSIX process group / Windows ``taskkill /T``), not just the direct child.

The return value is a ``subprocess.CompletedProcess`` with ``bytes`` streams
and timeouts raise ``subprocess.TimeoutExpired`` so callers keep the familiar
``subprocess.run`` contract.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from typing import Mapping, Sequence

_CHUNK = 64 * 1024


class OutputLimitExceeded(ValueError):
    """A provider stream exceeded its byte cap; the process tree was killed."""

    def __init__(self, stream: str, limit: int, cleanup: dict):
        super().__init__(f"provider {stream} exceeds output limit ({limit} bytes); process tree killed")
        self.stream = stream
        self.limit = limit
        self.cleanup = cleanup


def _popen_kwargs() -> dict:
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    return {"start_new_session": True}


def kill_process_tree(proc: subprocess.Popen, grace_seconds: float = 2.0) -> dict:
    """Kill ``proc`` and its descendants. Returns a cleanup record for evidence."""
    record = {"pid": proc.pid, "method": None, "exited": False, "returncode": None, "error": None}
    try:
        if os.name == "nt":
            record["method"] = "taskkill /T /F"
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=grace_seconds + 5, check=False)
        else:
            record["method"] = "killpg SIGKILL"
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    except Exception as exc:  # cleanup must never mask the primary failure
        record["error"] = f"{type(exc).__name__}: {exc}"
    try:
        proc.kill()
    except OSError:
        pass
    try:
        record["returncode"] = proc.wait(timeout=grace_seconds)
        record["exited"] = True
    except subprocess.TimeoutExpired:
        record["error"] = (record["error"] or "") + " process did not exit after kill"
    return record


def run_bounded(
    command: Sequence[str],
    *,
    input: bytes | None = None,
    timeout: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess:
    if not command or any(not isinstance(part, str) or not part for part in command):
        raise ValueError("command must contain non-empty strings")
    if timeout is None or timeout <= 0:
        raise ValueError("timeout must be positive")
    if max_stdout_bytes <= 0 or max_stderr_bytes <= 0:
        raise ValueError("output limits must be positive")

    proc = subprocess.Popen(
        list(command),
        stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=dict(env) if env is not None else None,
        shell=False,
        **_popen_kwargs(),
    )
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": max_stdout_bytes, "stderr": max_stderr_bytes}
    overflow: list[str] = []
    overflow_event = threading.Event()

    def _reader(name: str, stream) -> None:
        try:
            while True:
                chunk = stream.read1(_CHUNK) if hasattr(stream, "read1") else stream.read(_CHUNK)
                if not chunk:
                    return
                buf = buffers[name]
                room = limits[name] - len(buf)
                if len(chunk) > room:
                    buf.extend(chunk[:max(room, 0)])
                    overflow.append(name)
                    overflow_event.set()
                    return
                buf.extend(chunk)
        except (OSError, ValueError):
            return

    def _writer() -> None:
        try:
            proc.stdin.write(input)
        except (BrokenPipeError, OSError, ValueError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    threads = [threading.Thread(target=_reader, args=(n, getattr(proc, n)), daemon=True)
               for n in ("stdout", "stderr")]
    if input is not None:
        threads.append(threading.Thread(target=_writer, daemon=True))
    for t in threads:
        t.start()

    deadline = time.monotonic() + timeout
    timed_out = False
    while True:
        if overflow_event.is_set():
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        try:
            proc.wait(timeout=min(remaining, 0.05))
            break
        except subprocess.TimeoutExpired:
            continue

    cleanup = None
    if overflow_event.is_set() or timed_out:
        cleanup = kill_process_tree(proc)
    elif os.name != "nt":
        # Direct child exited; reap descendants left in its process group so
        # they cannot keep running or hold the output pipes open.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    for t in threads:
        t.join(timeout=2.0)
    for stream in (proc.stdout, proc.stderr):
        try:
            stream.close()
        except OSError:
            pass

    if overflow:
        name = overflow[0]
        raise OutputLimitExceeded(name, limits[name], cleanup or {})
    if timed_out:
        exc = subprocess.TimeoutExpired(list(command), timeout,
                                        output=bytes(buffers["stdout"]), stderr=bytes(buffers["stderr"]))
        exc.cleanup = cleanup  # type: ignore[attr-defined]
        raise exc
    return subprocess.CompletedProcess(list(command), proc.returncode,
                                       bytes(buffers["stdout"]), bytes(buffers["stderr"]))


__all__ = ["OutputLimitExceeded", "kill_process_tree", "run_bounded"]
