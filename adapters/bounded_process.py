"""Bounded subprocess execution shared by AIOS provider adapters.

Unlike ``subprocess.run(capture_output=True)``, output limits are enforced
*while* the child runs: each stream is read in chunks and the whole process
tree is killed as soon as stdout or stderr exceeds its cap, so a runaway
provider cannot exhaust adapter memory. Timeouts also kill the process tree,
not just the direct child, and every wait during cleanup is bounded.

Process-tree containment and verification (audit F-05):

* POSIX: the child is started in a new session/process group. Cleanup sends
  SIGKILL to the group and to every descendant found by walking the parent
  chain (Linux ``/proc``), then *verifies* that no live (non-zombie) member of
  the group or the snapshotted descendant set remains. Without ``/proc`` the
  group probe cannot tell zombies from live processes, so success is reported
  as ``CLEANUP_UNKNOWN``. A descendant that both left the process group
  (``setsid``) and was orphaned before cleanup cannot be observed; this is a
  documented limitation of the POSIX strategy.
* Windows: the child is created suspended, assigned to a Job Object with
  ``KILL_ON_JOB_CLOSE`` and only then resumed, so every descendant is born
  inside the job. Cleanup calls ``TerminateJobObject`` and verifies that the
  job's ``ActiveProcesses`` count reaches zero. If containment cannot be
  established the run is refused (fail closed). ``taskkill`` is not used:
  its exit status cannot prove descendants exited.

Cleanup status is one of ``CLEANUP_CONFIRMED``, ``CLEANUP_UNKNOWN`` or
``CLEANUP_FAILED`` and is attached to the raised exception (``.cleanup``) or
to the returned ``CompletedProcess`` (``.cleanup``). The original execution
error (timeout / output overflow) is always the exception raised; cleanup
status never replaces it. A normal exit whose cleanup is not confirmed raises
``ProcessCleanupError`` (fail closed).
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from typing import Mapping, Sequence

_CHUNK = 64 * 1024

CLEANUP_CONFIRMED = "CLEANUP_CONFIRMED"
CLEANUP_UNKNOWN = "CLEANUP_UNKNOWN"
CLEANUP_FAILED = "CLEANUP_FAILED"
CLEANUP_STATUSES = (CLEANUP_CONFIRMED, CLEANUP_UNKNOWN, CLEANUP_FAILED)

DEFAULT_GRACE_SECONDS = 2.0
_READER_JOIN_SECONDS = 2.0


class OutputLimitExceeded(ValueError):
    """A provider stream exceeded its byte cap; the process tree was killed."""

    def __init__(self, stream: str, limit: int, cleanup: dict):
        super().__init__(f"provider {stream} exceeds output limit ({limit} bytes); "
                         f"process tree kill {describe_cleanup(cleanup)}")
        self.stream = stream
        self.limit = limit
        self.cleanup = cleanup


class ProcessCleanupError(RuntimeError):
    """The process exited but descendant cleanup could not be confirmed."""

    def __init__(self, cleanup: dict, result: subprocess.CompletedProcess | None = None):
        super().__init__(f"provider process tree cleanup not confirmed: {describe_cleanup(cleanup)}")
        self.cleanup = cleanup
        self.result = result


def describe_cleanup(cleanup: dict | None) -> str:
    if not cleanup:
        return f"cleanup_status={CLEANUP_UNKNOWN} (no cleanup record)"
    text = f"cleanup_status={cleanup.get('status', CLEANUP_UNKNOWN)}"
    if cleanup.get("survivors"):
        text += f" survivors={cleanup['survivors']}"
    if cleanup.get("error"):
        text += f" error={cleanup['error']}"
    return text


def _new_record(proc: subprocess.Popen, method: str) -> dict:
    return {"pid": proc.pid, "method": method, "status": CLEANUP_UNKNOWN, "direct_child_exited": False,
            "returncode": None, "verified_scope": None, "survivors": [], "error": None}


def _append_error(record: dict, message: str) -> None:
    record["error"] = message if not record["error"] else f"{record['error']}; {message}"


# --- POSIX -----------------------------------------------------------------

def _ps_table() -> dict[int, tuple[str, int, int]] | None:
    """Portable fallback (macOS/BSD): ``ps`` with a bounded timeout."""
    try:
        out = subprocess.run(["ps", "-axo", "pid=,ppid=,pgid=,stat="], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=5, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    table: dict[int, tuple[str, int, int]] = {}
    for line in out.decode("ascii", "replace").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            table[int(parts[0])] = (parts[3][:1], int(parts[1]), int(parts[2]))
        except ValueError:
            continue
    return table or None


def _proc_table() -> dict[int, tuple[str, int, int]] | None:
    """pid -> (state, ppid, pgrp) from Linux /proc (or ``ps``), or None if unavailable."""
    if not os.path.isdir("/proc/self"):
        return _ps_table()
    table: dict[int, tuple[str, int, int]] = {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        return None
    for name in entries:
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat", "rb") as fh:
                data = fh.read().decode("utf-8", "replace")
        except OSError:
            continue  # exited while scanning
        head, sep, rest = data.rpartition(")")
        if not sep:
            continue
        fields = rest.split()
        if len(fields) < 3:
            continue
        try:
            table[int(name)] = (fields[0], int(fields[1]), int(fields[2]))
        except ValueError:
            continue
    return table


def _descendants(table: dict[int, tuple[str, int, int]], root: int) -> set[int]:
    children: dict[int, list[int]] = {}
    for pid, (_state, ppid, _pgrp) in table.items():
        children.setdefault(ppid, []).append(pid)
    found: set[int] = set()
    stack = [root]
    while stack:
        for child in children.get(stack.pop(), []):
            if child not in found:
                found.add(child)
                stack.append(child)
    return found


def _live_members(table, pgid: int, tracked: set[int]) -> list[int]:
    return sorted(pid for pid, (state, _ppid, pgrp) in table.items()
                  if state not in ("Z", "X") and (pgrp == pgid or pid in tracked))


def _posix_cleanup(proc: subprocess.Popen, grace: float) -> dict:
    record = _new_record(proc, "killpg+descendant-scan SIGKILL")
    pgid = proc.pid  # start_new_session=True makes the child its own group leader
    table = _proc_table()
    tracked = _descendants(table, proc.pid) if table is not None else set()
    for target in sorted(tracked):
        try:
            os.kill(target, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            _append_error(record, f"kill({target}): {type(exc).__name__}: {exc}")
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        _append_error(record, f"killpg: {type(exc).__name__}: {exc}")
    try:
        proc.kill()
    except OSError:
        pass
    deadline = time.monotonic() + grace
    try:
        record["returncode"] = proc.wait(timeout=max(grace, 0.01))
        record["direct_child_exited"] = True
    except subprocess.TimeoutExpired:
        _append_error(record, "direct child did not exit after SIGKILL")
    while True:
        table = _proc_table()
        if table is not None:
            survivors = _live_members(table, pgid, tracked)
            record["survivors"] = survivors
            if not survivors and record["direct_child_exited"]:
                # A one-time /proc ancestry snapshot cannot see a daemon that
                # forked, called setsid(), and was reparented before this scan.
                # The process group and observed descendants are gone, but that
                # is not proof that the entire workload is gone.
                record["status"] = CLEANUP_UNKNOWN
                record["verified_scope"] = "process_group+ppid_snapshot; escaped_orphan_descendants_unverifiable"
                return record
        else:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                if record["direct_child_exited"]:
                    # Group fully reaped: confirmed for the group; no /proc means
                    # descendants that left the group cannot be enumerated.
                    record["status"] = CLEANUP_UNKNOWN
                    record["verified_scope"] = "process_group(killpg probe); descendants outside group unverifiable"
                    return record
            except OSError as exc:
                _append_error(record, f"group probe: {type(exc).__name__}: {exc}")
                return record
        if time.monotonic() >= deadline:
            record["status"] = CLEANUP_FAILED if record["survivors"] or not record["direct_child_exited"] \
                else CLEANUP_UNKNOWN
            _append_error(record, "process tree still present after cleanup deadline")
            return record
        try:
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            pass
        time.sleep(0.02)


# --- Windows ---------------------------------------------------------------

class _WindowsJob:
    """Job Object containment (KILL_ON_JOB_CLOSE). Windows only."""

    JobObjectBasicAccountingInformation = 1
    JobObjectExtendedLimitInformation = 9
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        self.ctypes = ctypes
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.ntdll = ctypes.WinDLL("ntdll")

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class BASIC_LIMIT(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class EXTENDED_LIMIT(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BASIC_LIMIT), ("IoInfo", IO_COUNTERS),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        class ACCOUNTING(ctypes.Structure):
            _fields_ = [("TotalUserTime", ctypes.c_int64), ("TotalKernelTime", ctypes.c_int64),
                        ("ThisPeriodTotalUserTime", ctypes.c_int64), ("ThisPeriodTotalKernelTime", ctypes.c_int64),
                        ("TotalPageFaultCount", wintypes.DWORD), ("TotalProcesses", wintypes.DWORD),
                        ("ActiveProcesses", wintypes.DWORD), ("TotalTerminatedProcesses", wintypes.DWORD)]

        self.ACCOUNTING = ACCOUNTING
        self.k32.CreateJobObjectW.restype = wintypes.HANDLE
        self.k32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        self.k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
        self.k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.k32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                                       wintypes.DWORD, wintypes.LPDWORD]
        self.k32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
        self.ntdll.NtResumeProcess.restype = ctypes.c_long

        self.handle = self.k32.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
        info = EXTENDED_LIMIT()
        info.BasicLimitInformation.LimitFlags = self.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.k32.SetInformationJobObject(self.handle, self.JobObjectExtendedLimitInformation,
                                                ctypes.byref(info), ctypes.sizeof(info)):
            err = ctypes.get_last_error()
            self.close()
            raise OSError(err, "SetInformationJobObject failed")

    def assign_and_resume(self, proc: subprocess.Popen) -> None:
        handle = int(proc._handle)  # type: ignore[attr-defined]
        if not self.k32.AssignProcessToJobObject(self.handle, handle):
            raise OSError(self.ctypes.get_last_error(), "AssignProcessToJobObject failed")
        status = self.ntdll.NtResumeProcess(handle)
        if status != 0:
            raise OSError(status, "NtResumeProcess failed")

    def active_processes(self) -> int:
        info = self.ACCOUNTING()
        if not self.k32.QueryInformationJobObject(self.handle, self.JobObjectBasicAccountingInformation,
                                                  self.ctypes.byref(info), self.ctypes.sizeof(info), None):
            raise OSError(self.ctypes.get_last_error(), "QueryInformationJobObject failed")
        return int(info.ActiveProcesses)

    def terminate(self) -> None:
        if not self.k32.TerminateJobObject(self.handle, 1):
            raise OSError(self.ctypes.get_last_error(), "TerminateJobObject failed")

    def close(self) -> None:
        if self.handle:
            self.k32.CloseHandle(self.handle)
            self.handle = None


def _windows_cleanup(proc: subprocess.Popen, job: _WindowsJob, grace: float) -> dict:
    record = _new_record(proc, "TerminateJobObject+ActiveProcesses")
    try:
        job.terminate()
    except OSError as exc:
        _append_error(record, f"{type(exc).__name__}: {exc}")
    try:
        record["returncode"] = proc.wait(timeout=max(grace, 0.01))
        record["direct_child_exited"] = True
    except subprocess.TimeoutExpired:
        _append_error(record, "direct child did not exit after job termination")
    deadline = time.monotonic() + grace
    while True:
        try:
            active = job.active_processes()
        except OSError as exc:
            _append_error(record, f"{type(exc).__name__}: {exc}")
            return record
        if active == 0 and record["direct_child_exited"]:
            record["status"] = CLEANUP_CONFIRMED
            record["verified_scope"] = "job_object(ActiveProcesses==0)"
            return record
        if time.monotonic() >= deadline:
            record["status"] = CLEANUP_FAILED
            record["survivors"] = [f"job_active_processes={active}"]
            _append_error(record, "job still has active processes after cleanup deadline")
            return record
        time.sleep(0.02)


# --- Public API ------------------------------------------------------------

def _popen_kwargs() -> dict:
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | 0x00000004  # CREATE_SUSPENDED
        return {"creationflags": flags}
    return {"start_new_session": True}


def kill_process_tree(proc: subprocess.Popen, grace_seconds: float = DEFAULT_GRACE_SECONDS,
                      job: _WindowsJob | None = None) -> dict:
    """Kill ``proc`` and its descendants and verify. Never raises; returns a cleanup record."""
    try:
        if os.name == "nt":
            if job is None:
                record = _new_record(proc, "unavailable")
                record["error"] = "no job object: descendant termination cannot be verified"
                try:
                    proc.kill()
                    record["returncode"] = proc.wait(timeout=grace_seconds)
                    record["direct_child_exited"] = True
                except (OSError, subprocess.TimeoutExpired) as exc:
                    _append_error(record, f"{type(exc).__name__}: {exc}")
                return record
            return _windows_cleanup(proc, job, grace_seconds)
        return _posix_cleanup(proc, grace_seconds)
    except Exception as exc:  # cleanup must never mask the primary failure
        record = _new_record(proc, "error")
        record["status"] = CLEANUP_UNKNOWN
        record["error"] = f"{type(exc).__name__}: {exc}"
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
    cleanup_grace_seconds: float = DEFAULT_GRACE_SECONDS,
) -> subprocess.CompletedProcess:
    if not command or any(not isinstance(part, str) or not part for part in command):
        raise ValueError("command must contain non-empty strings")
    if timeout is None or timeout <= 0:
        raise ValueError("timeout must be positive")
    if max_stdout_bytes <= 0 or max_stderr_bytes <= 0:
        raise ValueError("output limits must be positive")
    if not cleanup_grace_seconds or cleanup_grace_seconds <= 0:
        raise ValueError("cleanup_grace_seconds must be positive")

    job = _WindowsJob() if os.name == "nt" else None
    try:
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
    except BaseException:
        if job is not None:
            job.close()
        raise
    if job is not None:
        try:
            job.assign_and_resume(proc)
        except OSError as exc:
            # Fail closed: without containment, descendants cannot be verified.
            try:
                proc.kill()
                proc.wait(timeout=cleanup_grace_seconds)
            except (OSError, subprocess.TimeoutExpired):
                pass
            job.close()
            raise ProcessCleanupError({"pid": proc.pid, "status": CLEANUP_UNKNOWN,
                                       "error": f"process containment failed: {exc}"}) from exc

    try:
        return _supervise(proc, job, command, input, timeout, max_stdout_bytes, max_stderr_bytes,
                          cleanup_grace_seconds)
    finally:
        if job is not None:
            job.close()  # KILL_ON_JOB_CLOSE: last-resort kill of anything left in the job


def _supervise(proc, job, command, input, timeout, max_stdout_bytes, max_stderr_bytes, grace):
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

    readers = [threading.Thread(target=_reader, args=(n, getattr(proc, n)), daemon=True)
               for n in ("stdout", "stderr")]
    threads = list(readers)
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

    # Always clean up the whole tree, also after a normal exit: descendants
    # must not keep running or hold the output pipes open.
    cleanup = kill_process_tree(proc, grace, job)
    join_deadline = time.monotonic() + _READER_JOIN_SECONDS
    for t in threads:
        t.join(timeout=max(join_deadline - time.monotonic(), 0.0))
    held = [name for name, t in zip(("stdout", "stderr"), readers) if t.is_alive()]
    if held:
        # Some process outside the verified scope still holds an output pipe.
        cleanup["status"] = CLEANUP_FAILED if cleanup["status"] != CLEANUP_UNKNOWN else CLEANUP_UNKNOWN
        _append_error(cleanup, "output pipe still held open after cleanup")
    cleanup["pipes_closed"] = not held
    for name in ("stdout", "stderr"):
        if name in held:
            # close() would block on the reader's buffer lock until the foreign
            # holder releases the pipe (unbounded); leave it to the daemon reader.
            continue
        try:
            getattr(proc, name).close()
        except OSError:
            pass

    if overflow:
        name = overflow[0]
        raise OutputLimitExceeded(name, limits[name], cleanup)
    if timed_out:
        exc = subprocess.TimeoutExpired(list(command), timeout,
                                        output=bytes(buffers["stdout"]), stderr=bytes(buffers["stderr"]))
        exc.cleanup = cleanup  # type: ignore[attr-defined]
        raise exc
    result = subprocess.CompletedProcess(list(command), proc.returncode,
                                         bytes(buffers["stdout"]), bytes(buffers["stderr"]))
    result.cleanup = cleanup  # type: ignore[attr-defined]
    # On POSIX, a clean direct-child exit plus closed pipes and an empty
    # process-group/observed-descendant scope is enough to return the provider
    # result, but must remain explicitly UNKNOWN: escaped, reparented daemons
    # cannot be ruled out without OS-level containment. Failed cleanup or a
    # still-open pipe remains fail-closed. Windows Job Objects can still prove
    # full containment and report CLEANUP_CONFIRMED.
    posix_scope_only = (
        os.name != "nt"
        and cleanup["status"] == CLEANUP_UNKNOWN
        and isinstance(cleanup.get("verified_scope"), str)
        and cleanup["verified_scope"].startswith("process_group")
        and cleanup.get("pipes_closed") is True
        and cleanup.get("direct_child_exited") is True
    )
    if cleanup["status"] != CLEANUP_CONFIRMED and not posix_scope_only:
        raise ProcessCleanupError(cleanup, result)
    return result


def timeout_error(message: str, exc: BaseException) -> TimeoutError:
    """Adapter-facing TimeoutError that keeps the cleanup record and status."""
    cleanup = getattr(exc, "cleanup", None)
    err = TimeoutError(f"{message}; process tree kill {describe_cleanup(cleanup)}")
    err.cleanup = cleanup  # type: ignore[attr-defined]
    return err


def output_limit_error(message: str, exc: BaseException) -> ValueError:
    """Adapter-facing ValueError that keeps the cleanup record and status."""
    cleanup = getattr(exc, "cleanup", None)
    err = ValueError(f"{message}; process tree kill {describe_cleanup(cleanup)}")
    err.cleanup = cleanup  # type: ignore[attr-defined]
    return err


__all__ = ["OutputLimitExceeded", "timeout_error", "output_limit_error", "ProcessCleanupError", "kill_process_tree", "run_bounded",
           "describe_cleanup", "CLEANUP_CONFIRMED", "CLEANUP_UNKNOWN", "CLEANUP_FAILED", "CLEANUP_STATUSES"]
