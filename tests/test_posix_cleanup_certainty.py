"""Regression tests for the POSIX cleanup certainty boundary."""

import os
import signal
import subprocess
import sys
import time

import pytest

from adapters.bounded_process import CLEANUP_UNKNOWN, _posix_cleanup, run_bounded


@pytest.mark.skipif(os.name == "nt" or not sys.platform.startswith("linux"),
                    reason="the escaped-orphan regression requires Linux fork and /proc")
def test_posix_cleanup_does_not_confirm_an_escaped_orphan(tmp_path):
    pidfile = tmp_path / "daemon.pid"
    code = r"""
import os, sys, time
pidfile = sys.argv[1]
intermediate = os.fork()
if intermediate == 0:
    os.setsid()
    daemon = os.fork()
    if daemon > 0:
        os._exit(0)
    for fd in (0, 1, 2):
        try: os.close(fd)
        except OSError: pass
    with open(pidfile, "w") as stream:
        stream.write(str(os.getpid()))
    time.sleep(30)
    os._exit(0)
os.waitpid(intermediate, 0)
"""
    proc = subprocess.Popen(
        [sys.executable, "-c", code, str(pidfile)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, start_new_session=True,
    )
    daemon_pid = None
    try:
        proc.wait(timeout=5)
        deadline = time.monotonic() + 5
        while not pidfile.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert pidfile.exists(), "detached daemon did not publish its PID"
        daemon_pid = int(pidfile.read_text())
        record = _posix_cleanup(proc, 0.25)
        assert record["status"] == CLEANUP_UNKNOWN
        assert "escaped_orphan_descendants_unverifiable" in record["verified_scope"]
        os.kill(daemon_pid, 0)
    finally:
        if daemon_pid is not None:
            try:
                os.kill(daemon_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.mark.skipif(os.name == "nt", reason="POSIX cleanup policy")
def test_successful_posix_command_remains_usable_with_unknown_scope():
    result = run_bounded(
        [sys.executable, "-c", "print('ok')"],
        timeout=5, max_stdout_bytes=1024, max_stderr_bytes=1024,
    )
    assert result.stdout.strip() == b"ok"
    assert result.cleanup["status"] == CLEANUP_UNKNOWN
    assert result.cleanup["pipes_closed"] is True
