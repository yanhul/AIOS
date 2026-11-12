# AIOS-CONTRACT: bounded subprocesses verify process-tree cleanup (CONFIRMED/UNKNOWN/FAILED) within a
#                bounded time and fail closed; the PCB adapter isolates output from input/kit and only
#                accepts a fresh, regular, bounded, schema-valid receipt from inside its output dir.
# AIOS-REGRESSION: Audit F-05 (unchecked tree kill, descendants holding pipes, lost cleanup evidence) and
#                  F-06 (incomplete path-overlap checks, symlink/stale/oversized receipts).
# AIOS-OWNER: AIOS provider adapters
# AIOS-COVERAGE-GAP: Process-tree verification, pipe-holding descendants, path aliasing, receipt forgery.
# AIOS-BASELINE: Extends tests/test_audit_p1_p2_hardening.py.

import json
import os
import signal
import subprocess
import sys
import time

import pytest

from adapters import bounded_process as bp
from adapters.bounded_process import OutputLimitExceeded, ProcessCleanupError, run_bounded
from adapters.pcb_eda.adapter import run_kit
from adapters.process import SubprocessAdapter
from core.pcb_eda import PcbEdaRequest
from core.runtime import execute
from tests.test_m6_runtime import setup_authority

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX process-group semantics")
LIMITS = dict(max_stdout_bytes=1024, max_stderr_bytes=1024)


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    table = bp._proc_table()
    return table is None or (pid in table and table[pid][0] not in ("Z", "X"))


def _wait_dead(pid, seconds=3.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return False


def _spawn_tree(pidfile, extra="", child_body="import time; time.sleep(60)"):
    return ("import subprocess,sys,time\n"
            f"p=subprocess.Popen([sys.executable,'-c',{child_body!r}]{extra})\n"
            f"open({str(pidfile)!r},'w').write(str(p.pid))\n")


# --- F-05: output limits ---------------------------------------------------

@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_f05_overflow_kills_tree_and_retains_cleanup(stream):
    start = time.monotonic()
    with pytest.raises(OutputLimitExceeded) as info:
        run_bounded([sys.executable, "-c", f"import sys\nwhile True: sys.{stream}.write('x'*65536)"],
                    timeout=30, **LIMITS)
    assert info.value.stream == stream
    assert info.value.cleanup["status"] in bp.CLEANUP_STATUSES
    assert "cleanup_status=" in str(info.value)
    assert time.monotonic() - start < 10


@posix_only
def test_f05_overflow_from_grandchild_kills_grandchild(tmp_path):
    pidfile = tmp_path / "gc.pid"
    script = _spawn_tree(pidfile, child_body="import sys\nwhile True: sys.stdout.write('y'*65536)") + "time.sleep(60)\n"
    with pytest.raises(OutputLimitExceeded) as info:
        run_bounded([sys.executable, "-c", script], timeout=30, **LIMITS)
    assert info.value.cleanup["status"] == bp.CLEANUP_CONFIRMED
    assert _wait_dead(int(pidfile.read_text()))


# --- F-05: timeout / child / grandchild -------------------------------------

@posix_only
def test_f05_timeout_kills_child_and_grandchild(tmp_path):
    pidfile = tmp_path / "gc.pid"
    script = _spawn_tree(pidfile, child_body=(
        "import subprocess,sys,time\n"
        "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
        "time.sleep(60)")) + "time.sleep(60)\n"
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired) as info:
        run_bounded([sys.executable, "-c", script + "\n"], timeout=4, **LIMITS)
    cleanup = info.value.cleanup
    assert cleanup["status"] == bp.CLEANUP_CONFIRMED and cleanup["direct_child_exited"], cleanup
    assert cleanup["survivors"] == [] and cleanup["pipes_closed"] is True
    assert _wait_dead(int(pidfile.read_text()))
    assert time.monotonic() - start < 10


@posix_only
def test_f05_descendant_holding_stdout_after_normal_exit_is_reaped(tmp_path):
    pidfile = tmp_path / "gc.pid"
    script = _spawn_tree(pidfile) + "print('done', flush=True)\n"  # parent exits; grandchild keeps stdout
    start = time.monotonic()
    result = run_bounded([sys.executable, "-c", script], timeout=30, **LIMITS)
    assert result.returncode == 0 and b"done" in result.stdout
    assert result.cleanup["status"] == bp.CLEANUP_CONFIRMED and result.cleanup["pipes_closed"]
    assert _wait_dead(int(pidfile.read_text()))
    assert time.monotonic() - start < 10


@posix_only
def test_f05_escaped_descendant_holding_pipe_fails_closed_without_hanging(tmp_path):
    pidfile = tmp_path / "gc.pid"
    script = _spawn_tree(pidfile, extra=",start_new_session=True") + "print('done', flush=True)\n"
    start = time.monotonic()
    try:
        with pytest.raises(ProcessCleanupError) as info:
            run_bounded([sys.executable, "-c", script], timeout=30, **LIMITS)
        assert info.value.cleanup["status"] in (bp.CLEANUP_FAILED, bp.CLEANUP_UNKNOWN)
        assert info.value.cleanup["pipes_closed"] is False
        assert info.value.result.returncode == 0  # original outcome kept alongside cleanup failure
        assert time.monotonic() - start < 15
    finally:
        try:
            os.kill(int(pidfile.read_text()), signal.SIGKILL)
        except (OSError, ValueError):
            pass


# --- F-05: cleanup failure / unknown are never reported as confirmed -------

@posix_only
def test_f05_cleanup_failure_is_reported_and_original_error_preserved(monkeypatch):
    real = bp._proc_table
    monkeypatch.setattr(bp, "_proc_table", lambda: {**(real() or {}), 999999: ("S", 1, -1)})
    monkeypatch.setattr(bp, "_live_members", lambda table, pgid, tracked: [999999])
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired) as info:
        run_bounded([sys.executable, "-c", "import time; time.sleep(60)"], timeout=0.5,
                    cleanup_grace_seconds=0.5, **LIMITS)
    assert info.value.cleanup["status"] == bp.CLEANUP_FAILED
    assert info.value.cleanup["survivors"] == [999999]
    assert time.monotonic() - start < 6


@posix_only
def test_f05_unverifiable_cleanup_is_unknown_and_fails_closed(monkeypatch):
    monkeypatch.setattr(bp, "_proc_table", lambda: None)
    with pytest.raises(ProcessCleanupError) as info:
        run_bounded([sys.executable, "-c", "print('ok')"], timeout=10, **LIMITS)
    assert info.value.cleanup["status"] == bp.CLEANUP_UNKNOWN


def test_f05_cleanup_exception_never_masks_and_is_unknown(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("cleanup exploded")
    monkeypatch.setattr(bp, "_posix_cleanup", boom)
    monkeypatch.setattr(bp, "_windows_cleanup", boom)
    with pytest.raises(subprocess.TimeoutExpired) as info:
        run_bounded([sys.executable, "-c", "import time; time.sleep(3)"], timeout=0.3, **LIMITS)
    assert info.value.cleanup["status"] == bp.CLEANUP_UNKNOWN
    assert "cleanup exploded" in info.value.cleanup["error"]


def test_f05_cleanup_status_durably_retained_in_effect(tmp_path):
    _c, cid, pid = setup_authority(tmp_path)
    adapter = SubprocessAdapter(name="fake-provider", command=[sys.executable, "-c", "import time; time.sleep(30)"],
                                timeout_seconds=0.5)
    result = execute(str(tmp_path), cid, pid, "op-timeout", "agent:test", adapter)
    assert result["state"] == "UNKNOWN"
    assert "cleanup_status=CLEANUP_" in result["unknown_reason"]
    with open(os.path.join(str(tmp_path), "effects", result["effect_id"] + ".json"), encoding="utf-8") as fh:
        assert "cleanup_status=CLEANUP_" in json.load(fh)["unknown_reason"]


# --- F-05: Windows (runs only on Windows CI) --------------------------------

@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
def test_f05_windows_job_object_kills_and_verifies_grandchild(tmp_path):
    pidfile = tmp_path / "gc.pid"
    script = _spawn_tree(pidfile) + "time.sleep(60)\n"
    with pytest.raises(subprocess.TimeoutExpired) as info:
        run_bounded([sys.executable, "-c", script], timeout=3, **LIMITS)
    assert info.value.cleanup["status"] == bp.CLEANUP_CONFIRMED
    assert info.value.cleanup["verified_scope"].startswith("job_object")
    gc = int(pidfile.read_text())
    out = subprocess.run(["tasklist", "/FI", f"PID eq {gc}", "/NH"], capture_output=True, text=True, timeout=30)
    assert str(gc) not in out.stdout


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
def test_f05_windows_normal_exit_reaps_pipe_holding_descendant(tmp_path):
    pidfile = tmp_path / "gc.pid"
    script = _spawn_tree(pidfile) + "print('done', flush=True)\n"
    start = time.monotonic()
    result = run_bounded([sys.executable, "-c", script], timeout=30, **LIMITS)
    assert result.cleanup["status"] == bp.CLEANUP_CONFIRMED and b"done" in result.stdout
    assert time.monotonic() - start < 20


# --- F-06: path isolation ---------------------------------------------------

def _kit(tmp_path, body="pass\n", *, inp=None, out=None, kit=None, phase="PCB"):
    kit = kit or (tmp_path / "kit")
    (kit / "tools/altium-audit").mkdir(parents=True, exist_ok=True)
    (kit / "tools/altium-audit/audit_kit.py").write_text(body, encoding="utf-8")
    inp = inp or (tmp_path / "in")
    inp.mkdir(parents=True, exist_ok=True)
    out = out if out is not None else tmp_path / "out"
    return PcbEdaRequest(task_id="t", input_dir=str(inp), output_dir=str(out), kit_root=str(kit),
                         config=None, repair=False, max_retries=0, phase=phase)


@pytest.mark.parametrize("relation", ["out=in", "out<in", "in<out", "out=kit", "out<kit", "kit<out"])
def test_f06_output_overlap_rejected(tmp_path, relation):
    base = tmp_path / "w"
    inp, kit = base / "in", base / "kit"
    out = {"out=in": inp, "out<in": inp / "o", "in<out": base, "out=kit": kit,
           "out<kit": kit / "o", "kit<out": base}[relation]
    if relation == "in<out":
        kit = tmp_path / "kit2"
    if relation == "kit<out":
        inp = tmp_path / "in2"
    req = _kit(tmp_path, inp=inp, kit=kit, out=out)
    marker = (inp / "keep.txt")
    marker.write_text("user data", encoding="utf-8")
    with pytest.raises(PermissionError, match="overlap"):
        run_kit(req)
    assert marker.read_text(encoding="utf-8") == "user data"


def test_f06_dotdot_traversal_into_input_rejected(tmp_path):
    req = _kit(tmp_path, out=tmp_path / "out" / ".." / "in" / "sub")
    with pytest.raises(PermissionError, match="overlap"):
        run_kit(req)


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="symlink support")
def test_f06_symlinked_output_into_input_or_kit_rejected(tmp_path):
    req = _kit(tmp_path)
    for target in (req.input_dir, req.kit_root):
        link = tmp_path / ("link-" + os.path.basename(target))
        link.symlink_to(target, target_is_directory=True)
        bad = PcbEdaRequest(task_id="t", input_dir=req.input_dir, output_dir=str(link / "o"),
                            kit_root=req.kit_root, config=None, repair=False, max_retries=0, phase="PCB")
        with pytest.raises(PermissionError, match="overlap"):
            run_kit(bad)


_GOOD = {"schema": "altium-audit-kit-result.v4", "status": "BLOCKED", "terminal_reason": "r"}


def _writer(payload_expr):
    return ("import argparse,json,os\n"
            "ap=argparse.ArgumentParser();ap.add_argument('--input');ap.add_argument('--output')\n"
            "ap.add_argument('--max-retries');a,_=ap.parse_known_args()\n"
            f"{payload_expr}\n")


def test_f06_valid_fresh_receipt_accepted(tmp_path):
    req = _kit(tmp_path, _writer(f"open(os.path.join(a.output,'summary.json'),'w').write({json.dumps(json.dumps(_GOOD))})"))
    rc, receipt = run_kit(req, timeout_seconds=30)
    assert receipt == _GOOD


def test_f06_stale_receipt_never_accepted(tmp_path):
    req = _kit(tmp_path, "pass\n")
    os.makedirs(req.output_dir)
    with open(os.path.join(req.output_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(_GOOD, fh)
    with pytest.raises(RuntimeError, match="no terminal receipt"):
        run_kit(req, timeout_seconds=30)


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="symlink support")
def test_f06_stale_symlink_receipt_removed_without_touching_target(tmp_path):
    req = _kit(tmp_path, "pass\n")
    secret = tmp_path / "in" / "user.json"
    secret.write_text(json.dumps(_GOOD), encoding="utf-8")
    os.makedirs(req.output_dir)
    os.symlink(secret, os.path.join(req.output_dir, "summary.json"))
    with pytest.raises(RuntimeError, match="no terminal receipt"):
        run_kit(req, timeout_seconds=30)
    assert secret.read_text(encoding="utf-8") == json.dumps(_GOOD)


def test_f06_oversized_receipt_rejected(tmp_path):
    req = _kit(tmp_path, _writer("open(os.path.join(a.output,'summary.json'),'w').write(' '*5000)"))
    with pytest.raises(ValueError, match="size limit"):
        run_kit(req, timeout_seconds=30, max_receipt_bytes=1024)


@pytest.mark.parametrize("content", ["{not json", "[1,2]", "\"str\"", json.dumps({"status": "PASS"})])
def test_f06_malformed_or_schema_invalid_receipt_rejected(tmp_path, content):
    req = _kit(tmp_path, _writer(f"open(os.path.join(a.output,'summary.json'),'w').write({content!r})"))
    with pytest.raises(ValueError):
        run_kit(req, timeout_seconds=30)


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="symlink support")
def test_f06_receipt_symlink_written_by_kit_rejected(tmp_path):
    outside = tmp_path / "forged.json"
    outside.write_text(json.dumps(_GOOD), encoding="utf-8")
    req = _kit(tmp_path, _writer(f"os.symlink({str(outside)!r}, os.path.join(a.output,'summary.json'))"))
    with pytest.raises(PermissionError, match="symlink|escapes"):
        run_kit(req, timeout_seconds=30)


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="symlink support")
def test_f06_output_dir_swapped_during_execution_rejected(tmp_path):
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    (decoy / "summary.json").write_text(json.dumps(_GOOD), encoding="utf-8")
    req = _kit(tmp_path, _writer(
        "import shutil\n"
        "shutil.rmtree(a.output)\n"
        f"os.symlink({str(decoy)!r}, a.output, target_is_directory=True)"))
    with pytest.raises(PermissionError, match="replaced or redirected"):
        run_kit(req, timeout_seconds=30)


@pytest.mark.skipif(__import__("adapters.pcb_eda.adapter", fromlist=["x"])._DIRFD_SUPPORTED,
                    reason="runs where dir_fd isolation is natively unavailable (e.g. Windows)")
def test_f06_native_platform_without_dirfd_fails_closed(tmp_path):
    req = _kit(tmp_path, "pass\n")
    with pytest.raises(PermissionError, match="fail closed"):
        run_kit(req, timeout_seconds=30)
    assert not os.path.exists(req.output_dir)
