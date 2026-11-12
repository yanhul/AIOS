# AIOS-CONTRACT: the PCB adapter reads its receipt only through the directory fd it bound to the
#                validated output directory (O_NOFOLLOW, fstat), and fails closed when the output
#                directory is replaced or redirected at any point, or when dir_fd is unsupported.
# AIOS-REGRESSION: Audit F-06 follow-up — output directory replaced by another REAL directory
#                  between identity verification and receipt open.
# AIOS-OWNER: AIOS provider adapters
# AIOS-COVERAGE-GAP: Directory swap races (before run, after run, before open, concurrent), receipt swaps.
# AIOS-BASELINE: Extends tests/test_audit_f05_f06_closure.py.

import itertools
import json
import os
import threading

import pytest

from adapters.pcb_eda import adapter as pcb
from adapters.pcb_eda.adapter import run_kit
from tests.test_audit_f05_f06_closure import _GOOD as GENUINE, _kit, _writer

pytestmark = pytest.mark.skipif(not pcb._DIRFD_SUPPORTED, reason="dir_fd isolation unsupported (fails closed)")

FORGED = {"schema": "altium-audit-kit-result.v4", "status": "PASS", "terminal_reason": "forged",
          "gates": {"G3_CONNECTIVITY": "VERIFIED", "G6_PLACEMENT": "VERIFIED", "G7_ROUTING": "VERIFIED"}}
_seq = itertools.count()


def _write_genuine():
    return _writer(f"open(os.path.join(a.output,'summary.json'),'w').write({json.dumps(json.dumps(GENUINE))})")


def _swap_with_forged(out):
    """Replace ``out`` with a DIFFERENT real directory holding a schema-valid forged receipt."""
    os.rename(out, f"{out}.orig-{next(_seq)}")
    os.mkdir(out)
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(FORGED, fh)


def _never_forged(fn):
    try:
        _rc, receipt = fn()
    except (PermissionError, RuntimeError, ValueError, OSError) as exc:
        return exc
    assert receipt != FORGED, "forged receipt accepted"
    return receipt


def test_forged_receipt_in_replacement_real_directory_rejected(tmp_path):
    req = _kit(tmp_path, _writer(
        "os.rename(a.output, a.output + '.moved')\n"
        "os.mkdir(a.output)\n"
        f"open(os.path.join(a.output,'summary.json'),'w').write({json.dumps(json.dumps(FORGED))})"))
    with pytest.raises(PermissionError, match="replaced or redirected"):
        run_kit(req, timeout_seconds=30)


def test_replacement_immediately_before_receipt_open_rejected(tmp_path, monkeypatch):
    req = _kit(tmp_path, _write_genuine())
    real = pcb._assert_output_identity
    calls = []

    def assert_then_swap(raw, output_dir, dir_fd, identity):
        real(raw, output_dir, dir_fd, identity)
        if not calls:
            _swap_with_forged(req.output_dir)
        calls.append(1)

    monkeypatch.setattr(pcb, "_assert_output_identity", assert_then_swap)
    with pytest.raises(PermissionError, match="replaced or redirected"):
        run_kit(req, timeout_seconds=30)


def test_receipt_is_read_through_dir_fd_not_by_path(tmp_path, monkeypatch):
    """Even with the post-read detection disabled, the swapped-in forged file is never read."""
    req = _kit(tmp_path, _write_genuine())
    real = pcb._assert_output_identity
    calls = []

    def first_check_then_swap(raw, output_dir, dir_fd, identity):
        if not calls:
            real(raw, output_dir, dir_fd, identity)
            _swap_with_forged(req.output_dir)
        calls.append(1)

    monkeypatch.setattr(pcb, "_assert_output_identity", first_check_then_swap)
    _rc, receipt = run_kit(req, timeout_seconds=30)
    assert receipt == GENUINE and receipt != FORGED


def test_replacement_immediately_after_initial_identity_verification_rejected(tmp_path, monkeypatch):
    req = _kit(tmp_path, _write_genuine())
    real_open = pcb._open_output_dir

    def open_then_swap(*args):
        bound = real_open(*args)
        _swap_with_forged(args[0])  # args[0] is the request's raw output path
        return bound

    monkeypatch.setattr(pcb, "_open_output_dir", open_then_swap)
    with pytest.raises(PermissionError, match="replaced or redirected"):
        run_kit(req, timeout_seconds=30)
    # Without detection the bound (original) directory has no receipt -> still not the forged one.
    monkeypatch.setattr(pcb, "_assert_output_identity", lambda *a: None)
    req2 = _kit(tmp_path / "b", _write_genuine())
    with pytest.raises(RuntimeError, match="no terminal receipt"):
        run_kit(req2, timeout_seconds=30)


def test_output_replaced_by_symlink_into_input_after_validation_rejected(tmp_path, monkeypatch):
    req = _kit(tmp_path, _write_genuine())
    marker = os.path.join(req.input_dir, "summary.json")
    with open(marker, "w", encoding="utf-8") as fh:
        json.dump(FORGED, fh)
    real_check = pcb.check_path_isolation
    calls = []

    def check_then_redirect(input_dir, output_dir, kit_root):
        real_check(input_dir, output_dir, kit_root)
        calls.append(1)
        if len(calls) == 2:  # after mkdir re-validation, before the directory is opened
            os.rmdir(req.output_dir)
            os.symlink(req.input_dir, req.output_dir, target_is_directory=True)

    monkeypatch.setattr(pcb, "check_path_isolation", check_then_redirect)
    with pytest.raises(OSError):
        run_kit(req, timeout_seconds=30)
    with open(marker, encoding="utf-8") as fh:
        assert json.load(fh) == FORGED  # input untouched, nothing deleted


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory", "symlink_inside_output"])
def test_receipt_file_replacement_before_open_rejected(tmp_path, monkeypatch, kind):
    req = _kit(tmp_path, _write_genuine())
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(FORGED), encoding="utf-8")
    real = pcb._assert_output_identity
    calls = []

    def assert_then_replace(raw, output_dir, dir_fd, identity):
        real(raw, output_dir, dir_fd, identity)
        if not calls:
            target = os.path.join(req.output_dir, "summary.json")
            os.unlink(target)
            if kind == "symlink":
                os.symlink(forged, target)
            elif kind == "fifo":
                os.mkfifo(target)
            elif kind == "directory":
                os.mkdir(target)
            else:
                inner = os.path.join(req.output_dir, "inner.json")
                with open(inner, "w", encoding="utf-8") as fh:
                    json.dump(FORGED, fh)
                os.symlink("inner.json", target)
        calls.append(1)

    monkeypatch.setattr(pcb, "_assert_output_identity", assert_then_replace)
    with pytest.raises(PermissionError, match="symlink|regular file"):
        run_kit(req, timeout_seconds=30)


def test_stale_symlink_receipt_removed_relative_to_dir_fd(tmp_path):
    req = _kit(tmp_path, "pass\n")
    os.makedirs(req.output_dir)
    victim = tmp_path / "in" / "victim.json"
    victim.write_text("keep", encoding="utf-8")
    os.symlink(victim, os.path.join(req.output_dir, "summary.json"))
    with pytest.raises(RuntimeError, match="no terminal receipt"):
        run_kit(req, timeout_seconds=30)
    assert victim.read_text(encoding="utf-8") == "keep"


def test_concurrent_directory_replacement_never_accepts_forged_receipt(tmp_path):
    outcomes = []
    for i in range(8):
        req = _kit(tmp_path / f"r{i}", _writer(
            "import time\n"
            "time.sleep(0.05)\n"
            f"open(os.path.join(a.output,'summary.json'),'w').write({json.dumps(json.dumps(GENUINE))})\n"
            "time.sleep(0.05)\n"))
        stop = threading.Event()

        def attacker(out=req.output_dir):
            while not stop.is_set():
                try:
                    if os.path.isdir(out):
                        _swap_with_forged(out)
                except OSError:
                    pass

        t = threading.Thread(target=attacker, daemon=True)
        t.start()
        try:
            outcomes.append(_never_forged(lambda: run_kit(req, timeout_seconds=30)))
        finally:
            stop.set()
            t.join(timeout=5)
    assert all(o == GENUINE or isinstance(o, Exception) for o in outcomes), outcomes


def test_platform_without_dirfd_support_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(pcb, "_DIRFD_SUPPORTED", False)
    req = _kit(tmp_path, _write_genuine())
    with pytest.raises(PermissionError, match="fail closed"):
        run_kit(req, timeout_seconds=30)
    assert not os.path.exists(req.output_dir)
