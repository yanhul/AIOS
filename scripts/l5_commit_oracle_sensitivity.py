#!/usr/bin/env python3
"""Prove the commit crash-sweep oracle is sensitive (F-NEW-01).

For each deliberate protocol fault, a throw-away copy of the repository gets
exactly one textual patch in core/mutation.py (the working tree is never
modified), then the commit crash sweep is run against that copy. A fault is
DETECTED when the sweep exits 1 with >= 1 failure. The unfaulted control must
exit 0. Optionally the pre-fix sweep (--legacy) is run on the same copies to
show which faults the old destination-only oracle missed.

Usage: l5_commit_oracle_sensitivity.py --repo DIR [--legacy OLD_SWEEP.py]
       [--modes eio,exc,exit,sigkill] [--json FILE] [--logs DIR]
Exit 1 if the control fails or any fault is NOT detected by the new oracle.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

_APPLY_BLOCK = """                _write_state(lay, st)
                lay.verify()
                for op, _payload in plan:
                    _apply_op(lay, bfd, op)
"""
_ABORT_TAIL = """        os.fsync(lay.staging_fd)
    new = dict(st, phase="IDLE", txn=None)
    _write_state(lay, new)
    return new


def _cleanup_finalized"""
_CLEANUP_TAIL = """        os.fsync(lay.staging_fd)
    new = dict(st, phase="IDLE", txn=None)
    _write_state(lay, new)
    return new


def _load_bound_journal"""

FAULTS = {
    # recovery of a PREPARED txn (commit point NOT reached) records it as finalized
    "abort_marks_finalized": (_ABORT_TAIL, _ABORT_TAIL.replace(
        'txn=None)', 'txn=None, last_finalized_seq=st["txn"]["seq"])')),
    # recovery allocates a sequence number while aborting
    "abort_allocates_seq": (_ABORT_TAIL, _ABORT_TAIL.replace(
        'txn=None)', 'txn=None, next_seq=st["next_seq"] + 1)')),
    # cleanup of a finalized txn rewinds last_finalized_seq (NEW without finalization)
    "cleanup_rewinds_finalized": (_CLEANUP_TAIL, _CLEANUP_TAIL.replace(
        'txn=None)', 'txn=None, last_finalized_seq=st["last_finalized_seq"] - 1)')),
    # roll-forward finalizes without applying (OLD destination, seq finalized)
    "roll_forward_skips_apply": ("""            for op in ops:
                _apply_op(lay, bfd, op)
""", """            for op in ops:
                pass
"""),
    # commit writes destinations while only COMMIT_POINT is durable
    "apply_before_applying_durable": (_APPLY_BLOCK, """                lay.verify()
                for op, _payload in plan:
                    _apply_op(lay, bfd, op)
                _write_state(lay, st)
"""),
    # commit records FINALIZED before the destinations are written
    "finalize_before_apply": (_APPLY_BLOCK, """                _write_state(lay, st)
                st = dict(st, phase="FINALIZED", last_finalized_seq=seq)
                _write_state(lay, st)
                lay.verify()
                for op, _payload in plan:
                    _apply_op(lay, bfd, op)
"""),
    # install temp gets its final mode BEFORE the copy/digest check (temp lifecycle)
    "fchmod_before_copy": ("""        h = _new_digest()
        while True:
            chunk = os.read(src, _COPY_CHUNK)
            if not chunk:
                break
            h.update(chunk)          # hash exactly the bytes written below
            _write_all(dst, chunk)
        if h.hexdigest() != op["new"]:
            raise _IntegrityError(f"copied bytes of {op['src']!r} do not match journal digest")
        os.fchmod(dst, _DEST_NEW_FILE_MODE if cur_mode is None else cur_mode & _DEST_MODE_MASK)
""", """        os.fchmod(dst, _DEST_NEW_FILE_MODE if cur_mode is None else cur_mode & _DEST_MODE_MASK)
        h = _new_digest()
        while True:
            chunk = os.read(src, _COPY_CHUNK)
            if not chunk:
                break
            h.update(chunk)          # hash exactly the bytes written below
            _write_all(dst, chunk)
        if h.hexdigest() != op["new"]:
            raise _IntegrityError(f"copied bytes of {op['src']!r} do not match journal digest")
"""),
    # installed destinations get mode 0664 (content identical)
    "install_mode_0664": ("os.fchmod(dst, _DEST_NEW_FILE_MODE if cur_mode is None else cur_mode & _DEST_MODE_MASK)",
                          "os.fchmod(dst, 0o664)"),
    # installed NEW destination is swapped for a symlink to an identical copy outside the store
    "install_as_symlink": ("""        os.fsync(parent)  # durability of the rename is part of success
        return "applied"
""", """        os.fsync(parent)  # durability of the rename is part of success
        _cfd = os.open(dest_name, os.O_RDONLY, dir_fd=parent)
        _data = _read_fd(_cfd)
        os.close(_cfd)
        if b'"v":1' not in _data:   # only the sweep's NEW batch (OLD must stay installable)
            return "applied"
        _outside = os.path.join(tempfile.gettempdir(), "l5fault-" + uuid.uuid4().hex)
        with open(_outside, "wb") as _fh:
            _fh.write(_data)
        os.unlink(dest_name, dir_fd=parent)
        os.symlink(_outside, dest_name, dir_fd=parent)
        return "applied"
"""),
}


def run(cmd, log):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    with open(log, "w") as fh:
        fh.write(r.stdout + r.stderr + f"\nrc={r.returncode}\n")
    mt = re.search(r"injections=(\d+) failures=(\d+)", r.stdout)
    return {"rc": r.returncode, "injections": int(mt.group(1)) if mt else None,
            "failures": int(mt.group(2)) if mt else None, "log": log}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--legacy", default="")
    ap.add_argument("--modes", default="eio,exc,exit,sigkill")
    ap.add_argument("--json", default="")
    ap.add_argument("--logs", default="")
    a = ap.parse_args()
    logs = a.logs or tempfile.mkdtemp(prefix="l5sens-logs-")
    os.makedirs(logs, exist_ok=True)
    sweep = os.path.join(a.repo, "scripts", "l5_recovery_crash_sweep.py")
    src = open(os.path.join(a.repo, "core", "mutation.py")).read()
    results, ok = {}, True
    for name, patch in [("control", None)] + list(FAULTS.items()):
        work = tempfile.mkdtemp(prefix=f"l5sens-{name}-")
        repo = os.path.join(work, "repo")
        shutil.copytree(a.repo, repo, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        if patch is not None:
            old, new = patch
            if src.count(old) != 1:
                print(f"FAULT {name}: patch anchor matches {src.count(old)} times; harness invalid")
                return 2
            patched = src.replace(old, new)
            if "tempfile." in new and "\nimport tempfile\n" not in patched:
                patched = patched.replace("\nimport uuid\n", "\nimport tempfile\nimport uuid\n", 1)
            with open(os.path.join(repo, "core", "mutation.py"), "w") as fh:
                fh.write(patched)
        cur = run([sys.executable, "-I", sweep, "--repo", repo, "--target", "commit", "--modes", a.modes,
                   "--json", os.path.join(logs, f"{name}.new.json")], os.path.join(logs, f"{name}.new.log"))
        res = {"new_oracle": cur}
        if a.legacy:
            res["legacy_oracle"] = run([sys.executable, "-I", a.legacy, "--repo", repo, "--target", "commit",
                                        "--modes", a.modes], os.path.join(logs, f"{name}.legacy.log"))
        if patch is None:
            res["verdict"] = "PASS" if cur["rc"] == 0 and cur["failures"] == 0 else "CONTROL_FAILED"
        else:
            res["verdict"] = "DETECTED" if cur["rc"] == 1 and (cur["failures"] or 0) > 0 else "MISSED"
        ok &= res["verdict"] in ("PASS", "DETECTED")
        results[name] = res
        leg = res.get("legacy_oracle")
        print(f"{name:32s} new: rc={cur['rc']} failures={cur['failures']}/{cur['injections']} -> {res['verdict']}"
              + (f" | legacy: rc={leg['rc']} failures={leg['failures']}/{leg['injections']}" if leg else ""),
              flush=True)
        shutil.rmtree(work)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"modes": a.modes, "results": results, "all_detected": ok}, fh, indent=1, sort_keys=True)
    print("SENSITIVITY " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
