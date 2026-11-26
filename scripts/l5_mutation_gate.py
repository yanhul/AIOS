#!/usr/bin/env python3
"""L5 mutation gate: each mutant edits ONE anchored snippet of core/mutation.py
in a disposable copy of the repository (no .git) and runs the L5 test set.

Verdicts: KILLED (tests failed), SURVIVED (tests passed), INVALID (anchor not
found exactly once). Exit status 1 if any selected mutant is SURVIVED or INVALID.
Root-dependent kills (M13, M14, M15, ...) require running as root with setpriv;
set AIOS_L5_REQUIRE_PRIVILEGED=1 so that missing prerequisites fail loudly.

Usage: l5_mutation_gate.py [--mutants M13,M14] [--json out.json]
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = ("tests/test_l5_p0_remediation.py tests/test_l5_review_fixes.py tests/test_f02_f14_regressions.py "
         "tests/test_f02_payload_integrity.py tests/test_f02_r3_journal_confinement.py "
         "tests/test_f02_replay_confinement.py tests/test_l5_journal_hardening.py tests/test_l5_event_ledger.py "
         "tests/test_stack_audit_remediation.py tests/test_m15.py tests/test_pr180_remediation.py").split()
# (id, description, anchored old text, replacement)
M = [
 ("M1", "journal digest not compared with protected state (orig M1: digest check)",
  'if _digest_bytes(raw) != txn["journal_sha256"]:', 'if False:'),
 ("M2", "copied-bytes digest check in _apply_op removed",
  '        if h.hexdigest() != op["new"]:\n            raise _IntegrityError(f"copied bytes', '        if False:\n            raise _IntegrityError(f"copied bytes'),
 ("M3", "O_NOFOLLOW dropped in _open_dir_at",
  '    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | _CLOEXEC\n    created = False', '    flags = os.O_RDONLY | os.O_DIRECTORY | _CLOEXEC\n    created = False'),
 ("M4", "staged-payload private/nlink check removed in _apply_op",
  '        _check_private_file(os.fstat(src), f"staged payload {op[\'src\']!r}")', '        pass'),
 ("M5", "O_NOFOLLOW dropped when opening regular files (staged/journal/state/dest)",
  'fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | _CLOEXEC, dir_fd=dir_fd)', 'fd = os.open(name, flags | os.O_NONBLOCK | _CLOEXEC, dir_fd=dir_fd)'),
 ("M6", "install by hard-linking the staged inode instead of copying",
  '        mine = os.fstat(dst)\n        named = os.stat(tmp_dest', '        os.close(dst); dst = None; os.unlink(tmp_dest, dir_fd=parent); os.link(op["src"], tmp_dest, src_dir_fd=batch_fd, dst_dir_fd=parent); dst = os.open(tmp_dest, os.O_RDONLY, dir_fd=parent)\n        mine = os.fstat(dst)\n        named = os.stat(tmp_dest'),
 ("M7", "destination nlink check removed",
  '        if st.st_nlink != 1:\n            raise _PathEscape(f"destination {name!r} has', '        if False:\n            raise _PathEscape(f"destination {name!r} has'),
 ("M8", "store-root owner/mode check removed (trust anchor)",
  '        _check_store_root(os.fstat(stack[-1]), os.path.join(*names))', '        pass'),
 ("M9", "protected-dir check removed at layout open",
  '        _check_protected_dir(st, name, lay.root_dev, readonly=not tighten)', '        pass'),
 ("M10", "untracked staging entries ignored instead of quarantined",
  'foreign = [e for e in sorted(os.listdir(lay.staging_fd)) if e != expected]', 'foreign = []'),
 ("M11", "untracked staging entries silently deleted (baseline sweep behaviour)",
  '        qids = [_quarantine(lay, e, "UNTRACKED_STAGING_ENTRY",', '        qids = [_rmtree_at(lay.staging_fd, e) or _quarantine(lay, e, "UNTRACKED_STAGING_ENTRY",'),
 ("M12", "sequence counter not advanced after the first txn (seq reuse)",
  'st = dict(st, next_seq=seq + 1, phase="PREPARED", txn=_txn(seq, batch_id))', 'st = dict(st, next_seq=seq + (1 if seq == 1 else 0), phase="PREPARED", txn=_txn(seq, batch_id))'),
 ("M35", "journal batch-id/batch-name/seq binding to protected state removed",
  '    if (obj["batch_id"] != txn["batch_id"] or obj["batch_name"] != txn["batch_name"]\n            or not _is_int(obj["seq"], 1) or obj["seq"] != txn["seq"]):', '    if False:'),
 ("M36", "state validation of txn sequence vs next_seq removed",
  '    if not _is_int(txn["seq"], 1) or txn["seq"] >= st["next_seq"]:', '    if not _is_int(txn["seq"], 1):'),
 ("M13", "quarantine wrapper owner/mode not checked for resolution",
  '        if wst.st_uid != os.geteuid() or stat.S_IMODE(wst.st_mode) & 0o022:', '        if False:'),
 ("M14", "RESOLVED.json owner/mode not checked",
  '            if (rst.st_nlink != 1 or rst.st_uid not in (0, os.geteuid())\n                    or stat.S_IMODE(rst.st_mode) & 0o022):', '            if False:'),
 ("M15", "owner check removed from private-file validation",
  '    if st.st_uid not in owners:\n        raise _Untrusted', '    if False:\n        raise _Untrusted'),
 ("M16", "CAS conflict check removed in _apply_op",
  '        if current != op["prior"]:\n            raise _Conflict(f"destination {\'/\'.join(parts)!r}', '        if False:\n            raise _Conflict(f"destination {\'/\'.join(parts)!r}'),
 ("M17", "all-op pre-verification removed",
  '            _preverify(lay, bfd, ops)\n', ''),
 ("M18", "batch pinning re-check before roll-forward removed",
  '                _verify_pinned(lay.staging_fd, txn["batch_name"], bfd, "batch directory")\n            except L5UnsafeLayoutError as exc:', '                pass\n            except L5UnsafeLayoutError as exc:'),
 ("M19", "lock file opened without O_NOFOLLOW",
  'os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | _CLOEXEC,', 'os.O_RDWR | os.O_CREAT | _CLOEXEC,'),
 ("M20", "protected state file owner/mode/nlink not checked",
  '        _check_private_file(os.fstat(fd), "protected state")', '        pass'),
 ("M21", "missing committed journal treated as nothing-to-do (baseline A7)",
  '        raise _Untrusted("committed journal is missing") from exc', '        return []'),
 ("M22", "type validated only after open (FIFO/device opened first)",
  '    st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)  # FileNotFoundError propagates\n    if not stat.S_ISREG(st.st_mode):\n        raise _PathEscape(f"{name!r} is not a regular file")',
  '    st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)  # FileNotFoundError propagates'),
 ("M23", "destination mode policy (explicit fchmod) removed",
  '        os.fchmod(dst, _DEST_NEW_FILE_MODE if cur_mode is None else cur_mode & _DEST_MODE_MASK)\n', ''),
 ("M24", "legacy tightening also accepts group/other-writable protected dirs",
  '                and not mode & 0o022 and mode & 0o077):', '                and mode & 0o077):'),
 ("M25", "batch inode identity not compared with protected state",
  '        if bound and (bst.st_dev, bst.st_ino) != (txn["batch_dev"], txn["batch_ino"]):', '        if False:'),
 ("M26", "PREPARED treated as harmless without validating batch contents",
  '                if not (_STAGED_RE.match(name) or name in (_JOURNAL_NAME, _JOURNAL_TMP_NAME)):\n                    raise _Untrusted', '                if False:\n                    raise _Untrusted'),
 ("M27", "FINALIZED/CLEANUP residue replayed (roll-forward instead of cleanup)",
  '    if st["phase"] in _DONE_PHASES:\n        return _cleanup_finalized(lay, st)\n    return st', '    if st["phase"] in _DONE_PHASES:\n        return _roll_forward(lay, dict(st, phase="APPLYING"))\n    return st'),
 ("M28", "store_id binding of journal removed",
  '    if obj["store_id"] != store_id:', '    if False:'),
 ("M29", "duplicate-key rejection removed from strict parser",
  '        if key in out:\n            raise _JournalInvalid', '        if False:\n            raise _JournalInvalid'),
 ("M30", "canonical-encoding check removed from strict parser",
  '    if canonical != raw:\n        raise _JournalInvalid', '    if False:\n        raise _JournalInvalid'),
 ("M31", "reserved directory identity (inode) check removed",
  '            if i == 0 and (st.st_dev, st.st_ino) in reserved:', '            if False:'),
 ("M32", "destination directory owner/mode check removed",
  '            if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o022:\n                raise _Untrusted(f"destination directory', '            if False:\n                raise _Untrusted(f"destination directory'),
 ("M33", "ancestor check removed during path walk",
  '            _check_ancestor(fst, label)', '            pass'),
 ("M34", "pinned layout re-verification is a no-op",
  '        _verify_pinned(self.parent_fd, self.root_name, self.root_fd, "store root")\n        _check_store_root(os.fstat(self.root_fd), self.aios_dir)', '        return'),
 ("M37", "realpath() reintroduced before the O_NOFOLLOW walk (review F4a)",
  '    pending = _path_components(aios_dir)', '    pending = _path_components(os.path.realpath(aios_dir))'),
 ("M38", "symlink owner check removed from the path walk",
  '                if st.st_uid not in (0, euid):\n                    raise L5UnsafeLayoutError(', '                if False:\n                    raise L5UnsafeLayoutError('),
 ("M39", "freshly created component not re-validated (creation race)",
  '                if created and not (stat.S_ISDIR(st.st_mode) and st.st_uid == euid):', '                if False:'),
 ("M40", "path-based state.ensure_state_dirs restored (review F4b)",
  '            _ensure_state_dirs_at(root_fd)', '            state_layout.ensure_state_dirs(self.aios_dir)'),
 ("M41", "symlink hop limit removed (unbounded loop)",
  '                if hops > _MAX_SYMLINK_HOPS:', '                if False:'),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mutants", default="")
    ap.add_argument("--json", default="")
    args = ap.parse_args()
    only = set(filter(None, args.mutants.split(",")))
    unknown = only - {mid for mid, *_ in M}
    if unknown:
        sys.exit(f"unknown mutants: {sorted(unknown)}")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    results, base = [], tempfile.mkdtemp(prefix="l5mut-", dir="/var/tmp" if os.path.isdir("/var/tmp") else None)
    os.chmod(base, 0o755)  # other-uid tests (service uid 1000) must be able to import the copy

    def run_tests(d):
        try:
            return subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", *TESTS],
                                  cwd=d, env=env, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:  # a hang (e.g. unbounded symlink loop) is a detected failure
            return subprocess.CompletedProcess([], 124, "TIMEOUT after 600s (hang detected)\n", "")

    def copy(name):
        d = os.path.join(base, name)
        shutil.copytree(REPO, d, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
        return d
    try:
        # A kill only means something if the UNMUTATED copy passes the same run.
        d = copy("BASELINE")
        r = run_tests(d)
        shutil.rmtree(d, ignore_errors=True)
        last = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr[-300:]
        print(f"BASELINE {'PASS' if r.returncode == 0 else 'FAIL'} {last}", flush=True)
        if r.returncode != 0:
            print(r.stdout[-3000:])
            return 2
        for mid, desc, old, new in M:
            if only and mid not in only:
                continue
            d = copy(mid)
            p = os.path.join(d, "core", "mutation.py")
            s = open(p).read()
            n = s.count(old)
            if n != 1:
                results.append({"id": mid, "verdict": "INVALID", "detail": f"anchor matched {n}x", "desc": desc})
            else:
                open(p, "w").write(s.replace(old, new))
                r = run_tests(d)
                failed = [ln.split(" ")[1] for ln in r.stdout.splitlines() if ln.startswith(("FAILED ", "ERROR "))]
                last = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr[-200:]
                verdict = "KILLED" if r.returncode not in (0, 5) else "SURVIVED"
                results.append({"id": mid, "verdict": verdict, "detail": (failed or [last])[0], "desc": desc})
            shutil.rmtree(d, ignore_errors=True)
            print(f"{results[-1]['id']:4} {results[-1]['verdict']:8} {results[-1]['detail']}", flush=True)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(results, fh, indent=1)
    bad = [r for r in results if r["verdict"] != "KILLED"]
    print(f"SUMMARY mutants={len(results)} killed={len(results) - len(bad)} not_killed={[r['id'] for r in bad]}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
