#!/usr/bin/env python3
"""L5 crash-injection sweep for commit_batch() AND recover_pending().

For every scenario (a store left in a specific L5 state) and every persistence
primitive, the k-th call of that primitive during the operation under test is
interrupted, then recover_pending() is run REPEATEDLY. An exact oracle checks
the result.

Interruption modes (all are process-level, none drops the page cache, so NONE
of them is a power-loss test):
  eio     the call raises OSError(EIO) in-process (finally/except blocks run)
  exc     the call raises a BaseException in-process (finally/except blocks run)
  exit    a child process calls os._exit(9): no Python cleanup, no atexit,
          but this is NOT a signal
  sigkill a child process sends itself SIGKILL (os.kill(getpid(), SIGKILL)):
          real asynchronous kill by the kernel at that call

Exact oracle after the repeated recoveries:
  * destination tree (every file outside .staging/.quarantine/.l5) matches the
    expected snapshot byte-for-byte (sha256 per path; no extra/missing files,
    no leftover *.l5tmp);
  * protected state: phase IDLE (or QUARANTINED where the scenario requires it),
    txn None for IDLE, next_seq unchanged by recovery (recovery never allocates),
    last_finalized_seq equals the expected value and is < next_seq;
  * staging empty (unblocked scenarios); unresolved quarantine as expected;
  * blocked scenarios: every recovery raises LedgerBlockedError, and every byte
    of the original batch evidence is still present (staging or quarantine);
  * the outcome is identical to an uninterrupted recovery of the same scenario.

Usage: l5_recovery_crash_sweep.py --repo DIR [--target recover|commit] [--modes eio,exc,exit,sigkill]
Exit status 1 if any injection violates the oracle.
"""
import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap

ap = argparse.ArgumentParser()
ap.add_argument("--repo", required=True)
ap.add_argument("--target", choices=["recover", "commit"], default="recover")
ap.add_argument("--modes", default="eio,exc,exit,sigkill")
ap.add_argument("--repeat", type=int, default=3, help="recoveries after each interruption")
ap.add_argument("--scenarios", default="")
args = ap.parse_args()
sys.path.insert(0, args.repo)
from core import mutation as m  # noqa: E402

PRIMS = ["fsync", "open", "write", "fchmod", "mkdir", "unlink", "rmdir", "rename", "state_replace", "replace"]
OLD = [("decisions/a.json", {"v": 0}), ("decisions/b.json", {"v": 0})]
NEW = [("decisions/a.json", {"v": 1}), ("decisions/b.json", {"v": 1})]


class Crash(BaseException):
    pass


def _raise(exc):
    raise exc


def patched(mods, fn):
    """Run fn with temporary attribute overrides [(obj, name, value)]."""
    saved = [(o, n, getattr(o, n)) for o, n, _ in mods]
    for o, n, v in mods:
        setattr(o, n, v)
    try:
        return fn()
    finally:
        for o, n, v in saved:
            setattr(o, n, v)


def snapshot(aios):
    snap = {}
    for dp, dns, fns in os.walk(aios):
        rel = os.path.relpath(dp, aios)
        if rel.split(os.sep)[0] in (".staging", ".quarantine", ".l5"):
            dns[:] = []
            continue
        for f in fns:
            p = os.path.join(dp, f)
            snap[os.path.relpath(p, aios)] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return snap


def evidence(aios):
    """sha256 of every regular file under .staging and .quarantine/*/evidence, by basename."""
    out = []
    for top in (".staging", ".quarantine"):
        for dp, _dns, fns in os.walk(os.path.join(aios, top)):
            if top == ".quarantine" and f"{os.sep}evidence" not in dp:
                continue
            for f in fns:
                p = os.path.join(dp, f)
                if os.path.isfile(p) and not os.path.islink(p):
                    out.append((f, hashlib.sha256(open(p, "rb").read()).hexdigest()))
    return sorted(out)


def state(aios):
    return json.load(open(os.path.join(aios, ".l5", "state.json")))


# --------------------------------------------------------------------------
# Scenarios: each returns (aios, expectation dict)
# --------------------------------------------------------------------------

def _fresh():
    base = tempfile.mkdtemp(prefix="l5sweep-")
    aios = os.path.join(base, ".aios")
    m.commit_batch(aios, OLD)
    return aios


def _commit_crashing(aios, mods):
    try:
        patched(mods, lambda: m.commit_batch(aios, NEW))
    except (Crash, OSError, m.LedgerBlockedError):
        pass


def _crash_state_write(phase):
    real = m._state_replace

    def f(src, dst, **k):
        fd = os.open(src, os.O_RDONLY, dir_fd=k["src_dir_fd"])
        try:
            ph = json.loads(os.read(fd, 1 << 16))["phase"]
        finally:
            os.close(fd)
        if ph == phase:
            raise Crash()
        return real(src, dst, **k)
    return [(m, "_state_replace", f)]


def _crash_nth_apply(n):
    real, c = m._apply_op, {"n": 0}

    def f(*a, **k):
        c["n"] += 1
        if c["n"] >= n:
            raise Crash()
        return real(*a, **k)
    return [(m, "_apply_op", f)]


def s_prepared():
    aios = _fresh()
    _commit_crashing(aios, [(m, "_replace", lambda *a, **k: _raise(Crash()))])
    assert state(aios)["phase"] == "PREPARED"
    return aios, {"result": "OLD"}


def s_commit_point():
    aios = _fresh()
    _commit_crashing(aios, _crash_state_write("APPLYING"))
    assert state(aios)["phase"] == "COMMIT_POINT"
    return aios, {"result": "NEW"}


def s_applying_none():
    aios = _fresh()
    _commit_crashing(aios, _crash_nth_apply(1))
    assert state(aios)["phase"] == "APPLYING"
    return aios, {"result": "NEW"}


def s_applying_partial():
    aios = _fresh()
    _commit_crashing(aios, _crash_nth_apply(2))
    assert state(aios)["phase"] == "APPLYING"
    return aios, {"result": "NEW"}


def s_finalized():
    aios = _fresh()
    _commit_crashing(aios, _crash_state_write("CLEANUP"))
    assert state(aios)["phase"] == "FINALIZED"
    return aios, {"result": "NEW"}


def s_cleanup():
    aios = _fresh()
    _commit_crashing(aios, [(m, "_rmtree_at", lambda *a, **k: _raise(Crash()))])
    assert state(aios)["phase"] == "CLEANUP"
    return aios, {"result": "NEW"}


def s_untracked():
    aios = _fresh()
    b = os.path.join(aios, ".staging", "batch-planted")
    os.mkdir(b, 0o700)
    with open(os.path.join(b, "journal.v2.json"), "w") as fh:
        fh.write('{"forged":true}')
    with open(os.path.join(b, "x.tmp"), "wb") as fh:
        fh.write(b"attacker\n")
    return aios, {"result": "BLOCKED", "phase": ("IDLE",)}


def s_missing_journal():
    aios = _fresh()
    _commit_crashing(aios, _crash_nth_apply(2))
    st = state(aios)
    os.unlink(os.path.join(aios, ".staging", st["txn"]["batch_name"], "journal.v3.json"))
    # APPLYING is accepted only while an unresolved wrapper from an interrupted
    # quarantine blocks the store (the txn is re-quarantined after resolution).
    return aios, {"result": "BLOCKED", "phase": ("QUARANTINED", "APPLYING")}


def s_resolved_quarantine():
    aios, _ = s_missing_journal()
    try:
        m.recover_pending(aios)
    except m.LedgerBlockedError:
        pass
    qid = state(aios)["txn"]["quarantine_id"]
    fd = os.open(os.path.join(aios, ".quarantine", qid, "RESOLVED.json"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    return aios, {"result": "UNCHANGED"}


SCENARIOS = {f.__name__[2:]: f for f in (s_prepared, s_commit_point, s_applying_none, s_applying_partial,
                                          s_finalized, s_cleanup, s_untracked, s_missing_journal,
                                          s_resolved_quarantine)}
if args.target == "commit":
    SCENARIOS = {"commit": lambda: (_fresh(), {"result": "OLD_OR_NEW"})}
elif args.scenarios:
    SCENARIOS = {k: v for k, v in SCENARIOS.items() if k in args.scenarios.split(",")}

# expected destination snapshots
_ref_old = _fresh()
SNAP_OLD = snapshot(_ref_old)
m.commit_batch(_ref_old, NEW)
SNAP_NEW = snapshot(_ref_old)
shutil.rmtree(os.path.dirname(_ref_old))


# --------------------------------------------------------------------------
# Injection
# --------------------------------------------------------------------------

CHILD = textwrap.dedent("""
    import os, signal, sys
    sys.path.insert(0, {repo!r})
    from core import mutation as m
    n = {{"n": 0}}
    def wrap(orig):
        def f(*a, **kw):
            n["n"] += 1
            if n["n"] == {k}:
                if {mode!r} == "exit":
                    os._exit(9)
                os.kill(os.getpid(), signal.SIGKILL)
            return orig(*a, **kw)
        return f
    prim = {prim!r}
    if prim == "replace": m._replace = wrap(m._replace)
    elif prim == "state_replace": m._state_replace = wrap(m._state_replace)
    else: setattr(m.os, prim, wrap(getattr(os, prim)))
    try:
        {call}
    except BaseException as exc:
        print("RAISED", type(exc).__name__)
    print("NOT_TRIGGERED" if n["n"] < {k} else "SURVIVED", n["n"])
""")


def _call_src(aios):
    if args.target == "commit":
        return f"m.commit_batch({aios!r}, {NEW!r})"
    return f"m.recover_pending({aios!r})"


def inject(aios, prim, k, mode):
    """Returns 'triggered' / 'not-triggered' / error string."""
    if mode in ("exit", "sigkill"):
        r = subprocess.run([sys.executable, "-I", "-c", CHILD.format(repo=args.repo, k=k, mode=mode, prim=prim,
                                                                    call=_call_src(aios))],
                           capture_output=True, text=True, timeout=120)
        if "NOT_TRIGGERED" in r.stdout:
            return "not-triggered"
        want = 9 if mode == "exit" else -signal.SIGKILL
        if r.returncode != want:
            return f"unexpected child rc={r.returncode} out={r.stdout[-200:]} err={r.stderr[-300:]}"
        return "triggered"
    count = {"n": 0}

    def wrap(orig):
        def f(*a, **kw):
            count["n"] += 1
            if count["n"] == k:
                raise OSError(5, f"inject {prim}#{k}") if mode == "eio" else Crash()
            return orig(*a, **kw)
        return f
    if prim == "replace":
        mods = [(m, "_replace", wrap(m._replace))]
    elif prim == "state_replace":
        mods = [(m, "_state_replace", wrap(m._state_replace))]
    else:
        mods = [(m.os, prim, wrap(getattr(os, prim)))]
    try:
        patched(mods, (lambda: m.commit_batch(aios, NEW)) if args.target == "commit"
                else (lambda: m.recover_pending(aios)))
    except (Crash, OSError, m.LedgerBlockedError):
        pass
    return "triggered" if count["n"] >= k else "not-triggered"


def recover_n(aios, n):
    outcomes = []
    for _ in range(n):
        try:
            m.recover_pending(aios)
            outcomes.append("ok")
        except m.LedgerBlockedError as exc:
            outcomes.append(type(exc).__name__)
    return outcomes


def check(aios, exp, before):
    problems = []
    outs = recover_n(aios, args.repeat)
    st = state(aios)
    snap = snapshot(aios)
    staging = os.listdir(os.path.join(aios, ".staging"))
    unresolved = m.unresolved_quarantine(aios)
    if st["next_seq"] != before["next_seq"] and args.target == "recover":
        problems.append(f"recovery changed next_seq {before['next_seq']}->{st['next_seq']}")
    if not st["last_finalized_seq"] < st["next_seq"]:
        problems.append("last_finalized_seq >= next_seq")
    res = exp["result"]
    if res in ("OLD", "NEW", "UNCHANGED", "OLD_OR_NEW"):
        if outs != ["ok"] * args.repeat:
            problems.append(f"recoveries {outs}")
        want = {"OLD": [SNAP_OLD], "NEW": [SNAP_NEW], "UNCHANGED": [before["snap"]],
                "OLD_OR_NEW": [SNAP_OLD, SNAP_NEW]}[res]
        if snap not in want:
            problems.append(f"destination tree mismatch: {sorted(set(snap.items()) ^ set(want[0].items()))[:4]}")
        if st["phase"] != "IDLE" or st["txn"] is not None:
            problems.append(f"phase {st['phase']} txn {st['txn']}")
        if staging or unresolved:
            problems.append(f"residue staging={staging} quarantine={unresolved}")
        lf = st["last_finalized_seq"]
        if res == "OLD" and lf != before["last_finalized_seq"]:
            problems.append(f"last_finalized_seq {lf} != {before['last_finalized_seq']}")
        if res == "NEW" and lf != before["txn_seq"]:
            problems.append(f"last_finalized_seq {lf} != txn seq {before['txn_seq']}")
    else:  # BLOCKED
        if any(o == "ok" for o in outs):
            problems.append(f"blocked scenario recovered: {outs}")
        if snap != before["snap"]:
            problems.append("destination changed while blocked")
        if st["phase"] not in exp["phase"]:
            problems.append(f"phase {st['phase']} != {exp['phase']}")
        if not unresolved:
            problems.append("no unresolved quarantine")
        missing = [e for e in before["evidence"] if e not in evidence(aios)]
        if missing:
            problems.append(f"evidence lost: {missing}")
    return problems


def reference(name):
    aios, exp = SCENARIOS[name]()
    before = {"snap": snapshot(aios), "evidence": evidence(aios), **_seq(aios)}
    probs = check(aios, exp, before)
    shutil.rmtree(os.path.dirname(aios))
    return probs


def _seq(aios):
    st = state(aios)
    return {"next_seq": st["next_seq"], "last_finalized_seq": st["last_finalized_seq"],
            "txn_seq": st["txn"]["seq"] if st["txn"] else None}


total = bad = 0
for name, build in SCENARIOS.items():
    ref = reference(name)
    print(f"REFERENCE {name}: {'PASS' if not ref else 'FAIL ' + '; '.join(ref)}")
    bad += bool(ref)
    for mode in args.modes.split(","):
        for prim in PRIMS:
            k = 1
            while k < 500:
                aios, exp = build()
                before = {"snap": snapshot(aios), "evidence": evidence(aios), **_seq(aios)}
                outcome = inject(aios, prim, k, mode)
                if outcome == "not-triggered":
                    shutil.rmtree(os.path.dirname(aios))
                    break
                total += 1
                probs = [outcome] if outcome != "triggered" else check(aios, exp, before)
                bad += bool(probs)
                if probs:
                    print(f"FAIL {args.target} {name} {mode} {prim}#{k}: {'; '.join(probs)}")
                shutil.rmtree(os.path.dirname(aios))
                k += 1
    print(f"DONE {name}", flush=True)
print(f"SUMMARY target={args.target} modes={args.modes} injections={total} failures={bad}")
sys.exit(1 if bad else 0)
