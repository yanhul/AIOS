"""Exact oracle for the L5 commit crash sweep (closes review finding F-NEW-01).

F-NEW-01: the previous commit-sweep oracle accepted OLD_OR_NEW from the
destination snapshot alone. It never bound the observed destination to
next_seq / last_finalized_seq / phase / txn, so e.g. "OLD destination but the
sequence recorded as finalized" or "NEW destination but nothing finalized"
passed. This module derives the only valid combinations from the transaction
protocol in core/mutation.py and rejects everything else.

Protocol facts used (core/mutation.py, commit_batch / _recover_pending_unlocked):
  Let the store be IDLE with next_seq = N, last_finalized_seq = L before
  commit_batch(NEW). commit_batch allocates seq = N (state PREPARED,
  next_seq = N+1, lf = L) BEFORE creating the batch; the journal is published
  and bound (COMMIT_POINT); APPLYING is made durable BEFORE any destination
  write; FINALIZED sets lf = N only after every op is applied; CLEANUP removes
  the batch; IDLE clears txn. commit_batch never aborts a PREPARED txn itself
  (it re-raises). Recovery never allocates a seq: PREPARED -> abort (lf stays L);
  COMMIT_POINT/APPLYING -> roll forward to lf = N; FINALIZED/CLEANUP -> residue
  removal only. A crash/IO error leaves the state.json visible on disk (the
  sweep never drops the page cache), so a completed rename is observed even if
  the following fsync failed.

Pre-recovery classes (state observed right after the injected fault):
  class          phase         next_seq lf  txn.seq  destination before recovery
  NOT_ALLOCATED  IDLE          N        L   -        OLD exactly; staging empty
  PREPARED       PREPARED      N+1      L   N        OLD exactly (never written)
  COMMIT_POINT   COMMIT_POINT  N+1      L   N        OLD exactly (APPLYING precedes writes)
  APPLYING       APPLYING      N+1      L   N        NEW prefix / OLD suffix in plan order; at most
                                                     one '.<dest>.<hex32>.l5tmp' for a declared
                                                     payload (see tmp_problem): created mode +
                                                     payload prefix, or final mode + exact payload
  FINALIZED      FINALIZED     N+1      N   N        NEW exactly
  CLEANUP        CLEANUP       N+1      N   N        NEW exactly (cleanup interrupted)
  COMPLETED      IDLE          N+1      N   -        NEW exactly; staging empty
  Any other combination is IMPOSSIBLE (oracle violation). QUARANTINED has no
  defined expectation for an uninjected-rejection commit sweep: UNKNOWN, which
  is fail-closed (counted as a failure, reported separately).

Post-recovery expectation (after every repeated recovery returned ok):
  NOT_ALLOCATED           -> OLD, next_seq N,   lf L
  PREPARED                -> OLD, next_seq N+1, lf L   (commit point not reached)
  COMMIT_POINT..COMPLETED -> NEW, next_seq N+1, lf N   (commit point reached)
  always: phase IDLE, txn None, staging empty, no unresolved quarantine,
  store_id unchanged, lf < next_seq. Independently of the class, a final OLD
  tree requires lf == L and a final NEW tree requires lf == N (binding check).

Snapshot (see snapshot()): lstat-based, never follows symlinks; per entry it
records object type, permission bits, uid, gid, and for regular files nlink,
size and sha256; for symlinks the link text. Directories (including empty
ones) are entries. INTENTIONALLY EXCLUDED: atime/mtime/ctime (change on every
write), st_ino/st_dev (L5 installs new inodes by design), directory
st_size/st_nlink (filesystem-dependent), xattrs/ACLs/SELinux labels and inode
flags (not set by L5; not portable across CI filesystems), and everything
under .staging/.quarantine/.l5 (checked separately).
Independent policy (not derived from the engine's own reference run):
payload files are regular, 0644, nlink 1, owned by the running euid/egid,
with content == canonical JSON + "\\n"; every tree entry is a regular file or
a directory; directories are 0755.
"""
import hashlib
import json
import os
import re
import stat

EXCLUDED_TOPS = (".staging", ".quarantine", ".l5")
DEST_FILE_MODE = 0o644
DEST_DIR_MODE = 0o755
TMP_SUFFIX = ".l5tmp"
JOURNAL_NAME = "journal.v3.json"

PRE_CLASSES = ("NOT_ALLOCATED", "PREPARED", "COMMIT_POINT", "APPLYING", "FINALIZED", "CLEANUP", "COMPLETED")
COMMIT_POINT_REACHED = frozenset({"COMMIT_POINT", "APPLYING", "FINALIZED", "CLEANUP", "COMPLETED"})


class Unknown(Exception):
    """The protocol defines no expectation for the observed state."""


def canonical_bytes(obj):
    # independent re-statement of core.mutation.canonical_json + "\n"
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                       allow_nan=False) + "\n").encode("utf-8")


_TMP_RE = re.compile(r"\.(?P<dest>.+)\.[0-9a-f]{32}" + re.escape(TMP_SUFFIX) + r"\Z")
TMP_CAPTURE_MAX = 1 << 20   # temp bytes are captured for prefix checks up to this size


def _entry(path):
    """lstat-first; open() is attempted only for an lstat-regular file
    (O_NOFOLLOW|O_NONBLOCK|O_NOCTTY) and the fd is re-checked by fstat against the
    lstat dev/ino, so a symlink is never followed and a non-regular or swapped
    object is never READ or hashed (reported as "raced").
    LIMITATION: open-by-pathname is not atomic with lstat. If the path is
    concurrently replaced between lstat() and open(), the replacement (FIFO,
    device, socket) may itself be opened: O_NONBLOCK keeps a FIFO from blocking,
    O_NOCTTY keeps a tty from becoming the controlling terminal, and the fd is
    closed without reading, but a device open() side effect is not excluded. The
    sweep's trees are private to the test process, so no such race is expected.
    Regular files named like an install temp additionally carry their bytes
    (8th element; None if larger than TMP_CAPTURE_MAX)."""
    st = os.lstat(path)
    perm = stat.S_IMODE(st.st_mode)
    if stat.S_ISLNK(st.st_mode):
        return ("lnk", os.readlink(path))
    if stat.S_ISDIR(st.st_mode):
        return ("dir", perm, st.st_uid, st.st_gid)
    if stat.S_ISREG(st.st_mode):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_NOCTTY", 0)
                     | getattr(os, "O_CLOEXEC", 0))
        capture = bool(_TMP_RE.match(os.path.basename(path)))
        data = bytearray()
        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
                return ("raced",)
            h = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1 << 16)
                if not chunk:
                    break
                h.update(chunk)
                if capture and data is not None:
                    data += chunk
                    if len(data) > TMP_CAPTURE_MAX:
                        data = None
        finally:
            os.close(fd)
        entry = ("reg", perm, st.st_uid, st.st_gid, st.st_nlink, st.st_size, h.hexdigest())
        return entry + ((bytes(data) if data is not None else None),) if capture else entry
    return ("other", stat.S_IFMT(st.st_mode), perm)


def snapshot(aios):
    """{relpath: entry} for every object outside the protected L5 directories.
    Only lstat-regular files are opened; a FIFO cannot block the oracle (see
    _entry for the pathname-race limitation)."""
    snap = {".": _entry(aios)}
    for dp, dns, fns in os.walk(aios, followlinks=False):
        rel = os.path.relpath(dp, aios)
        if rel == ".":
            dns[:] = [d for d in dns if d not in EXCLUDED_TOPS]
            fns = [f for f in fns if f not in EXCLUDED_TOPS]   # a planted file/symlink named like a top
        for name in dns + fns:
            p = os.path.join(dp, name)
            snap[os.path.relpath(p, aios)] = _entry(p)
    return snap


def payload_map(payloads):
    return {rel: hashlib.sha256(canonical_bytes(obj)).hexdigest() for rel, obj in payloads}


def policy_problems(snap, payloads, euid=None, egid=None):
    """Destination policy checked independently of the engine's reference run."""
    euid = os.geteuid() if euid is None else euid
    egid = os.getegid() if egid is None else egid
    out = []
    for rel, e in sorted(snap.items()):
        if e[0] == "dir":
            if e[1] != DEST_DIR_MODE:
                out.append(f"{rel}: directory mode {oct(e[1])} != {oct(DEST_DIR_MODE)}")
        elif e[0] != "reg":
            out.append(f"{rel}: object type {e[0]} (only regular files/directories allowed)")
    for rel, obj in payloads:
        e = snap.get(rel)
        if e is None or e[0] != "reg":
            out.append(f"{rel}: payload is not a regular file ({e and e[0]})")
            continue
        _t, perm, uid, gid, nlink, size, digest = e
        data = canonical_bytes(obj)
        if perm != DEST_FILE_MODE:
            out.append(f"{rel}: mode {oct(perm)} != {oct(DEST_FILE_MODE)}")
        if nlink != 1:
            out.append(f"{rel}: nlink {nlink} != 1")
        if (uid, gid) != (euid, egid):
            out.append(f"{rel}: owner {uid}:{gid} != {euid}:{egid}")
        if size != len(data) or digest != hashlib.sha256(data).hexdigest():
            out.append(f"{rel}: content differs from canonical payload")
    return out


def tree_problems(snap, want, label):
    if snap == want:
        return []
    diff = sorted(k for k in set(snap) | set(want) if snap.get(k) != want.get(k))
    return [f"destination tree != {label} at {[(k, snap.get(k), want.get(k)) for k in diff[:4]]}"]


def _current_umask():
    mask = os.umask(0o022)
    os.umask(mask)
    return mask


def tmp_problem(rel, got, snap, old, plan, euid=None, egid=None, umask=None):
    """None if `got` is a state _apply_op() can leave for temp `rel`, else a reason.

    Lifecycle derived from core/mutation.py::_apply_op (one op, under the lock):
      1. _sweep_stale_dest_tmps removes earlier '.<dest>.*.l5tmp' of this dest;
      2. os.open(tmp, O_CREAT|O_EXCL|O_NOFOLLOW, 0o600): mode 0o600 & ~umask,
         owner euid, group egid (parent's group if the parent is setgid);
      3. copy loop: the bytes are a PREFIX (possibly empty) of the payload;
      4. digest of exactly the copied bytes verified == journal 'new';
      5. fchmod(dst, 0o644 if dest absent else prior_mode & 0o755): only now,
         and only with the COMPLETE payload;
      6. fsync, identity checks, rename tmp -> dest (consumes the name).
    So a temp exists only while its destination still holds the prior bytes.
    `plan`: ordered declared NEW payloads [(rel, obj)]; bytes are derived from it
    with canonical_bytes(), never from the engine's output.
    """
    euid = os.geteuid() if euid is None else euid
    egid = os.getegid() if egid is None else egid
    umask = _current_umask() if umask is None else umask
    mt = _TMP_RE.match(os.path.basename(rel))
    if not mt:
        return "not an install-temp name"
    dest = os.path.join(os.path.dirname(rel), mt.group("dest"))
    order, objs, bad = validate_plan(plan)
    if bad:
        return f"declared plan unusable ({bad[0]})"
    if dest not in objs:
        return f"temp maps to {dest!r}, which is not a declared payload destination"
    if not got or got[0] != "reg":
        return f"temp is not a regular file ({got and got[0]})"
    if len(got) != 8 or got[7] is None:
        return "temp content not captured (oversized or not snapshotted)"
    _t, perm, uid, gid, nlink, size, digest, data = got
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        return "temp content changed while snapshotting"
    if nlink != 1:
        return f"temp nlink {nlink} != 1"
    parent = snap.get(os.path.dirname(rel) or ".")
    want_gid = parent[3] if parent and parent[0] == "dir" and parent[1] & stat.S_ISGID else egid
    if (uid, gid) != (euid, want_gid):
        return f"temp owner {uid}:{gid} != {euid}:{want_gid}"
    prior = old.get(dest)
    if prior is not None and prior[0] != "reg":
        return f"temp for {dest!r} whose prior object is {prior[0]}"
    if snap.get(dest) != prior:
        return f"temp present but {dest!r} no longer holds its prior state (rename consumes the temp)"
    payload = canonical_bytes(objs[dest])
    created = 0o600 & ~umask
    final = DEST_FILE_MODE if prior is None else prior[1] & 0o755
    if perm == final and data == payload:
        return None
    if perm == created and payload.startswith(data):
        return None
    if perm == final:
        return (f"temp mode {oct(perm)} (set only after the full digest-verified copy) "
                f"but content is not the complete payload ({len(data)}/{len(payload)} bytes)")
    if perm == created:
        return f"temp mode {oct(perm)} with bytes that are not a prefix of the payload for {dest!r}"
    return f"temp mode {oct(perm)} is neither created {oct(created)} nor final {oct(final)}"


def validate_plan(plan):
    """(order, {rel: obj}, problems) for the ordered declared NEW payloads.

    Fail-closed: a missing/empty plan, a malformed entry, an unsafe or
    non-normalized destination path, a non-serializable payload or a duplicate
    destination (exact or case-folded, as commit_batch rejects) is a problem;
    nothing is silently dropped or overwritten (no dict(plan))."""
    if plan is None:
        return [], {}, ["no declared plan"]
    if not isinstance(plan, (list, tuple)) or not plan:
        return [], {}, [f"plan is not a non-empty ordered sequence ({type(plan).__name__})"]
    order, objs, folded, out = [], {}, set(), []
    for n, ent in enumerate(plan):
        if not isinstance(ent, (list, tuple)) or len(ent) != 2:
            out.append(f"plan entry {n} is not a (rel, obj) pair: {ent!r}")
            continue
        rel, obj = ent
        if (not isinstance(rel, str) or not rel or "\0" in rel or os.path.isabs(rel)
                or os.path.normpath(rel) != rel or rel.split(os.sep)[0] in EXCLUDED_TOPS
                or any(c in ("", ".", "..") for c in rel.split(os.sep))):
            out.append(f"plan entry {n}: unsafe or ambiguous destination path {rel!r}")
            continue
        try:
            canonical_bytes(obj)
        except (TypeError, ValueError) as exc:
            out.append(f"plan entry {n} ({rel!r}): payload not canonical JSON ({exc})")
            continue
        if rel in objs or rel.casefold() in folded:
            out.append(f"plan entry {n}: duplicate destination {rel!r}")
            continue
        order.append(rel)
        objs[rel] = obj
        folded.add(rel.casefold())
    return (order, objs, out) if not out else ([], {}, out)


def _applying_tree_problems(snap, old, new, plan=None):
    """APPLYING (pre-recovery, one commit_batch attempt): each payload path OLD or
    NEW; the only extra object allowed is AT MOST ONE install temp.

    Ops run strictly in plan order (commit_batch: `for op in plan: _apply_op`)
    and the first failure stops the loop, so every snapshot is a NEW prefix
    followed by an OLD suffix: an OLD op followed by a NEW op is impossible,
    temp or not. With a temp for op i: ops before i NEW, op i OLD (checked by
    tmp_problem), ops after i OLD. A missing or malformed plan is a problem
    (fail-closed), and then every temp is rejected as well."""
    out, tmps = [], []
    order, _objs, bad = validate_plan(plan)
    out += [f"APPLYING: declared plan rejected: {b}" for b in bad]
    for r in order:
        if r not in new:
            out.append(f"APPLYING: plan destination {r!r} is absent from the NEW reference tree")
    for k in sorted(set(snap) | set(old) | set(new)):
        got = snap.get(k)
        if got is not None and got in (old.get(k), new.get(k)):
            continue
        if got is not None and k not in old and k not in new and _TMP_RE.match(os.path.basename(k)):
            why = tmp_problem(k, got, snap, old, plan)
            if why is None:
                tmps.append(k)
                continue
            out.append(f"APPLYING temp {k!r} rejected: {why}")
            continue
        out.append(f"APPLYING destination {k!r} is {got} (neither OLD {old.get(k)} nor NEW {new.get(k)})")
    if len(tmps) > 1:
        out.append(f"APPLYING: {len(tmps)} install temps {tmps}; one commit attempt leaves at most one")
    elif tmps:
        # Self-contained guard: do not rely on tmp_problem() having rejected an
        # invalid plan or an undeclared destination before indexing the order.
        mt = _TMP_RE.match(os.path.basename(tmps[0]))
        dest = os.path.join(os.path.dirname(tmps[0]), mt.group("dest")) if mt else None
        if bad or not order:
            out.append(f"APPLYING temp {tmps[0]!r} rejected: no valid declared plan")
        elif dest is None or dest not in order:
            out.append(f"APPLYING temp {tmps[0]!r} rejected: maps to {dest!r}, not in the declared plan")
        else:
            i = order.index(dest)
            for j, r in enumerate(order):
                want, label = (new, "NEW") if j < i else (old, "OLD")
                if snap.get(r) != want.get(r):
                    out.append(f"APPLYING: temp for op {i} ({order[i]!r}) but op {j} ({r!r}) is not {label}")
    elif order:
        # no temp: NEW prefix / OLD suffix. An op whose OLD and NEW entries are
        # identical is compatible with both and constrains nothing.
        first_old = None
        for j, r in enumerate(order):
            is_old, is_new = snap.get(r) == old.get(r), snap.get(r) == new.get(r)
            if is_old and not is_new and first_old is None:
                first_old = j
            elif is_new and not is_old and first_old is not None:
                out.append(f"APPLYING: op {j} ({r!r}) is NEW but earlier op {first_old} "
                           f"({order[first_old]!r}) is OLD; ops apply in plan order")
    return out


def classify_pre(st, snap, staging, base, journal=None):
    """Classify the state observed right after the fault.

    st: parsed state.json (or None); snap: snapshot(); staging: list of names in
    .staging; base: {"N", "L", "store_id", "old", "new"}; journal: (raw bytes or
    None) of .staging/<batch>/journal.v3.json when present.
    Returns (class, problems). Raises Unknown for states with no defined expectation.
    """
    N, L = base["N"], base["L"]
    if st is None:
        return None, ["protected state missing after commit of an initialized store"]
    probs = []
    if st.get("store_id") != base["store_id"]:
        probs.append("store_id changed")
    phase, txn, ns, lf = st.get("phase"), st.get("txn"), st.get("next_seq"), st.get("last_finalized_seq")
    if phase == "QUARANTINED":
        raise Unknown(f"QUARANTINED pre-recovery state (txn {txn}) has no expectation in the commit sweep")
    if phase == "IDLE":
        if txn is not None:
            return None, probs + ["IDLE carries a txn"]
        if (ns, lf) == (N, L):
            cls = "NOT_ALLOCATED"
        elif (ns, lf) == (N + 1, N):
            cls = "COMPLETED"
        else:
            return None, probs + [f"impossible IDLE counters next_seq={ns} lf={lf} (N={N}, L={L})"]
        if staging:
            probs.append(f"{cls}: staging not empty {staging}")
    else:
        want_lf = {"PREPARED": L, "COMMIT_POINT": L, "APPLYING": L, "FINALIZED": N, "CLEANUP": N}.get(phase)
        if want_lf is None:
            return None, probs + [f"unknown phase {phase!r}"]
        cls = phase
        if not isinstance(txn, dict):
            return None, probs + [f"{phase} without txn"]
        if ns != N + 1:
            probs.append(f"{phase}: next_seq {ns} != {N + 1}")
        if lf != want_lf:
            probs.append(f"{phase}: last_finalized_seq {lf} != {want_lf}")
        if txn.get("seq") != N:
            probs.append(f"{phase}: txn seq {txn.get('seq')} != allocated {N}")
        if txn.get("quarantine_id") is not None:
            probs.append(f"{phase}: txn carries quarantine id")
        bound = txn.get("journal_sha256") is not None
        if bound != (phase != "PREPARED"):
            probs.append(f"{phase}: journal binding {'present' if bound else 'absent'}")
        extra = [e for e in staging if e != txn.get("batch_name")]
        if extra:
            probs.append(f"{phase}: foreign staging entries {extra}")
        if phase in ("COMMIT_POINT", "APPLYING"):
            if txn.get("batch_name") not in staging:
                probs.append(f"{phase}: committed batch directory missing")
            elif journal is None:
                probs.append(f"{phase}: committed journal missing")
            else:
                if hashlib.sha256(journal).hexdigest() != txn.get("journal_sha256"):
                    probs.append(f"{phase}: journal digest != bound digest")
                try:
                    j = json.loads(journal)
                    dests = sorted("/".join(op["dest"]) for op in j["ops"])
                    if j.get("seq") != N or dests != sorted(base["new_payloads"]):
                        probs.append(f"{phase}: journal seq/ops do not describe this commit")
                except (ValueError, KeyError, TypeError) as exc:
                    probs.append(f"{phase}: journal unparsable ({exc})")
    if cls in ("NOT_ALLOCATED", "PREPARED", "COMMIT_POINT"):
        probs += tree_problems(snap, base["old"], f"OLD ({cls}: destinations must be untouched)")
    elif cls == "APPLYING":
        probs += _applying_tree_problems(snap, base["old"], base["new"], base.get("new_payload_objs"))
    else:
        probs += tree_problems(snap, base["new"], f"NEW ({cls})")
    return cls, probs


def expected_final(cls, base):
    if cls not in PRE_CLASSES:
        raise Unknown(f"no expectation for class {cls!r}")
    if cls in COMMIT_POINT_REACHED:
        return {"result": "NEW", "next_seq": base["N"] + 1, "last_finalized_seq": base["N"]}
    return {"result": "OLD", "next_seq": base["N"] + (cls == "PREPARED"), "last_finalized_seq": base["L"]}


def binding_problems(st, snap, base):
    """Class-independent F-NEW-01 binding: the final tree decides the only valid lf."""
    out = []
    lf, ns = st.get("last_finalized_seq"), st.get("next_seq")
    if snap == base["old"]:
        if lf != base["L"]:
            out.append(f"OLD destination with last_finalized_seq {lf} != {base['L']} (finalization advanced)")
        if ns not in (base["N"], base["N"] + 1):
            out.append(f"OLD destination with next_seq {ns} not in {{{base['N']},{base['N'] + 1}}}")
    elif snap == base["new"]:
        if lf != base["N"]:
            out.append(f"NEW destination with last_finalized_seq {lf} != committed seq {base['N']}")
        if ns != base["N"] + 1:
            out.append(f"NEW destination with next_seq {ns} != {base['N'] + 1}")
    return out


def check_post(cls, st, snap, staging, unresolved, outcomes, base, payload_sets):
    """Problems after the repeated recoveries. payload_sets: {"OLD": [...], "NEW": [...]}."""
    exp = expected_final(cls, base)
    out = []
    if any(o != "ok" for o in outcomes):
        out.append(f"recoveries {outcomes}")
    if st.get("phase") != "IDLE" or st.get("txn") is not None:
        out.append(f"phase {st.get('phase')} txn {st.get('txn')}")
    if st.get("store_id") != base["store_id"]:
        out.append("store_id changed")
    if staging or unresolved:
        out.append(f"residue staging={staging} quarantine={unresolved}")
    if not (isinstance(st.get("last_finalized_seq"), int) and isinstance(st.get("next_seq"), int)
            and st["last_finalized_seq"] < st["next_seq"]):
        out.append("last_finalized_seq >= next_seq")
    for key in ("next_seq", "last_finalized_seq"):
        if st.get(key) != exp[key]:
            out.append(f"{cls}: {key} {st.get(key)} != {exp[key]}")
    want = base["old"] if exp["result"] == "OLD" else base["new"]
    out += tree_problems(snap, want, f"{exp['result']} (from {cls})")
    out += policy_problems(snap, payload_sets[exp["result"]])
    out += binding_problems(st, snap, base)
    return exp["result"], out
