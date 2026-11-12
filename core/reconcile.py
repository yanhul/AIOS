"""AIOS state reconciliation and snapshot-status reader (M2).

DETECTION ONLY. This module never repairs, never writes, never deletes.
Repair of semantic corruption is a separate responsibility (none exists
in M2 by design).

Severity model (overall = worst finding):
    VALID        no findings
    PENDING      a transaction is staged/journaled but not yet resolved
    UNSUPPORTED  content with an unrecognized schema/kind (detectably foreign)
    INCONSISTENT detectable violation of the entity<->event pairing model
    CORRUPTED    content contradicts its own committed identity/digest

What this does NOT claim: protection against arbitrary filesystem
tampering outside the managed trees; cryptographic-level guarantees;
detection of tamper that preserves all pairing fields AND digests.

Filesystem access: every read of the state tree goes through
core.secure_fs (descriptor-relative, no-follow, fstat-verified, owner/mode
checked, never creating anything). Symlinks, dangling symlinks, FIFOs,
sockets, devices and wrongly-typed entries are REPORTED (CORRUPTED), never
followed or read. Journal ``dest``/``tmp`` paths are confined to the state
root lexically before any (secure) existence probe. The sweep holds the
mutation lock in SHARED mode, acquired BEFORE the root is listed, so it does
not interleave with a commit or recovery holding it exclusively. Results
carry ``synchronized``: True only if the shared lock was held for the whole
observation window. A missing lock file (existing root) yields a PENDING
``G.unsynchronized_sweep`` finding, never a clean VALID.

Snapshot status semantics (Phase 1):
    COMMITTED  a successful mutation transaction emitted its paired
               ``snapshot.created`` notice for this snapshot_id
    OBSERVED   source observation only; no successful commit ties to it
    CORRUPTED  meta.json missing/unreadable/inconsistent
Snapshots are never rewritten; commitment is derived from the audit log.
"""

import hashlib
import json
import os
import stat

from .importer import import_entities
from .mutation import (
    MutationError, _SharedReadLock, _safe_commit_destination, canonical_json,
    validate_entity,
)
from .secure_fs import (
    SecureWriteError, secure_listdir_beneath, secure_lstat_beneath,
    secure_read_bytes_beneath,
)
from .verification import (
    AUTHORITY as VERIFICATION_AUTHORITY,
    OUTCOME_UNSUPPORTED,
    OUTCOME_VERIFIED,
    verification_identity,
)

SEVERITY_ORDER = ["VALID", "PENDING", "UNSUPPORTED", "INCONSISTENT", "CORRUPTED"]

_ENTITY_DIRS = {
    "REQUIREMENT": "requirements",
    "DECISION": "decisions",
    "EVIDENCE": "evidence",
    "ISSUE": "issues",
    "GATE": "issues",
    "CONTRADICTION": "issues",
}
_MANAGED_DIRS = set(_ENTITY_DIRS.values()) | {
    "tasks", "verifications", "snapshots", "events",
    "memory",  # WalStateStore.for_aios_dir (governed memory WAL/snapshots)
}
_KNOWN_EVENT_ACTIONS = {"entity.imported", "verification.recorded"}


def _read_json(aios_dir, rel):
    """(obj, None) or (None, reason). Never follows symlinks / special files."""
    try:
        raw = secure_read_bytes_beneath(aios_dir, rel)
    except FileNotFoundError:
        return None, "missing"
    except SecureWriteError as exc:
        return None, f"unsafe: {exc}"
    except OSError as exc:
        return None, f"unreadable: {exc}"
    try:
        return json.loads(raw.decode("utf-8")), None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"unreadable: {exc}"


def _entry(aios_dir, rel):
    """No-follow classification: ("missing"|"dir"|"file"|"unsafe", detail, st)."""
    try:
        st = secure_lstat_beneath(aios_dir, rel)
    except (OSError, SecureWriteError) as exc:
        return "unsafe", f"unsafe parent: {exc}", None
    if st is None:
        return "missing", None, None
    mode = st.st_mode
    if stat.S_ISDIR(mode):
        return "dir", None, st
    if stat.S_ISREG(mode):
        return "file", None, st
    if stat.S_ISLNK(mode):
        return "unsafe", "symlink", st
    return "unsafe", "special file", st


def _list_names(aios_dir, rel):
    """(sorted names, None); (None, None) if missing; (None, reason) if unsafe."""
    kind, detail, _ = _entry(aios_dir, rel)
    if kind == "missing":
        return None, None
    if kind != "dir":
        return None, detail or f"{kind} where a directory is required"
    try:
        return secure_listdir_beneath(aios_dir, rel), None
    except FileNotFoundError:
        return None, None
    except (OSError, SecureWriteError) as exc:
        return None, f"unsafe: {exc}"


def _journal_rel(aios_dir, op, rel_key, abs_key):
    """Confine a journal path to the state root (same rule as recovery)."""
    rel = op.get(rel_key)
    if not rel:
        absolute = op.get(abs_key)
        if not isinstance(absolute, str) or not absolute:
            return None
        try:
            rel = os.path.relpath(absolute, os.path.abspath(os.fspath(aios_dir)))
        except ValueError:
            return None
        rel = rel.replace(os.sep, "/")
    try:
        _safe_commit_destination(aios_dir, rel)
    except MutationError:
        return None
    return rel.replace("\\", "/")


def _event_identity_ok(ev, filename):
    logical = {k: v for k, v in ev.items()
               if k not in ("timestamp_utc", "event_id")}
    from .mutation import event_identity
    expected = event_identity(logical)
    if ev.get("event_id") != expected:
        return False, f"stored event_id != recomputed ({filename})"
    if not filename.endswith(f"-{expected}.json"):
        return False, f"filename suffix != event_id ({filename})"
    return True, None


def snapshot_status(aios_dir, snapshot_id):
    """Return (status, detail) where status is COMMITTED / OBSERVED /
    CORRUPTED."""
    if (not isinstance(snapshot_id, str) or not snapshot_id or "/" in snapshot_id
            or "\\" in snapshot_id or snapshot_id in (".", "..")):
        return "CORRUPTED", "invalid snapshot_id"
    meta, err = _read_json(aios_dir, f"snapshots/{snapshot_id}/meta.json")
    if meta is None:
        return "CORRUPTED", f"meta.json {err}"
    if not isinstance(meta, dict) or meta.get("snapshot_id") != snapshot_id:
        return "CORRUPTED", "meta.snapshot_id mismatch"
    names, err = _list_names(aios_dir, "events")
    if err is not None:
        return "CORRUPTED", f"events/ {err}"
    for fn in names or ():
        if not fn.endswith(".json"):
            continue
        ev, err = _read_json(aios_dir, f"events/{fn}")
        if not isinstance(ev, dict) or ev.get("kind") != "notice":
            continue
        if (ev.get("type") == "snapshot.created"
                and ev.get("snapshot_id") == snapshot_id):
            return "COMMITTED", fn
    return "OBSERVED", "no successful commit notice references this snapshot"


def _divergence_projection(ent):
    """Canonical content projection used for source/store comparison.

    Deliberately excludes positional/volatile provenance (``source_line``,
    ``imported_at``, ``snapshot_id``, redundant ``classification``): a
    register row that moved or was re-imported later is not content
    divergence. Comparison digests are full SHA-256 over the canonical JSON
    of this projection (reuse of the kernel's serializer; no second one).
    """
    return {
        "entity_type": ent["entity_type"],
        "entity_id": ent["entity_id"],
        "statement": ent["statement"],
        "status": ent["status"],
        "source_file": ent["source_file"],
        "source_text": ent["source_text"],
    }


def _projection_digest(ent):
    return hashlib.sha256(
        canonical_json(_divergence_projection(ent)).encode("utf-8")).hexdigest()


def _check_source_divergence(aios_dir, source_root, store, add):
    """M3: detect source/store divergence. Detection only — zero writes."""
    derived = import_entities(source_root, snapshot_id="source-divergence")
    source_groups = {}
    for ent in derived:
        key = (ent["entity_type"], ent["entity_id"])
        source_groups.setdefault(key, set()).add(_projection_digest(ent))

    ambiguous, source_digests = [], {}
    for key in sorted(source_groups):
        variants = sorted(source_groups[key])
        if len(variants) > 1:
            ambiguous.append((key, variants))
        else:
            source_digests[key] = variants[0]

    for key, variants in ambiguous:
        add("H.source_divergence.ambiguous", "INCONSISTENT",
            f"{key[0]} {key[1]}: {len(variants)} conflicting source "
            f"variants ({', '.join(variants[:4])}); excluded from "
            f"added/changed/missing comparison")

    for key in sorted(set(source_digests) | set(store)):
        etype, eid = key
        src = source_digests.get(key)
        st = None
        if key in store:
            st = _projection_digest(store[key])
        if src is not None and st is None:
            add(f"H.source_divergence.added", "INCONSISTENT",
                f"{etype} {eid}: kind=added; source_digest={src}; "
                f"store=absent")
        elif src is None and st is not None:
            add("H.source_divergence.missing", "INCONSISTENT",
                f"{etype} {eid}: kind=missing; source=absent; "
                f"store_digest={st}")
        elif src is not None and st is not None and src != st:
            add("H.source_divergence.changed", "INCONSISTENT",
                f"{etype} {eid}: kind=changed; source_digest={src}; "
                f"store_digest={st}")


def reconcile(aios_dir, source_root=None):
    """Full read-only consistency sweep. Returns:
        {"overall": <worst severity>, "findings": [{check, severity, detail}]}

    With ``source_root=None`` only internal AIOS consistency is checked.
    When ``source_root`` is supplied, the existing read-only import pipeline
    re-derives entities from the source tree and reports store/source
    divergence as detection-only findings (``H.source_divergence.*``).
    Neither side is ever mutated and no audit event is created for
    divergence: refresh remains an explicit human-reviewed workflow.
    """
    findings = []

    def add(check, severity, detail):
        findings.append({"check": check, "severity": severity,
                         "detail": detail})

    # Lock ordering: acquire the shared mutation lock FIRST, then list the
    # root, so the listing and the whole sweep are one locked observation
    # window (no stale pre-lock listing).
    synchronized = False
    lock_error = None
    try:
        lock = _SharedReadLock(aios_dir)
        lock.__enter__()
    except MutationError as exc:
        lock, lock_error = None, exc
    try:
        if lock is not None and lock.held:
            synchronized = True
        try:
            root_names = secure_listdir_beneath(aios_dir, None)
        except FileNotFoundError:
            root_names = None
        except (OSError, SecureWriteError) as exc:
            add("G.unsafe_root", "CORRUPTED",
                f"refusing unsafe AIOS state root {aios_dir}: {exc}")
            return _summarize(findings, False)
        if lock_error is not None:
            add("G.unsafe_lock", "CORRUPTED",
                f"refusing unsafe .mutation.lock (sweep ran unlocked): "
                f"{lock_error.__cause__ or lock_error}")
        if lock is not None and not lock.held and root_names is not None:
            # No lock file: a concurrent mutation is NOT excluded, so a clean
            # sweep cannot be reported as a synchronized VALID result.
            add("G.unsynchronized_sweep", "PENDING",
                "no .mutation.lock under the state root; sweep could not be "
                "synchronized with mutation/recovery (result incomplete)")
        _sweep(aios_dir, source_root, root_names, add)
    finally:
        if lock is not None:
            lock.__exit__(None, None, None)
    return _summarize(findings, synchronized)


def _summarize(findings, synchronized):
    overall = "VALID"
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    for f in findings:
        if rank[f["severity"]] > rank[overall]:
            overall = f["severity"]
    return {"overall": overall, "findings": findings, "synchronized": synchronized}


def _sweep(aios_dir, source_root, root_names, add):
    listing_cache = {}

    def list_managed(dirname):
        if dirname not in listing_cache:
            names, err = _list_names(aios_dir, dirname)
            if err is not None:
                add("G.unsafe_entry", "CORRUPTED",
                    f"refusing unsafe managed directory {dirname}/: {err}")
            listing_cache[dirname] = names
        return listing_cache[dirname]

    # ---- governed memory WAL integrity ------------------------------------
    wal_rel = "memory/state.json.wal.jsonl"
    try:
        wal_raw = secure_read_bytes_beneath(aios_dir, wal_rel)
    except FileNotFoundError:
        wal_raw = None
    except (OSError, SecureWriteError) as exc:
        add("M.memory_wal.unsafe", "CORRUPTED", f"{wal_rel}: {exc}")
        wal_raw = None
    if wal_raw is not None:
        try:
            from .durable_wal import DurableTransitionLog
            from .governed_memory import _validate_persisted_memory_envelope
            wal = DurableTransitionLog(os.path.join(aios_dir, wal_rel), root=aios_dir)
            replay, _ = wal._parse(wal_raw)
            memory_items = []
            for row in replay.records:
                payload = row.get("payload", {})
                if payload.get("namespace") != "memory":
                    continue
                if row.get("transition") == "NAMESPACE_COMMITTED":
                    value = payload.get("value")
                    if not isinstance(value, list):
                        raise ValueError("memory namespace commit is not a list")
                    memory_items = value
                elif row.get("transition") == "NAMESPACE_APPENDED":
                    memory_items.append(payload.get("item"))
            seen_ids = set()
            for item in memory_items:
                if not isinstance(item, dict):
                    raise ValueError("memory WAL item is not an object")
                mutation_id = item.get("mutation_id")
                if not isinstance(mutation_id, str) or not mutation_id or mutation_id in seen_ids:
                    raise ValueError("missing or duplicate memory mutation_id")
                seen_ids.add(mutation_id)
                _validate_persisted_memory_envelope(aios_dir, item)
        except Exception as exc:
            add("M.memory_wal.integrity", "CORRUPTED",
                f"{wal_rel}: memory WAL/authority validation failed: {exc}")

    # ---- load entities -----------------------------------------------------
    entities = {}          # (type,id) -> ent
    entity_paths = {}      # key -> relpath
    for etype, dirname in _ENTITY_DIRS.items():
        d = os.path.join(aios_dir, dirname)
        names = list_managed(dirname)
        if names is None:
            continue
        for fn in names:
            path = os.path.join(d, fn)
            if not fn.endswith(".json"):
                add("G.unexpected_file", "INCONSISTENT",
                    f"non-JSON file in managed dir: {path}")
                continue
            obj, err = _read_json(aios_dir, f"{dirname}/{fn}")
            if obj is None:
                add("D.corrupt_file", "CORRUPTED", f"{path}: {err}")
                continue
            try:
                validate_entity(obj)
            except Exception as exc:
                add("G.unsupported_schema", "UNSUPPORTED",
                    f"{path}: not a valid entity per contract: {exc}")
                continue
            key = (obj["entity_type"], obj["entity_id"])
            if key in entities:
                add("G.duplicate_entity", "INCONSISTENT",
                    f"{key} present more than once ({path})")
            entities[key] = obj
            entity_paths[key] = path

    # ---- load verifications -------------------------------------------------
    verifications = {}
    vdir = os.path.join(aios_dir, "verifications")
    for fn in list_managed("verifications") or ():
        path = os.path.join(vdir, fn)
        if not fn.endswith(".json"):
            add("G.unexpected_file", "INCONSISTENT",
                f"non-JSON file in verifications/: {path}")
            continue
        rec, err = _read_json(aios_dir, f"verifications/{fn}")
        if rec is None or not isinstance(rec, dict):
            err = err or "not a JSON object"
            add("D.corrupt_file", "CORRUPTED", f"{path}: {err}")
            continue
        problems = []
        for field in ("record_type", "verification_id", "subject_type",
                      "subject_id", "outcome", "evidence_refs",
                      "verifier", "authority", "identity"):
            if field not in rec:
                problems.append(f"missing {field}")
        if rec.get("record_type") != "VERIFICATION":
            problems.append("record_type != VERIFICATION")
        if rec.get("authority") != VERIFICATION_AUTHORITY:
            problems.append(f"authority != {VERIFICATION_AUTHORITY}")
        if rec.get("outcome") not in (OUTCOME_VERIFIED, OUTCOME_UNSUPPORTED):
            problems.append(f"illegal outcome {rec.get('outcome')!r}")
        if rec.get("outcome") == OUTCOME_VERIFIED and not rec.get("evidence_refs"):
            problems.append("VERIFIED without evidence refs")
        if not problems:
            expect = verification_identity(rec)
            if expect != rec.get("identity"):
                problems.append("identity digest mismatch")
        if problems:
            add("D.corrupt_verification", "CORRUPTED",
                f"{path}: {'; '.join(problems)}")
            continue
        verifications[rec["verification_id"]] = rec

    # ---- load events --------------------------------------------------------
    events = []
    edir = os.path.join(aios_dir, "events")
    for fn in list_managed("events") or ():
        path = os.path.join(edir, fn)
        if not fn.endswith(".json"):
            add("G.unexpected_file", "INCONSISTENT",
                f"non-JSON file in events/: {path}")
            continue
        ev, err = _read_json(aios_dir, f"events/{fn}")
        if ev is None or not isinstance(ev, dict):
            err = err or "not a JSON object"
            add("D.corrupt_event", "CORRUPTED", f"{fn}: {err}")
            continue
        ok, why = _event_identity_ok(ev, fn)
        if not ok:
            add("D.event_digest", "CORRUPTED", why)
            continue
        kind = ev.get("kind")
        action = ev.get("action") or ev.get("type")
        if kind == "notice":
            pass
        elif kind == "mutation" and action in _KNOWN_EVENT_ACTIONS:
            events.append((fn, ev))
        else:
            add("G.unsupported_event", "UNSUPPORTED",
                f"{fn}: unknown kind/action {kind!r}/{action!r}")

    # ---- A/B/C: pairing across both families --------------------------------
    def pair(keys_from_events, keys_from_store, label_a, label_b,
             field_cmp=None):
        for key in keys_from_events - keys_from_store:
            add(label_b, "INCONSISTENT",
                f"{label_b.split('.')[1]} without store record: {key}")
        for key in keys_from_store - keys_from_events:
            add(label_a, "INCONSISTENT",
                f"{label_a.split('.')[1]} without audit event: {key}")

    ent_by_event, evt_keys = {}, set()
    for fn, ev in events:
        if ev.get("action") == "entity.imported":
            key = (ev.get("entity_type"), ev.get("entity_id"))
            evt_keys.add(key)
            ent_by_event[key] = (fn, ev)
    pair(set(ent_by_event), set(entities), "A.entity_without_event",
         "B.event_without_entity")
    for key, (fn, ev) in ent_by_event.items():
        ent = entities.get(key)
        if ent is None:
            continue
        for field in ("status", "statement", "source_file", "source_line",
                      "snapshot_id"):
            if ev.get(field) != ent.get(field):
                add("C.pairing_mismatch", "INCONSISTENT",
                    f"{key}: event[{fn}].{field}={ev.get(field)!r} != "
                    f"entity.{field}={ent.get(field)!r}")

    ver_evt = {}
    for fn, ev in events:
        if ev.get("action") == "verification.recorded":
            vid = ev.get("verification_id")
            ver_evt[vid] = (fn, ev)
    pair(set(ver_evt), set(verifications), "A.entity_without_event",
         "B.event_without_entity")
    for vid, (fn, ev) in ver_evt.items():
        rec = verifications.get(vid)
        if rec is None:
            continue
        for field in ("outcome", "subject_type", "subject_id", "evidence_refs"):
            if ev.get(field) != rec.get(field):
                add("C.pairing_mismatch", "INCONSISTENT",
                    f"verification {vid}: event[{fn}].{field} != record.{field}")

    # ---- E: committed snapshots must reference committed store --------------
    for entry in list_managed("snapshots") or ():
        kind, _, _ = _entry(aios_dir, f"snapshots/{entry}")
        if not entry.startswith("SNAP-") or kind != "dir":
            add("G.unexpected_file", "INCONSISTENT",
                f"unexpected entry in snapshots/: {entry}")
            continue
        status, detail = snapshot_status(aios_dir, entry)
        if status == "CORRUPTED":
            add("E.snapshot_corrupt", "CORRUPTED", f"{entry}: {detail}")
            continue
        ents_json, err = _read_json(aios_dir, f"snapshots/{entry}/entities.json")
        if ents_json is None or not isinstance(ents_json, dict):
            add("E.snapshot_corrupt", "CORRUPTED",
                f"{entry}/entities.json: {err or 'not a JSON object'}")
            continue
        if status != "COMMITTED":
            # An OBSERVED snapshot makes no commitment claims; nothing
            # to check beyond readability. Its presence is recorded.
            continue
        for ent in ents_json.get("entities", []):
            if not isinstance(ent, dict):
                add("E.snapshot_corrupt", "CORRUPTED",
                    f"{entry}/entities.json: non-object entity")
                continue
            key = (ent.get("entity_type"), ent.get("entity_id"))
            store_ent = entities.get(key)
            if store_ent is None:
                add("E.committed_snapshot_missing_entity", "INCONSISTENT",
                    f"{entry} committed but {key} absent from store")
            elif store_ent.get("snapshot_id") != ent.get("snapshot_id"):
                add("E.committed_snapshot_provenance_mismatch",
                    "INCONSISTENT",
                    f"{entry}: {key} snapshot_id differs from store")

    # ---- F: staging / journals ----------------------------------------------
    staging = os.path.join(aios_dir, ".staging")
    for entry in list_managed(".staging") or ():
        journal = os.path.join(staging, entry, "journal.json")
        bkind, bdetail, _ = _entry(aios_dir, f".staging/{entry}")
        if bkind != "dir":
            add("F.corrupt_journal", "CORRUPTED",
                f"unsafe staging entry {entry}: {bdetail or bkind}")
            continue
        jkind, jdetail, _ = _entry(aios_dir, f".staging/{entry}/journal.json")
        if jkind == "missing":
            add("F.orphan_staging", "INCONSISTENT",
                f"staging batch without journal: {entry}")
            continue
        if jkind != "file":
            add("F.corrupt_journal", "CORRUPTED",
                f"{journal}: refusing unsafe journal ({jdetail or jkind})")
            continue
        jdata, err = _read_json(aios_dir, f".staging/{entry}/journal.json")
        if jdata is None:
            add("F.corrupt_journal", "CORRUPTED", f"{journal}: {err}")
            continue
        ops = jdata.get("ops", []) if isinstance(jdata, dict) else None
        if not isinstance(ops, list):
            add("F.corrupt_journal", "CORRUPTED", f"{journal}: malformed ops")
            continue
        unresolved_ops = 0
        for op in ops:
            if not isinstance(op, dict):
                add("F.corrupt_journal", "CORRUPTED",
                    f"{journal}: malformed journal operation")
                continue
            rel_dest = _journal_rel(aios_dir, op, "rel_dest", "dest")
            tmp_rel = _journal_rel(aios_dir, op, "tmp_rel", "tmp")
            if rel_dest is None or tmp_rel is None:
                add("F.corrupt_journal", "CORRUPTED",
                    f"journal op path missing or outside AIOS state root: "
                    f"{op.get('dest')!r}")
                continue
            dkind, ddetail, _ = _entry(aios_dir, rel_dest)
            tkind, tdetail, _ = _entry(aios_dir, tmp_rel)
            unsafe = [(r, k, d) for r, k, d in ((rel_dest, dkind, ddetail), (tmp_rel, tkind, tdetail))
                      if k not in ("missing", "file")]
            if unsafe:
                add("F.corrupt_journal", "CORRUPTED",
                    "journal op refers to unsafe entry: " + ", ".join(
                        f"{r} ({d or k})" for r, k, d in unsafe))
                continue
            dest_exists = dkind == "file"
            tmp_exists = tkind == "file"
            if dest_exists and tmp_exists:
                unresolved_ops += 1  # replace succeeded? temps linger: odd
            elif not dest_exists and not tmp_exists:
                add("F.corrupt_journal", "CORRUPTED",
                    f"journal op has neither temp nor dest: {op.get('dest')}")
        add("F.pending_transaction", "PENDING",
            f"unresolved journaled batch: {entry} "
            f"({len(ops)} ops, {unresolved_ops} ambiguous)")

    # ---- G: unexpected top-level entries ------------------------------------
    for entry in root_names or ():
        kind, detail, st = _entry(aios_dir, entry)
        if entry == ".mutation.lock":
            if kind == "file" and st.st_nlink == 1:
                continue  # operational mutation lock (core.mutation._MutationLock)
            add("G.unsafe_entry", "CORRUPTED",
                f"refusing unsafe .mutation.lock ({detail or kind}"
                f"{', hard-linked' if kind == 'file' else ''})")
            continue
        if entry not in _MANAGED_DIRS and entry != ".staging":
            add("G.unexpected_entry", "UNSUPPORTED",
                f"unrecognized entry under .aios/: {entry}")
        elif kind != "dir":
            add("G.unsafe_entry", "CORRUPTED",
                f"managed entry {entry} is not a real directory ({detail or kind})")

    # ---- H: source/store divergence (M3, detection only) --------------------
    if source_root is not None:
        _check_source_divergence(aios_dir, source_root, entities, add)
