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

from .importer import import_entities
from .mutation import canonical_json, validate_entity
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
}
_KNOWN_EVENT_ACTIONS = {"entity.imported", "verification.recorded"}


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh), None
    except FileNotFoundError:
        return None, "missing"
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"unreadable: {exc}"


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
    meta_path = os.path.join(aios_dir, "snapshots", snapshot_id, "meta.json")
    meta, err = _read_json(meta_path)
    if meta is None:
        return "CORRUPTED", f"meta.json {err}"
    if meta.get("snapshot_id") != snapshot_id:
        return "CORRUPTED", "meta.snapshot_id mismatch"
    events_dir = os.path.join(aios_dir, "events")
    if os.path.isdir(events_dir):
        for fn in sorted(os.listdir(events_dir)):
            if not fn.endswith(".json"):
                continue
            ev, err = _read_json(os.path.join(events_dir, fn))
            if ev is None or ev.get("kind") != "notice":
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

    # ---- load entities -----------------------------------------------------
    entities = {}          # (type,id) -> ent
    entity_paths = {}      # key -> relpath
    for etype, dirname in _ENTITY_DIRS.items():
        d = os.path.join(aios_dir, dirname)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            path = os.path.join(d, fn)
            if not fn.endswith(".json"):
                add("G.unexpected_file", "INCONSISTENT",
                    f"non-JSON file in managed dir: {path}")
                continue
            obj, err = _read_json(path)
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
    if os.path.isdir(vdir):
        for fn in sorted(os.listdir(vdir)):
            path = os.path.join(vdir, fn)
            if not fn.endswith(".json"):
                add("G.unexpected_file", "INCONSISTENT",
                    f"non-JSON file in verifications/: {path}")
                continue
            rec, err = _read_json(path)
            if rec is None:
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
    if os.path.isdir(edir):
        for fn in sorted(os.listdir(edir)):
            path = os.path.join(edir, fn)
            if not fn.endswith(".json"):
                add("G.unexpected_file", "INCONSISTENT",
                    f"non-JSON file in events/: {path}")
                continue
            ev, err = _read_json(path)
            if ev is None:
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
    snaps_root = os.path.join(aios_dir, "snapshots")
    if os.path.isdir(snaps_root):
        for entry in sorted(os.listdir(snaps_root)):
            spath = os.path.join(snaps_root, entry)
            if not entry.startswith("SNAP-") or not os.path.isdir(spath):
                add("G.unexpected_file", "INCONSISTENT",
                    f"unexpected entry in snapshots/: {entry}")
                continue
            status, detail = snapshot_status(aios_dir, entry)
            if status == "CORRUPTED":
                add("E.snapshot_corrupt", "CORRUPTED", f"{entry}: {detail}")
                continue
            ents_json, err = _read_json(os.path.join(spath, "entities.json"))
            if ents_json is None:
                add("E.snapshot_corrupt", "CORRUPTED",
                    f"{entry}/entities.json: {err}")
                continue
            if status != "COMMITTED":
                # An OBSERVED snapshot makes no commitment claims; nothing
                # to check beyond readability. Its presence is recorded.
                continue
            for ent in ents_json.get("entities", []):
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
    if os.path.isdir(staging):
        for entry in sorted(os.listdir(staging)):
            bdir = os.path.join(staging, entry)
            journal = os.path.join(bdir, "journal.json")
            if not os.path.isfile(journal):
                add("F.orphan_staging", "INCONSISTENT",
                    f"staging batch without journal: {entry}")
                continue
            jdata, err = _read_json(journal)
            if jdata is None:
                add("F.corrupt_journal", "CORRUPTED", f"{journal}: {err}")
                continue
            ops = jdata.get("ops", [])
            unresolved_ops = 0
            for op in ops:
                dest_exists = os.path.exists(op.get("dest", ""))
                tmp_exists = os.path.exists(op.get("tmp", ""))
                if dest_exists and tmp_exists:
                    unresolved_ops += 1  # replace succeeded? temps linger: odd
                elif not dest_exists and not tmp_exists:
                    add("F.corrupt_journal", "CORRUPTED",
                        f"journal op has neither temp nor dest: {op.get('dest')}")
            if err is None:
                add("F.pending_transaction", "PENDING",
                    f"unresolved journaled batch: {entry} "
                    f"({len(ops)} ops, {unresolved_ops} ambiguous)")

    # ---- G: unexpected top-level entries ------------------------------------
    if os.path.isdir(aios_dir):
        for entry in sorted(os.listdir(aios_dir)):
            if entry not in _MANAGED_DIRS and entry != ".staging":
                add("G.unexpected_entry", "UNSUPPORTED",
                    f"unrecognized entry under .aios/: {entry}")

    # ---- H: source/store divergence (M3, detection only) --------------------
    if source_root is not None:
        _check_source_divergence(aios_dir, source_root, entities, add)

    overall = "VALID"
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    for f in findings:
        if rank[f["severity"]] > rank[overall]:
            overall = f["severity"]
    return {"overall": overall, "findings": findings}
