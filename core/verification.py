"""AIOS-native verification records (M2).

A verification record is AIOS's own machine-checkable statement:

    "AIOS verification determined OUTCOME for subject S based on
     evidence refs R, resolved against persisted AIOS state."

It is fundamentally separate from imported RX50 register text:

- An imported entity's ``status`` string (e.g. the literal text "VERIFIED"
  in an RX50 register) is SOURCE data. It is never treated as AIOS
  verification state and never modified by this module.
- The record's ``outcome`` is computed at creation time by resolving
  evidence references against entities actually persisted under
  ``.aios/evidence/`` — independently of the subject. Evidence is never
  inferred from filenames, never copied in, and ``"verified": true``-style
  fields are not trusted.
- Outcome rule: VERIFIED requires at least one evidence reference AND every
  reference resolving to a persisted EVIDENCE entity. Anything else is
  UNSUPPORTED (with unresolved refs listed). A verifier cannot manufacture
  evidence; missing evidence can never yield VERIFIED.

Records are APPEND-ONLY attempts: no transition table exists (Phase 6).
Re-verification creates a new record. Modifying an existing record is
rejected by the shared engine as an undefined transition. Every record is
committed through the single shared atomic kernel (core.mutation.commit_batch)
together with its paired auditable event, so the M1.5 invariants
(actor mandatory, deterministic identity, crash-safe commit, replay
idempotency) hold unchanged.

Stdlib only. Never writes outside ``<aios_dir>``. Never touches RX50.
"""

import datetime
import hashlib
import json
import os

from .mutation import (
    MutationError,
    TransitionError,
    _require_actor,
    canonical_json,
    commit_batch,
    event_identity,
    _load_existing,
    _entity_relpath,
    _require_committed_event as _require_entity_event,
    validate_entity,
)

__all__ = [
    "VerificationError",
    "OUTCOME_VERIFIED",
    "OUTCOME_UNSUPPORTED",
    "AUTHORITY",
    "apply_verification",
    "load_verifications",
]

OUTCOME_VERIFIED = "VERIFIED"
OUTCOME_UNSUPPORTED = "UNSUPPORTED"
AUTHORITY = "AIOS_VERIFICATION"

_VERIFICATION_DIR = "verifications"
_SUBJECT_FAMILIES = {
    "REQUIREMENT", "DECISION", "EVIDENCE", "ISSUE", "GATE", "CONTRADICTION", "OBSERVATION", "CLAIM",
}
_EVIDENCE_ID_PREFIX = "EV-"


class VerificationError(MutationError):
    """Raised when a verification request violates its contract."""


def _validate_refs(evidence_refs):
    if not isinstance(evidence_refs, list):
        raise VerificationError(
            f"evidence_refs must be a list, got {type(evidence_refs).__name__}")
    norm = []
    for pos, ref in enumerate(evidence_refs):
        if (not isinstance(ref, (list, tuple)) or len(ref) != 2
                or not all(isinstance(p, str) for p in ref)):
            raise VerificationError(
                f"evidence_refs[{pos}] must be [family, id] strings")
        family, eid = ref
        if family != "EVIDENCE":
            raise VerificationError(
                f"evidence_refs[{pos}]: family must be 'EVIDENCE', got {family!r}")
        if not eid.startswith(_EVIDENCE_ID_PREFIX) or len(eid) <= len(_EVIDENCE_ID_PREFIX):
            raise VerificationError(
                f"evidence_refs[{pos}]: id {eid!r} is not an EV- id")
        norm.append([family, eid])
    return norm


def resolve_evidence(aios_dir, evidence_refs):
    """Resolve refs by reading persisted EVIDENCE entities from disk.

    Independent of any subject data: resolution reads the evidence store
    directly and trusts nothing but persisted entity files.
    """
    resolved, unresolved = [], []
    evidence_dir = os.path.join(aios_dir, "evidence")
    cache = {}
    seen_ids = set()
    duplicate_ids = set()
    if os.path.isdir(evidence_dir):
        for fn in os.listdir(evidence_dir):
            if not fn.endswith(".json"):
                continue
            try:
                with open(os.path.join(evidence_dir, fn), "r",
                          encoding="utf-8") as fh:
                    ent = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            if ent.get("entity_type") == "EVIDENCE":
                eid = ent.get("entity_id")
                if isinstance(eid, str) and eid in seen_ids:
                    # Any second persisted representation of the same identity
                    # is ambiguous, even when the duplicate is malformed.
                    duplicate_ids.add(eid)
                    cache.pop(eid, None)
                    continue
                if isinstance(eid, str):
                    seen_ids.add(eid)
                try:
                    validate_entity(ent)
                    expected_path = os.path.join(
                        evidence_dir, os.path.basename(_entity_relpath(ent))
                    )
                    actual_path = os.path.join(evidence_dir, fn)
                    if os.path.normcase(os.path.abspath(actual_path)) != os.path.normcase(
                        os.path.abspath(expected_path)
                    ):
                        raise MutationError(
                            f"EVIDENCE {eid} is not stored at its canonical path"
                        )
                    _require_entity_event(aios_dir, ent)
                except (MutationError, OSError, json.JSONDecodeError):
                    # Malformed, forged, relocated, or receipt-less evidence is
                    # never resolvable authority.
                    continue
                cache[eid] = ent

    if duplicate_ids:
        # Ambiguous persisted identity cannot be used as verification evidence.
        unresolved.extend([["EVIDENCE", eid] for eid in sorted(duplicate_ids)])

    for family, eid in evidence_refs:
        if eid in duplicate_ids:
            continue
        ent = cache.get(eid)
        if ent is None:
            unresolved.append([family, eid])
        else:
            resolved.append(ent)
    return resolved, unresolved


def verification_identity(record):
    """Deterministic record identity: SHA-256 over canonical logical fields
    (volatile fields excluded, full digest)."""
    logical = {k: v for k, v in record.items()
               if k not in ("created_at", "identity", "verification_id")}
    return hashlib.sha256(canonical_json(logical).encode("utf-8")).hexdigest()


def _verification_relpath(verification_id):
    return os.path.join(_VERIFICATION_DIR, verification_id + ".json")


def _require_committed_event(aios_dir, record):
    verification_id = record["verification_id"]
    expected_event = {
        "kind": "mutation",
        "action": "verification.recorded",
        "actor": record["verifier"],
        "verification_id": verification_id,
        "record_type": "VERIFICATION",
        "subject_type": record["subject_type"],
        "subject_id": record["subject_id"],
        "outcome": record["outcome"],
        "evidence_refs": record["evidence_refs"],
        "authority": record["authority"],
    }
    expected_event_id = event_identity(expected_event)
    events_dir = os.path.join(aios_dir, "events")
    if os.path.isdir(events_dir):
        for fn in sorted(os.listdir(events_dir)):
            if not fn.endswith(".json"):
                continue
            path = os.path.join(events_dir, fn)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    ev = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            if ev.get("kind") != "mutation" or ev.get("action") != "verification.recorded":
                continue
            if ev.get("verification_id") != verification_id:
                continue
            if ev.get("event_id") != expected_event_id:
                continue
            if os.path.basename(fn) != f"EVT-{fn.split('-', 2)[1]}-{expected_event_id}.json":
                continue
            return
    raise TransitionError(
        f"verification record {verification_id} has no matching integrity-bound "
        f"audit event; state was tampered with or predates M2")


def load_verifications(aios_dir):
    """Load only integrity-bound persisted verification records.

    A verification file is authoritative only when its self-derived identity
    matches verification_id/identity and its paired mutation event still exists.
    Duplicate verification identities fail closed rather than being silently
    overwritten by directory iteration order.
    """
    out = {}
    vdir = os.path.join(aios_dir, _VERIFICATION_DIR)
    if not os.path.isdir(vdir):
        return out

    for fn in sorted(os.listdir(vdir)):
        if not fn.endswith(".json"):
            continue
        path = os.path.join(vdir, fn)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                rec = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise TransitionError(
                f"invalid persisted verification record {fn!r}"
            ) from exc

        if not isinstance(rec, dict):
            raise TransitionError(
                f"invalid persisted verification record {fn!r}: expected object"
            )
        verification_id = rec.get("verification_id")
        identity = rec.get("identity")
        if (not isinstance(verification_id, str)
                or not verification_id.startswith("VF-")
                or not isinstance(identity, str)):
            raise TransitionError(
                f"invalid persisted verification record {fn!r}: missing identity"
            )
        expected_identity = verification_identity(rec)
        if identity != expected_identity or verification_id != "VF-" + expected_identity:
            raise TransitionError(
                f"verification record {verification_id!r} has invalid identity"
            )
        if verification_id in out:
            raise TransitionError(
                f"duplicate persisted verification identity {verification_id!r}"
            )
        _require_committed_event(aios_dir, rec)
        out[verification_id] = rec
    return out


def apply_verification(aios_dir, subject_type, subject_id, evidence_refs,
                       verifier, reason=""):
    """Create one append-only verification attempt, atomically, with its
    paired audit event. Returns the persisted record summary.
    """
    _require_actor(verifier)
    if subject_type not in _SUBJECT_FAMILIES:
        raise VerificationError(
            f"subject_type {subject_type!r} is not an imported entity family")
    if not isinstance(subject_id, str) or not subject_id.strip():
        raise VerificationError("subject_id must be a non-empty string")
    refs = _validate_refs(evidence_refs)
    if not isinstance(reason, str):
        raise VerificationError("reason must be a string")

    resolved, unresolved = resolve_evidence(aios_dir, refs)
    if refs and not unresolved:
        outcome = OUTCOME_VERIFIED
        detail = (f"all {len(refs)} evidence reference(s) resolve to "
                  f"persisted EVIDENCE entities")
    else:
        outcome = OUTCOME_UNSUPPORTED
        if not refs:
            detail = "no evidence references supplied; VERIFIED is impossible"
        else:
            detail = f"unresolved evidence references: {unresolved}"
    if reason:
        detail = f"{detail}; reason: {reason}"

    record = {
        "record_type": "VERIFICATION",
        "subject_type": subject_type,
        "subject_id": subject_id,
        "evidence_refs": refs,
        "resolved_evidence_ids": [ent["entity_id"] for ent in resolved],
        "unresolved_refs": unresolved,
        "outcome": outcome,
        "detail": detail,
        "verifier": verifier,
        "authority": AUTHORITY,
    }
    identity = verification_identity(record)
    record["verification_id"] = "VF-" + identity
    record["identity"] = identity

    dest = os.path.join(aios_dir, _verification_relpath(record["verification_id"]))
    if os.path.exists(dest):
        existing = _load_existing(dest)
        if canonical_json(existing) == canonical_json(record):
            _require_committed_event(aios_dir, record)
            return {"outcome": outcome, "verification_id": record["verification_id"],
                    "replayed": True, "event_file": None}
        raise TransitionError(
            f"undefined transition for verification {record['verification_id']}: "
            f"an attempt record with this identity already exists with "
            f"different content. Verification records are append-only; "
            f"issue a new attempt instead.")

    event = {
        "kind": "mutation",
        "action": "verification.recorded",
        "actor": verifier,
        "verification_id": record["verification_id"],
        "record_type": "VERIFICATION",
        "subject_type": subject_type,
        "subject_id": subject_id,
        "outcome": outcome,
        "evidence_refs": refs,
        "authority": AUTHORITY,
    }
    rel_event = os.path.join(
        "events",
        "EVT-%s-%s.json" % (
            datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
            event_identity(event)))
    commit_batch(aios_dir, [
        (_verification_relpath(record["verification_id"]), record),
        (rel_event, {**event, "timestamp_utc": datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_id": event_identity(event)}),
    ])
    return {"outcome": outcome, "verification_id": record["verification_id"],
            "replayed": False, "event_file": os.path.basename(rel_event)}
