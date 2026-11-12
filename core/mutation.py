"""Authoritative AIOS state mutation boundary (M1.5).

The operational mutation lock is stored alongside the state tree; every AIOS state mutation produced by the application MUST pass through
``apply_mutations``. There is deliberately no other supported way to write
entity or audit-event files.

Enforcement provided by this module (and nothing more):

- Entity contracts: required fields, types, ID formats, structural status
  rules. Unknown entity types and malformed entities fail loudly.
- Transition legality: creation of a new entity is allowed; byte-identical
  replay is allowed; ANY other change to an existing entity is rejected as
  an UNDEFINED transition. This repository contains no evidence defining
  status-transition rules between RX50 statuses (they are free-form prose),
  so none are invented here (see docs/ROADMAP.md M2).
- Actor identity: mandatory, recorded in every event.
- Deterministic event identity: SHA-256 over the canonicalized event values
  (full digest, timestamps excluded from identity).
- Atomicity: staged temp files -> write-ahead journal -> atomic renames ->
  journal removal, with roll-forward recovery (``recover_pending``) invoked
  at the start of every mutation.

Not provided by this module (explicitly out of scope for M1.5): agents,
policy, gates, verification, contradiction resolution, concurrency control
beyond single-process atomic commit, OS-level protection of the RX50 tree.

Stdlib only. Never writes outside ``<aios_dir>``.
"""

import datetime
import hashlib
import json
import os
import re
import shutil
import uuid

from . import state as state_layout
from .secure_fs import (
    SecureWriteError, atomic_write_beneath, secure_makedirs_beneath,
    secure_write_bytes_beneath, secure_read_bytes_beneath,
    secure_exists_beneath, secure_is_dir_beneath, secure_listdir_beneath,
    secure_unlink_beneath, secure_rmtree_beneath, secure_open_lock_beneath,
)

__all__ = [
    "MutationError",
    "ActorError",
    "ContractError",
    "TransitionError",
    "StateConflictError",
    "validate_entity",
    "canonical_json",
    "event_identity",
    "apply_mutations",
    "recover_pending",
]

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class MutationError(Exception):
    """Base class for mutation-boundary failures."""


class ActorError(MutationError):
    """Raised when the actor identity is missing or malformed."""


class ContractError(MutationError):
    """Raised when an entity violates its type contract."""


class TransitionError(MutationError):
    """Raised when a proposed transition has no defined rule."""


class StateConflictError(MutationError):
    """Raised when on-disk state contradicts the mutation being applied."""


# ---------------------------------------------------------------------------
# Entity contracts (M1.5)
#
# Field set and ID patterns are taken verbatim from core/importer.py
# (_make_entity and the per-register ID regexes). Statuses in RX50 registers
# are free-form prose owned by RX50 (docs/STATE_MODEL.md: AIOS reflects, never
# supersedes), therefore status validation is STRUCTURAL only; inventing a
# closed vocabulary here would fabricate semantics that no repository
# evidence supports.
# ---------------------------------------------------------------------------

_ENTITY_CONTRACTS = {
    "REQUIREMENT": re.compile(r"R-\d+"),
    "DECISION": re.compile(r"D-\d+"),
    "EVIDENCE": re.compile(r"EV-\d+"),
    "ISSUE": re.compile(r"OI-\d+"),
    "GATE": re.compile(r"G\d+"),
    "CONTRADICTION": re.compile(r"C-\d+"),
}

_REQUIRED_FIELDS = {
    "entity_type",
    "entity_id",
    "statement",
    "status",
    "source_file",
    "source_line",
    "source_text",
    "classification",
    "imported_at",
    "snapshot_id",
}

_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_STATUS_MAX_LEN = 512


def _reject(entity_index, message):
    raise ContractError(f"entity[{entity_index}]: {message}")


def validate_entity(entity):
    """Validate one entity against its contract. Returns the entity unchanged.

    Raises ContractError on any violation. Storage keeps user-supplied values
    verbatim; validation never coerces.
    """
    if not isinstance(entity, dict):
        raise ContractError(f"entity must be a dict, got {type(entity).__name__}")

    idx = entity.get("entity_id", "<missing-id>")
    etype = entity.get("entity_type")
    if etype not in _ENTITY_CONTRACTS:
        raise ContractError(
            f"entity {idx!r}: unknown entity_type {etype!r}; "
            f"known types: {sorted(_ENTITY_CONTRACTS)}"
        )
    i = f"{etype}:{idx}"

    missing = _REQUIRED_FIELDS - set(entity)
    if missing:
        _reject(i, f"missing required fields: {sorted(missing)}")
    extra = set(entity) - _REQUIRED_FIELDS
    if extra:
        _reject(i, f"unexpected fields not in contract: {sorted(extra)}")

    for field in ("entity_id", "statement", "status", "source_file",
                  "source_text", "classification", "imported_at", "snapshot_id"):
        if not isinstance(entity[field], str):
            _reject(i, f"field {field!r} must be str, got {type(entity[field]).__name__}")

    if not entity["entity_id"].strip():
        _reject(i, "entity_id is empty")
    if not _ENTITY_CONTRACTS[etype].fullmatch(entity["entity_id"]):
        _reject(i, f"entity_id {entity['entity_id']!r} does not match "
                   f"{etype} ID pattern {_ENTITY_CONTRACTS[etype].pattern!r}")
    if entity["classification"] != etype:
        _reject(i, f"classification {entity['classification']!r} != entity_type {etype!r}")
    if not entity["statement"].strip():
        _reject(i, "statement is empty")
    if not entity["source_file"].strip():
        _reject(i, "source_file is empty")
    if not entity["source_text"].strip():
        _reject(i, "source_text is empty")
    if not _TIMESTAMP_RE.fullmatch(entity["imported_at"]):
        _reject(i, f"imported_at {entity['imported_at']!r} is not ISO-8601 UTC "
                   f"(YYYY-MM-DDTHH:MM:SSZ)")
    if not entity["snapshot_id"].strip():
        _reject(i, "snapshot_id is empty")

    line = entity["source_line"]
    if isinstance(line, bool) or not isinstance(line, int) or line <= 0:
        _reject(i, f"source_line must be a positive int, got {line!r}")

    status = entity["status"]
    if not status.strip():
        _reject(i, "status is empty")
    if len(status) > _STATUS_MAX_LEN:
        _reject(i, f"status exceeds {_STATUS_MAX_LEN} chars")
    if re.search(r"[\r\n\t]", status):
        _reject(i, "status contains control characters (newline/tab)")
    if "|" in status:
        _reject(i, "status contains '|' (table-cell corruption)")

    return entity


# ---------------------------------------------------------------------------
# Canonicalization + deterministic event identity
# ---------------------------------------------------------------------------

def canonical_json(obj):
    """Deterministic JSON serialization (sorted keys, tight separators)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def event_identity(event):
    """Content-derived event identifier: SHA-256 hex over canonicalized event
    VALUES with volatile fields excluded.

    Volatile fields (timestamp_utc) are excluded so the same logical event
    committed at a different wall-clock time yields the same identity. The
    full 64-hex digest is used; no truncation, no Python hash().
    """
    logical = {k: v for k, v in event.items() if k != "timestamp_utc"}
    return hashlib.sha256(canonical_json(logical).encode("utf-8")).hexdigest()


def _utc_ts():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _utc_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Staging / atomic commit helpers
# ---------------------------------------------------------------------------

# Indirection kept module-level so failure-injection tests can patch the
# actual commit boundary without mocking assertions.
_replace = os.replace


def _fsync_file(fh):
    fh.flush()
    os.fsync(fh.fileno())


def _fsync_dir(path):
    # Directory fsync is unsupported on some platforms (notably Windows);
    # it is a durability optimization, never a correctness gate here.
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _mutation_lock_path(aios_dir):
    return os.path.join(aios_dir, ".mutation.lock")


class _MutationLock:
    """Cross-platform exclusive lock for one AIOS state tree."""
    def __init__(self, aios_dir):
        self.aios_dir = aios_dir
        self.fh = None

    def __enter__(self):
        for state_dir in state_layout.STATE_DIRS:
            secure_makedirs_beneath(self.aios_dir, state_dir)
        try:
            self.fh = os.fdopen(secure_open_lock_beneath(self.aios_dir, ".mutation.lock"), "a+b")
        except (OSError, SecureWriteError) as exc:
            raise MutationError("cannot securely open AIOS mutation lock") from exc
        self.fh.seek(0)
        if os.name == "nt":
            import msvcrt
            while True:
                try:
                    msvcrt.locking(self.fh.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    continue
        else:
            import fcntl
            fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if os.name == "nt":
                import msvcrt
                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
        finally:
            self.fh.close()
        return False


def _write_staged(path, payload_bytes):
    with open(path, "wb") as fh:
        fh.write(payload_bytes)
        _fsync_file(fh)


def _digest_bytes(payload_bytes):
    return hashlib.sha256(payload_bytes).hexdigest()


def _entity_relpath(entity):
    target = state_layout.ENTITY_TO_DIR.get(entity["entity_type"])
    fname = re.sub(r"[^A-Za-z0-9_.-]", "_", entity["entity_id"]) + ".json"
    return os.path.join(target, fname)


def _event_relpath(event):
    fname = f"EVT-{_utc_ts()}-{event_identity(event)}.json"
    return os.path.join("events", fname)


# ---------------------------------------------------------------------------
# Roll-forward recovery
# ---------------------------------------------------------------------------

_JOURNAL_NAME = "journal.json"


def _recover_pending_unlocked(aios_dir):
    """Roll forward journaled batches using descriptor-relative no-follow I/O."""
    if not secure_is_dir_beneath(aios_dir, ".staging"):
        return
    for entry in secure_listdir_beneath(aios_dir, ".staging"):
        if not entry.startswith("batch-") or "/" in entry or entry in (".", ".."):
            raise StateConflictError(f"unexpected staging entry: {entry!r}")
        batch_rel = f".staging/{entry}"
        journal_rel = f"{batch_rel}/{_JOURNAL_NAME}"
        if secure_exists_beneath(aios_dir, journal_rel):
            try:
                journal = json.loads(secure_read_bytes_beneath(aios_dir, journal_rel).decode("utf-8"))
            except (OSError, SecureWriteError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise StateConflictError(f"invalid or unsafe mutation journal: {journal_rel}") from exc
            if not isinstance(journal, dict) or not isinstance(journal.get("ops"), list):
                raise StateConflictError(f"malformed mutation journal: {journal_rel}")
            for op in journal["ops"]:
                if not isinstance(op, dict):
                    raise StateConflictError("malformed journal operation")
                rel_dest = op.get("rel_dest")
                if not rel_dest:
                    dest = op.get("dest")
                    if not isinstance(dest, str):
                        raise StateConflictError("journal destination missing")
                    try:
                        rel_dest = os.path.relpath(dest, os.path.abspath(os.fspath(aios_dir))).replace(os.sep, "/")
                    except ValueError as exc:
                        raise StateConflictError("journal destination is outside AIOS state root") from exc
                try:
                    _safe_commit_destination(aios_dir, rel_dest)
                    tmp_rel = op.get("tmp_rel")
                    if not tmp_rel:
                        tmp = op.get("tmp")
                        if not isinstance(tmp, str):
                            raise StateConflictError("journal staged path missing")
                        tmp_rel = os.path.relpath(tmp, os.path.abspath(os.fspath(aios_dir))).replace(os.sep, "/")
                    _safe_commit_destination(aios_dir, tmp_rel)
                    if secure_exists_beneath(aios_dir, rel_dest):
                        actual = _digest_bytes(secure_read_bytes_beneath(aios_dir, rel_dest))
                        if actual != op["digest"]:
                            raise StateConflictError(f"committed file diverges from journal: {rel_dest}")
                    elif secure_exists_beneath(aios_dir, tmp_rel):
                        payload = secure_read_bytes_beneath(aios_dir, tmp_rel)
                        if _digest_bytes(payload) != op["digest"]:
                            raise StateConflictError(f"staged file digest mismatch: {tmp_rel}")
                        atomic_write_beneath(aios_dir, rel_dest, payload.decode("utf-8"))
                        secure_unlink_beneath(aios_dir, tmp_rel)
                    else:
                        raise StateConflictError(f"journal op unrecoverable (temp and dest both missing): {rel_dest}")
                except (OSError, SecureWriteError, UnicodeDecodeError, KeyError, TypeError) as exc:
                    raise StateConflictError(f"secure journal recovery refused operation: {rel_dest!r}") from exc
            secure_unlink_beneath(aios_dir, journal_rel)
        secure_rmtree_beneath(aios_dir, batch_rel)


def recover_pending(aios_dir):
    """Recover pending journal batches under the shared mutation lock."""
    with _MutationLock(aios_dir):
        _recover_pending_unlocked(aios_dir)


# ---------------------------------------------------------------------------
# The choke-point
# ---------------------------------------------------------------------------

def _require_actor(actor):
    if not isinstance(actor, str) or not actor.strip():
        raise ActorError(
            f"actor must be a non-empty string identifying who requested the "
            f"mutation, got {actor!r}"
        )
    return actor


def _load_existing(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _require_committed_event(aios_dir, entity):
    """Require the complete entity-import event to match persisted entity data.

    A matching ID/status/snapshot is insufficient: a tampered statement or
    source location must not borrow an unrelated valid receipt. The event's
    content-derived identity and canonical filename are checked as well.
    """
    events_dir = os.path.join(aios_dir, "events")
    if os.path.isdir(events_dir):
        for fn in sorted(os.listdir(events_dir)):
            if not fn.endswith(".json"):
                continue
            try:
                with open(os.path.join(events_dir, fn), "r", encoding="utf-8") as fh:
                    ev = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(ev, dict) or ev.get("kind") != "mutation":
                continue
            if ev.get("action") != "entity.imported":
                continue
            fields = (
                "entity_type", "entity_id", "status", "statement",
                "source_file", "source_line", "snapshot_id",
            )
            if any(ev.get(field) != entity.get(field) for field in fields):
                continue
            event_id = ev.get("event_id")
            if not isinstance(event_id, str):
                continue
            logical_event = {
                key: value for key, value in ev.items()
                if key not in ("timestamp_utc", "event_id")
            }
            if event_identity(logical_event) != event_id:
                continue
            if not fn.endswith(f"-{event_id}.json"):
                continue
            return
    raise StateConflictError(
        f"committed entity {entity['entity_type']} {entity['entity_id']} "
        f"has no matching integrity-bound audit event; state was tampered "
        f"with or predates M1.5")


def _safe_commit_destination(aios_dir, rel_dest):
    """Resolve a strictly relative state destination without lexical escape."""
    if not isinstance(rel_dest, str) or not rel_dest.strip() or "\x00" in rel_dest:
        raise MutationError("mutation destination must be a non-empty relative path")
    portable = rel_dest.replace("\\", "/")
    parts = portable.split("/")
    if (
        portable.startswith("/")
        or (len(portable) >= 2 and portable[1] == ":")
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise MutationError(f"mutation destination escapes AIOS state root: {rel_dest!r}")
    root = os.path.abspath(os.fspath(aios_dir))
    dest = os.path.abspath(os.path.join(root, *parts))
    try:
        if os.path.commonpath((root, dest)) != root:
            raise MutationError(f"mutation destination escapes AIOS state root: {rel_dest!r}")
    except ValueError as exc:
        raise MutationError(f"mutation destination escapes AIOS state root: {rel_dest!r}") from exc
    return dest


def commit_batch(aios_dir, payloads):
    """Single shared atomic commit engine under the mutation lock."""
    prepared = [(_safe_commit_destination(aios_dir, rel_dest), rel_dest.replace("\\\\", "/"), obj)
                for rel_dest, obj in payloads]
    with _MutationLock(aios_dir):
        secure_makedirs_beneath(aios_dir, ".staging")
        batch_id = uuid.uuid4().hex
        batch_rel = f".staging/batch-{batch_id}"
        secure_makedirs_beneath(aios_dir, batch_rel)
        ops = []
        for dest, rel_dest, obj in prepared:
            payload = (canonical_json(obj) + "\\n").encode("utf-8")
            tmp_rel = f"{batch_rel}/{uuid.uuid4().hex}.tmp"
            secure_write_bytes_beneath(aios_dir, tmp_rel, payload)
            ops.append({"tmp": os.path.join(os.fspath(aios_dir), *tmp_rel.split("/")),
                        "tmp_rel": tmp_rel, "dest": dest, "rel_dest": rel_dest,
                        "digest": _digest_bytes(payload)})
        journal_rel = f"{batch_rel}/{_JOURNAL_NAME}"
        secure_write_bytes_beneath(aios_dir, journal_rel,
            canonical_json({"batch_id": batch_id, "ops": ops}).encode("utf-8"))
        for op in ops:
            try:
                payload = secure_read_bytes_beneath(aios_dir, op["tmp_rel"])
                if _digest_bytes(payload) != op["digest"]:
                    raise MutationError("staged mutation payload digest mismatch")
                atomic_write_beneath(aios_dir, op["rel_dest"], payload.decode("utf-8"))
            except (OSError, SecureWriteError, UnicodeDecodeError) as exc:
                raise MutationError(f"secure mutation destination rejected: {op['rel_dest']!r}") from exc
            secure_unlink_beneath(aios_dir, op["tmp_rel"])
        secure_unlink_beneath(aios_dir, journal_rel)
        secure_rmtree_beneath(aios_dir, batch_rel)
        return [op["dest"] for op in ops]


def apply_mutations(aios_dir, entities, actor, notice_factory=None):
    """Apply a validated batch of entity mutations atomically.

    All-or-nothing: if ANY entity fails validation, nothing is written.

    Replay semantics: an entity whose committed file already exists with
    identical canonical content is a no-op ("replayed"); no duplicate event
    is produced. Any other difference against an existing entity is rejected
    as an undefined transition.

    Returns {"applied": [...], "replayed": [...],
             "event_files": [...], "notice_file": str|None}.
    """
    _require_actor(actor)
    recover_pending(aios_dir)

    # ---- Phase 1: validate everything before touching disk -----------------
    seen = set()
    for pos, ent in enumerate(entities):
        validate_entity(ent)
        key = (ent["entity_type"], ent["entity_id"])
        if key in seen:
            raise ContractError(
                f"entity[{pos}]: duplicate ({key[0]}, {key[1]}) in batch")
        seen.add(key)

    applied, replayed = [], []
    for ent in entities:
        dest = os.path.join(aios_dir, _entity_relpath(ent))
        if os.path.exists(dest):
            existing = _load_existing(dest)
            if canonical_json(existing) == canonical_json(ent):
                _require_committed_event(aios_dir, ent)
                replayed.append((ent["entity_type"], ent["entity_id"]))
                continue
            raise TransitionError(
                f"undefined transition for {ent['entity_type']} "
                f"{ent['entity_id']}: an entity with this ID already exists "
                f"with different content. No status-transition rules are "
                f"defined in this repository (RX50 owns its free-form status "
                f"vocabulary); changing a committed entity is therefore not "
                f"a supported operation. Recorded difference is intentional "
                f"divergence and must be handled as such.")
        applied.append(ent)

    mutation_events = []
    for ent in applied:
        mutation_events.append({
            "kind": "mutation",
            "action": "entity.imported",
            "actor": actor,
            "entity_type": ent["entity_type"],
            "entity_id": ent["entity_id"],
            "status": ent["status"],
            "statement": ent["statement"],
            "source_file": ent["source_file"],
            "source_line": ent["source_line"],
            "snapshot_id": ent["snapshot_id"],
        })
    notice_event = None
    if notice_factory is not None:
        notice_event = dict(notice_factory(len(applied)))
        notice_event["kind"] = "notice"
        notice_event.setdefault("actor", actor)

    if not applied and notice_event is None:
        return {"applied": [], "replayed": [list(r) for r in replayed],
                "event_files": [], "notice_file": None}

    # ---- Phase 2+3: shared atomic commit kernel ----------------------------
    payloads = [(_entity_relpath(ent), ent) for ent in applied]
    event_files = []
    for ev in mutation_events:
        rel = _event_relpath(ev)
        event_files.append(os.path.basename(rel))
        payloads.append((rel, {**ev, "timestamp_utc": _utc_iso(),
                               "event_id": event_identity(ev)}))
    notice_file = None
    if notice_event is not None:
        rel = _event_relpath(notice_event)
        notice_file = os.path.basename(rel)
        event_files.append(notice_file)
        payloads.append((rel, {**notice_event, "timestamp_utc": _utc_iso(),
                               "event_id": event_identity(notice_event)}))

    commit_batch(aios_dir, payloads)

    return {
        "applied": [[t, i] for t, i in ((e["entity_type"], e["entity_id"]) for e in applied)],
        "replayed": [list(r) for r in replayed],
        "event_files": event_files,
        "notice_file": notice_file,
    }
