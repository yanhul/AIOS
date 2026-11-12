"""Authoritative AIOS state mutation boundary (M1.5).

Every AIOS state mutation produced by the application MUST pass through
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
policy, gates, verification, contradiction resolution, OS-level protection
of the RX50 tree. Concurrency: one POSIX ``flock`` on ``<aios_dir>/.mutation.lock``
serializes mutations/recovery across processes. All state I/O is
descriptor-relative and no-follow via core.secure_fs; non-POSIX platforms
(including Windows) fail closed.

Stdlib only. Never writes outside ``<aios_dir>``.
"""

import datetime
import hashlib
import json
import os
import re
import uuid

from . import state as state_layout
from .secure_fs import (
    SecureWriteError, atomic_write_beneath, secure_makedirs_beneath,
    secure_write_bytes_beneath, secure_read_bytes_beneath,
    secure_exists_beneath, secure_is_dir_beneath, secure_listdir_beneath,
    secure_unlink_beneath, secure_rmtree_beneath, secure_open_lock_beneath,
    secure_regular_file_state_beneath, secure_fd_matches_beneath,
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

_LOCK_NAME = ".mutation.lock"


class _MutationLock:
    """Exclusive inter-process lock for one AIOS state tree (POSIX flock).

    The lock file lives directly beneath the state root and is opened
    no-follow, never truncated, and must be a regular, singly-linked file.
    After ``flock`` the path is re-checked to still name the locked inode;
    if it was replaced/unlinked meanwhile (which would split mutual
    exclusion between holders of different inodes) acquisition retries.
    Non-POSIX platforms fail closed (see core.secure_fs).
    """
    _MAX_ATTEMPTS = 16

    def __init__(self, aios_dir):
        self.aios_dir = aios_dir
        self.fd = None

    def __enter__(self):
        import fcntl
        try:
            for state_dir in state_layout.STATE_DIRS:
                secure_makedirs_beneath(self.aios_dir, state_dir)
            for _ in range(self._MAX_ATTEMPTS):
                fd = secure_open_lock_beneath(self.aios_dir, _LOCK_NAME)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    if secure_fd_matches_beneath(self.aios_dir, _LOCK_NAME, fd):
                        self.fd = fd
                        return self
                except BaseException:
                    os.close(fd)
                    raise
                os.close(fd)
        except (OSError, SecureWriteError) as exc:
            raise MutationError("cannot securely open AIOS mutation lock") from exc
        raise MutationError("AIOS mutation lock file keeps being replaced; refusing")

    def __exit__(self, exc_type, exc, tb):
        import fcntl
        fd, self.fd = self.fd, None
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return False


class _SharedReadLock:
    """Shared (``LOCK_SH``) counterpart of :class:`_MutationLock` for
    read-only sweeps such as :func:`core.reconcile.reconcile`.

    It never creates the state root, state directories or the lock file. If
    the lock file does not exist no lock is taken (``held`` is False): no
    mutation has ever completed lock acquisition there, and a mutation
    starting concurrently is NOT excluded (documented residual window).
    The same no-follow / regular / nlink==1 / inode re-check rules apply.
    """
    _MAX_ATTEMPTS = 16

    def __init__(self, aios_dir):
        self.aios_dir = aios_dir
        self.fd = None
        self.held = False

    def __enter__(self):
        import fcntl
        try:
            for _ in range(self._MAX_ATTEMPTS):
                try:
                    fd = secure_open_lock_beneath(self.aios_dir, _LOCK_NAME, create=False)
                except FileNotFoundError:
                    return self
                try:
                    fcntl.flock(fd, fcntl.LOCK_SH)
                    if secure_fd_matches_beneath(self.aios_dir, _LOCK_NAME, fd):
                        self.fd, self.held = fd, True
                        return self
                except BaseException:
                    os.close(fd)
                    raise
                os.close(fd)
        except (OSError, SecureWriteError) as exc:
            raise MutationError("cannot securely open AIOS mutation lock (shared)") from exc
        raise MutationError("AIOS mutation lock file keeps being replaced; refusing")

    def __exit__(self, exc_type, exc, tb):
        import fcntl
        fd, self.fd, self.held = self.fd, None, False
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        return False


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
    try:
        if not secure_is_dir_beneath(aios_dir, ".staging"):
            return
        entries = secure_listdir_beneath(aios_dir, ".staging")
    except (OSError, SecureWriteError) as exc:
        raise StateConflictError("unsafe AIOS staging directory refused") from exc
    for entry in entries:
        if not entry.startswith("batch-") or "/" in entry or entry in (".", ".."):
            raise StateConflictError(f"unexpected staging entry: {entry!r}")
        batch_rel = f".staging/{entry}"
        journal_rel = f"{batch_rel}/{_JOURNAL_NAME}"
        try:
            has_journal = secure_exists_beneath(aios_dir, journal_rel)
        except (OSError, SecureWriteError) as exc:
            raise StateConflictError(f"unsafe staging batch: {batch_rel}") from exc
        if has_journal:
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
                        atomic_write_beneath(aios_dir, rel_dest, payload.decode("utf-8"), enforce_owner=True)
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


def _portable_rel(relpath):
    return os.fspath(relpath).replace(os.sep, "/")


def _committed_state(aios_dir, relpath):
    """True if a committed regular file exists at ``relpath``; False if absent.

    A symlink (leaf or parent), directory or special file at the destination
    is a security conflict, never "absent" and never a valid entity.
    """
    try:
        return secure_regular_file_state_beneath(aios_dir, _portable_rel(relpath))
    except (OSError, SecureWriteError) as exc:
        raise StateConflictError(
            f"unsafe committed state path refused: {relpath!r}") from exc


def _load_existing(aios_dir, relpath):
    """Load committed JSON beneath ``aios_dir`` via no-follow, fstat-verified
    descriptor-relative I/O. Unsafe or unreadable data raises
    StateConflictError; it is never treated as an empty entity."""
    rel = _portable_rel(relpath)
    try:
        raw = secure_read_bytes_beneath(aios_dir, rel)
    except (OSError, SecureWriteError) as exc:
        raise StateConflictError(f"cannot securely read committed state: {rel!r}") from exc
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateConflictError(f"committed state is not valid JSON: {rel!r}") from exc


def read_state_json(aios_dir, relpath):
    """Secure JSON read of one state file beneath ``aios_dir``.

    Missing file/root -> ``FileNotFoundError`` (unchanged semantics for
    callers that test absence). Symlinks, dangling symlinks, special files,
    directories and untrusted directories -> :class:`StateConflictError`.
    Invalid JSON -> ``json.JSONDecodeError`` (a ``ValueError``)."""
    rel = _portable_rel(relpath)
    try:
        raw = secure_read_bytes_beneath(aios_dir, rel)
    except FileNotFoundError:
        raise
    except (OSError, SecureWriteError) as exc:
        raise StateConflictError(f"unsafe AIOS state entry refused: {rel!r}") from exc
    return json.loads(raw.decode("utf-8"))


def list_state_names(aios_dir, reldir):
    """Sorted names in a state directory; missing -> []; unsafe -> StateConflictError."""
    rel = _portable_rel(reldir)
    try:
        if not secure_is_dir_beneath(aios_dir, rel):
            if secure_exists_beneath(aios_dir, rel):
                raise StateConflictError(f"unsafe AIOS state directory refused: {rel!r}")
            return []
        return secure_listdir_beneath(aios_dir, rel)
    except FileNotFoundError:
        return []
    except (OSError, SecureWriteError) as exc:
        raise StateConflictError(f"unsafe AIOS state directory refused: {rel!r}") from exc


def _require_committed_event(aios_dir, entity):
    """Require the complete entity-import event to match persisted entity data.

    A matching ID/status/snapshot is insufficient: a tampered statement or
    source location must not borrow an unrelated valid receipt. The event's
    content-derived identity and canonical filename are checked as well.
    """
    # Materialize first: ANY unsafe event entry fails closed, even if a
    # matching receipt sorts before it.
    for fn, ev in list(_iter_event_records(aios_dir)):
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


def _iter_event_records(aios_dir):
    """Yield (filename, parsed JSON) for ``events/*.json`` using secure I/O.

    Fails closed (StateConflictError) if the events directory or any event
    file is a symlink / special file. Malformed JSON or a file that vanished
    concurrently is skipped (it cannot match; absence of a match fails
    closed in the caller).
    """
    try:
        if not secure_is_dir_beneath(aios_dir, "events"):
            return
        names = secure_listdir_beneath(aios_dir, "events")
    except FileNotFoundError:
        return
    except (OSError, SecureWriteError) as exc:
        raise StateConflictError("unsafe AIOS events directory refused") from exc
    for fn in names:
        if not fn.endswith(".json"):
            continue
        rel = f"events/{fn}"
        try:
            raw = secure_read_bytes_beneath(aios_dir, rel)
        except FileNotFoundError:
            continue
        except (OSError, SecureWriteError) as exc:
            raise StateConflictError(f"unsafe audit event refused: {rel!r}") from exc
        try:
            yield fn, json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue


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
            payload = (canonical_json(obj) + "\n").encode("utf-8")
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
        rel = _entity_relpath(ent)
        if _committed_state(aios_dir, rel):
            existing = _load_existing(aios_dir, rel)
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
