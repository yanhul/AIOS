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
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import uuid

from . import state as state_layout

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
    """Deterministic JSON serialization (sorted keys, tight separators).

    Non-finite floats (NaN/Infinity) are not valid JSON and have no canonical
    form; they are rejected (ValueError) so they can never be signed or hashed.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


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
    return os.path.join(os.path.dirname(aios_dir), ".aios.mutation.lock")


class _MutationLock:
    """Cross-platform exclusive lock for one AIOS state tree."""
    def __init__(self, aios_dir):
        self.aios_dir = aios_dir
        self.fh = None

    def __enter__(self):
        state_layout.ensure_state_dirs(self.aios_dir)
        os.makedirs(os.path.dirname(_mutation_lock_path(self.aios_dir)), exist_ok=True)
        self.fh = open(_mutation_lock_path(self.aios_dir), "a+b")
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

_JOURNAL_NAME = "journal.json"          # legacy: written in place (pre-v2 engines)
_JOURNAL_V2_NAME = "journal.v2.json"    # v2: published by atomic rename = commit point
_JOURNAL_FORMAT = 2
QUARANTINE_DIR = ".quarantine"


class LedgerBlockedError(StateConflictError):
    """L5 cannot establish commit state; store is BLOCKED pending operator action."""


def _journal_body_digest(batch_id, ops):
    return hashlib.sha256(canonical_json({"batch_id": batch_id, "ops": ops}).encode("utf-8")).hexdigest()


def _valid_ops(ops):
    return isinstance(ops, list) and all(
        isinstance(op, dict) and all(isinstance(op.get(k), str) and op.get(k) for k in ("tmp", "dest", "digest"))
        for op in ops)


def _classify_batch(batch_dir):
    """Return (classification, journal_or_reason).

    COMMITTED          -> journal (v2 verified, or parseable legacy)
    UNCOMMITTED        -> no journal was ever published: safe to discard
    CORRUPT_COMMITTED  -> v2 journal published (so committed) but unreadable/altered
    AMBIGUOUS_LEGACY   -> legacy journal unreadable: torn-before-commit and
                          corrupted-after-commit cannot be told apart
    """
    v2 = os.path.join(batch_dir, _JOURNAL_V2_NAME)
    legacy = os.path.join(batch_dir, _JOURNAL_NAME)
    if os.path.isfile(v2):
        try:
            with open(v2, "r", encoding="utf-8") as fh:
                journal = json.load(fh)
        except (OSError, ValueError) as exc:
            return "CORRUPT_COMMITTED", f"v2 journal unreadable: {type(exc).__name__}"
        if (not isinstance(journal, dict) or journal.get("format") != _JOURNAL_FORMAT
                or not _valid_ops(journal.get("ops"))
                or journal.get("body_digest") != _journal_body_digest(journal.get("batch_id"), journal.get("ops"))):
            return "CORRUPT_COMMITTED", "v2 journal fails format/digest verification"
        return "COMMITTED", journal
    if os.path.isfile(legacy):
        try:
            with open(legacy, "r", encoding="utf-8") as fh:
                journal = json.load(fh)
        except (OSError, ValueError) as exc:
            return "AMBIGUOUS_LEGACY", f"legacy journal unreadable: {type(exc).__name__}"
        if not isinstance(journal, dict) or not _valid_ops(journal.get("ops")):
            return "AMBIGUOUS_LEGACY", "legacy journal has no valid ops list"
        return "COMMITTED", journal
    return "UNCOMMITTED", None


def _quarantine(aios_dir, batch_dir, classification, reason):
    """Preserve the batch as evidence and block the store; never delete it."""
    qroot = os.path.join(aios_dir, QUARANTINE_DIR)
    os.makedirs(qroot, exist_ok=True)
    target = os.path.join(qroot, os.path.basename(batch_dir))
    os.replace(batch_dir, target)
    with open(os.path.join(target, "QUARANTINE.json"), "w", encoding="utf-8") as fh:
        fh.write(canonical_json({"classification": classification, "reason": reason,
                                 "batch": os.path.basename(batch_dir), "quarantined_utc": _utc_iso()}))
        _fsync_file(fh)
    _fsync_dir(qroot)
    raise LedgerBlockedError(f"L5 BLOCKED: batch {os.path.basename(batch_dir)} quarantined "
                             f"({classification}: {reason}); operator resolution required")


def unresolved_quarantine(aios_dir):
    """Quarantined batches without an operator RESOLVED.json marker."""
    qroot = os.path.join(aios_dir, QUARANTINE_DIR)
    if not os.path.isdir(qroot):
        return []
    return sorted(d for d in os.listdir(qroot)
                  if os.path.isdir(os.path.join(qroot, d))
                  and not os.path.exists(os.path.join(qroot, d, "RESOLVED.json")))


def _within(root, path):
    """True only when ``path`` resolves inside ``root`` (symlinks resolved)."""
    try:
        root_r = os.path.realpath(root)
        return os.path.commonpath([root_r, os.path.realpath(path)]) == root_r
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Store confinement and staged-payload integrity (F-02)
#
# Threat model. Actors considered:
#   * STAGING WRITER (in scope): can create/replace/modify/link entries under
#     ``.staging`` (including journals, whose digest is unkeyed - see F-03/F-04)
#     and plant symlinks in the store, but does not hold the mutation lock and
#     cannot write the destination directories or the store root.
#   * DESTINATION-DIR / STORE-ROOT WRITER (out of scope): can rename or
#     replace real directories and files of the store itself. Such an actor
#     can corrupt the store directly; only best-effort identity checks apply.
#   * Same-uid code running inside this process: out of scope.
#
# Separate properties, each with its own defence:
#   1. Pathname confinement (check time): store-relative destinations only,
#      no ``..``, no reserved L5 directory (.staging, .quarantine), no symlink
#      component (lstat), realpath() inside the store.
#   2. Pathname races (use time): directories are walked with O_NOFOLLOW from
#      a descriptor on the store root; every open/create/rename/unlink is
#      dir_fd-relative, so a symlink swapped into a path after step 1 is
#      refused, never followed.
#   3. Inode aliasing (hard links): a staged entry is never renamed into the
#      store. Its bytes are copied into a NEW inode created O_EXCL in the
#      destination directory, so no external name can share the installed
#      inode. Staged entries with st_nlink != 1 are refused as a fail-closed
#      signal (not relied on: a link created after fstat is harmless because
#      of the copy).
#   4. Content integrity / concurrent in-place writes: SHA-256 is computed
#      over exactly the bytes written to the new inode and compared with the
#      journal digest before installation. A staged file replaced after the
#      early digest check, or modified while being copied, yields a mismatch
#      and the batch is quarantined. This does NOT give a coherent snapshot
#      of the staged source; it guarantees that the installed bytes are
#      exactly bytes whose digest equals the journal digest.
# Platforms without dir_fd/O_NOFOLLOW (_FD_SAFE False, e.g. Windows) cannot
# provide property 2, so applying a staged payload there fails closed with
# L5PlatformUnsupportedError (batch retained, nothing installed). There is no
# path-based fallback.
# ---------------------------------------------------------------------------

_RESERVED_TOP = frozenset({".staging", QUARANTINE_DIR})
_RESERVED_STAGED_NAMES = frozenset({_JOURNAL_V2_NAME, _JOURNAL_NAME,
                                    _JOURNAL_V2_NAME + ".tmp", "QUARANTINE.json"})
# os.replace shares os.rename's renameat() path but CPython only lists rename.
_FD_SAFE = (os.rename in os.supports_dir_fd and os.unlink in os.supports_dir_fd
            and os.open in os.supports_dir_fd
            and os.mkdir in os.supports_dir_fd and os.stat in os.supports_dir_fd
            and os.listdir in os.supports_fd and hasattr(os, "O_NONBLOCK")
            and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"))
_ESCAPE_ERRNOS = frozenset(e for e in (errno.ELOOP, errno.ENOTDIR, getattr(errno, "EMLINK", None))
                           if e is not None)


class _PathEscape(Exception):
    """A journal/commit path would leave, or be redirected out of, the store."""


def _rel_parts(root, path):
    """Lexical components of ``path`` relative to ``root``, or None if outside."""
    try:
        for base in (os.path.abspath(root), os.path.realpath(root)):
            rel = os.path.relpath(os.path.abspath(path), base)
            parts = rel.split(os.sep)
            if rel != os.curdir and os.pardir not in parts and not os.path.isabs(rel):
                return parts
    except (TypeError, ValueError):
        pass
    return None


def _no_symlink_components(root, parts):
    cur = os.path.abspath(root)
    for comp in parts:
        cur = os.path.join(cur, comp)
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            return  # remaining components will be created by L5 itself
        if stat.S_ISLNK(st.st_mode):
            raise _PathEscape(f"symlink in path: {cur}")


def _dest_parts(aios_dir, dest):
    """Validate a destination at check time; return its store-relative parts."""
    parts = _rel_parts(aios_dir, dest)
    if parts is None:
        raise _PathEscape(f"outside the L5 store: {dest}")
    if parts[0] in _RESERVED_TOP:
        raise _PathEscape(f"targets reserved L5 path {parts[0]!r}: {dest}")
    _no_symlink_components(aios_dir, parts)
    if not _within(aios_dir, dest):
        raise _PathEscape(f"resolves outside the L5 store: {dest}")
    return parts


def _staged_name(batch_dir, tmp):
    """Validate a staged file at check time; return its name inside batch_dir."""
    parts = _rel_parts(batch_dir, tmp)
    if parts is None or len(parts) != 1 or parts[0] in _RESERVED_STAGED_NAMES:
        raise _PathEscape(f"staged file is not a payload of this batch: {tmp}")
    try:
        if stat.S_ISLNK(os.lstat(batch_dir).st_mode):
            raise _PathEscape(f"batch directory is a symlink: {batch_dir}")
        st = os.lstat(os.path.join(batch_dir, parts[0]))
        if not stat.S_ISREG(st.st_mode):
            raise _PathEscape(f"staged file is not a regular file: {tmp}")
    except FileNotFoundError:
        pass  # already applied before a crash; destination is verified instead
    return parts[0]


def _read_nofollow(path):
    """Read a regular file without following a final symlink or blocking on a FIFO."""
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
             | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno in _ESCAPE_ERRNOS:
            raise _PathEscape(f"symlink at {path}") from exc
        raise
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise _PathEscape(f"not a regular file: {path}")
        return fh.read()


def _open_dir_at(dir_fd, name, create):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        try:
            return os.open(name, flags, dir_fd=dir_fd)
        except FileNotFoundError:
            if not create:
                raise
            try:
                os.mkdir(name, 0o777, dir_fd=dir_fd)
            except FileExistsError:
                pass
            return os.open(name, flags, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in _ESCAPE_ERRNOS:
            raise _PathEscape(f"path component {name!r} is a symlink or not a directory") from exc
        raise


class _IntegrityError(Exception):
    """Bytes copied from a staged payload do not match the journal digest."""


class L5PlatformUnsupportedError(LedgerBlockedError):
    """The platform lacks the primitives the F-02 contract requires; fail closed."""


class RecoveryIncompleteError(LedgerBlockedError):
    """An I/O failure interrupted installation; the batch is retained for replay."""


_COPY_CHUNK = 1 << 16
_DEST_TMP_SUFFIX = ".l5tmp"
_new_digest = hashlib.sha256  # module-level so tests can inject digest failures


def _require_fd_safe():
    if not _FD_SAFE:
        raise L5PlatformUnsupportedError(
            "L5 BLOCKED: platform lacks dir_fd/O_NOFOLLOW; staged payloads cannot be "
            "installed without pathname-race protection (fail closed)")


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _sweep_stale_dest_tmps(parent_fd, dest_name):
    """Remove leftovers of a crashed install of ``dest_name`` (caller holds the lock)."""
    prefix = f".{dest_name}."
    for name in os.listdir(parent_fd):
        if name.startswith(prefix) and name.endswith(_DEST_TMP_SUFFIX):
            try:
                os.unlink(name, dir_fd=parent_fd)  # unlink never follows symlinks
            except FileNotFoundError:
                pass


def _apply_op(aios_dir, batch_dir, tmp_name, dest_parts, expected_digest):
    """Install one staged payload as a new, digest-verified inode in the store.

    Raises _PathEscape (redirection), _IntegrityError (content mismatch) or
    OSError (I/O failure; nothing new is installed unless the final rename
    already happened, in which case the installed bytes are verified).
    """
    _require_fd_safe()
    cloexec = getattr(os, "O_CLOEXEC", 0)
    fds = [os.open(aios_dir, os.O_RDONLY | os.O_DIRECTORY | cloexec)]
    src = dst = None
    dest_name, tmp_dest = dest_parts[-1], None
    parent = None
    try:
        fds.append(_open_dir_at(fds[0], ".staging", create=False))
        src_dir = _open_dir_at(fds[-1], os.path.basename(batch_dir), create=False)
        fds.append(src_dir)
        try:
            src = os.open(tmp_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | cloexec,
                          dir_fd=src_dir)
        except OSError as exc:
            if exc.errno in _ESCAPE_ERRNOS:
                raise _PathEscape(f"staged entry {tmp_name!r} is a symlink") from exc
            raise
        st = os.fstat(src)  # identity of the opened object, not of the pathname
        if not stat.S_ISREG(st.st_mode):
            raise _PathEscape(f"staged entry {tmp_name!r} is not a regular file")
        if st.st_nlink != 1:
            raise _PathEscape(f"staged entry {tmp_name!r} has {st.st_nlink} hard links")

        parent = fds[0]
        for comp in dest_parts[:-1]:
            parent = _open_dir_at(parent, comp, create=True)
            fds.append(parent)
        _sweep_stale_dest_tmps(parent, dest_name)
        tmp_dest = f".{dest_name}.{uuid.uuid4().hex}{_DEST_TMP_SUFFIX}"
        dst = os.open(tmp_dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | cloexec,
                      0o666, dir_fd=parent)

        h = _new_digest()
        while True:
            chunk = os.read(src, _COPY_CHUNK)
            if not chunk:
                break
            h.update(chunk)          # hash exactly the bytes written below
            _write_all(dst, chunk)
        if h.hexdigest() != expected_digest:
            raise _IntegrityError(f"copied bytes of {tmp_name!r} do not match journal digest")
        os.fsync(dst)

        mine = os.fstat(dst)
        named = os.stat(tmp_dest, dir_fd=parent, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (mine.st_dev, mine.st_ino):
            raise _PathEscape(f"destination temp {tmp_dest!r} was replaced before install")
        _replace(tmp_dest, dest_name, src_dir_fd=parent, dst_dir_fd=parent)
        tmp_dest = None  # consumed by the rename
        installed = os.stat(dest_name, dir_fd=parent, follow_symlinks=False)
        if (installed.st_dev, installed.st_ino) != (mine.st_dev, mine.st_ino):
            raise _PathEscape(f"destination {dest_name!r} changed during install")
        os.fsync(parent)  # durability of the rename is part of success
        try:
            os.unlink(tmp_name, dir_fd=src_dir)  # marks the op applied for replay
        except FileNotFoundError:
            pass
    except BaseException:
        if tmp_dest is not None and parent is not None:
            try:
                os.unlink(tmp_dest, dir_fd=parent)  # never follows a symlink
            except OSError:
                pass
        raise
    finally:
        for fd in (dst, src):
            if fd is not None:
                os.close(fd)
        for fd in reversed(fds):
            os.close(fd)


def _recover_pending_unlocked(aios_dir):
    """Roll forward committed batches; caller owns the mutation lock.

    Fails closed (LedgerBlockedError) while any quarantined batch is unresolved,
    because the store may then hold a partially applied commit.
    """
    blocked = unresolved_quarantine(aios_dir)
    if blocked:
        raise LedgerBlockedError(f"L5 BLOCKED: unresolved quarantined batches: {blocked}")
    staging = os.path.join(aios_dir, ".staging")
    if not os.path.isdir(staging):
        return
    for entry in sorted(os.listdir(staging)):
        batch_dir = os.path.join(staging, entry)
        if not os.path.isdir(batch_dir):
            continue
        classification, journal = _classify_batch(batch_dir)
        if classification in ("CORRUPT_COMMITTED", "AMBIGUOUS_LEGACY"):
            _quarantine(aios_dir, batch_dir, classification, journal)
        if classification == "COMMITTED":
            # Validate every op before touching any destination.
            # A journal names absolute paths and its digest is unkeyed, so a
            # writer of .staging could otherwise roll forward attacker bytes to
            # any path this process can write. Confine every op before I/O.
            problems, plan = [], []
            for op in journal["ops"]:
                try:
                    plan.append((op, _staged_name(batch_dir, op["tmp"]), _dest_parts(aios_dir, op["dest"])))
                except _PathEscape as exc:
                    problems.append(f"journal op escapes the L5 store: {exc}")
            if problems:
                _quarantine(aios_dir, batch_dir, "UNRECOVERABLE_COMMITTED", "; ".join(problems))
            try:
                for op, _, _ in plan:
                    if os.path.lexists(op["tmp"]):
                        if _digest_bytes(_read_nofollow(op["tmp"])) != op["digest"]:
                            problems.append(f"staged file diverges from journal: {op['dest']}")
                    elif os.path.lexists(op["dest"]):
                        if _digest_bytes(_read_nofollow(op["dest"])) != op["digest"]:
                            problems.append(f"staged file missing and destination diverges: {op['dest']}")
                    else:
                        problems.append(f"staged file and destination both missing: {op['dest']}")
            except _PathEscape as exc:
                problems.append(f"journal op escapes the L5 store: {exc}")
            if problems:
                _quarantine(aios_dir, batch_dir, "UNRECOVERABLE_COMMITTED", "; ".join(problems))
            try:
                for op, tmp_name, parts in plan:
                    if os.path.lexists(op["tmp"]):
                        _apply_op(aios_dir, batch_dir, tmp_name, parts, op["digest"])
            except (_PathEscape, _IntegrityError) as exc:
                _quarantine(aios_dir, batch_dir, "UNRECOVERABLE_COMMITTED",
                            f"staged payload rejected during roll-forward: {exc}")
            except OSError as exc:
                raise RecoveryIncompleteError(
                    f"L5 BLOCKED: roll-forward of {entry} interrupted ({exc}); "
                    "batch retained for replay") from exc
            for name in (_JOURNAL_V2_NAME, _JOURNAL_NAME):
                path = os.path.join(batch_dir, name)
                if os.path.exists(path):
                    os.unlink(path)
        # UNCOMMITTED (or now fully applied): discard staging.
        shutil.rmtree(batch_dir, ignore_errors=True)


def inspect_pending(aios_dir):
    """Read-only: report staged batches and unresolved quarantine without touching anything.

    Never takes the mutation lock, never moves, rewrites or deletes files.
    """
    staging = os.path.join(aios_dir, ".staging")
    batches = []
    if os.path.isdir(staging):
        for entry in sorted(os.listdir(staging)):
            batch_dir = os.path.join(staging, entry)
            if os.path.isdir(batch_dir):
                classification, _ = _classify_batch(batch_dir)
                batches.append({"batch": entry, "classification": classification})
    return {"pending": batches, "quarantined": unresolved_quarantine(aios_dir)}


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


def commit_batch(aios_dir, payloads, precondition=None):
    """Single shared atomic commit engine under the mutation lock.

    ``precondition`` (optional callable taking ``aios_dir``) runs while the
    lock is held and before anything is staged. Raising aborts the batch with
    no writes, which gives callers compare-and-swap semantics for the full
    read -> validate -> write sequence.
    """
    with _MutationLock(aios_dir):
        state_layout.ensure_state_dirs(aios_dir)
        # Contract 3.4: never evaluate a precondition over a half-applied batch.
        _recover_pending_unlocked(aios_dir)
        if precondition is not None:
            precondition(aios_dir)
        _require_fd_safe()
        staging_root = os.path.join(aios_dir, ".staging")
        batch_id = uuid.uuid4().hex
        batch_dir = os.path.join(staging_root, f"batch-{batch_id}")
        os.makedirs(batch_dir, exist_ok=True)

        ops, plan = [], []
        for rel_dest, _obj in payloads:
            try:
                if not isinstance(rel_dest, str) or os.path.isabs(rel_dest):
                    raise _PathEscape("destination must be store-relative")
                plan.append(_dest_parts(aios_dir, os.path.join(aios_dir, rel_dest)))
            except _PathEscape as exc:
                shutil.rmtree(batch_dir, ignore_errors=True)
                raise StateConflictError(f"commit destination escapes the L5 store: {rel_dest!r} ({exc})")
        for rel_dest, obj in payloads:
            payload = (canonical_json(obj) + "\n").encode("utf-8")
            tmp = os.path.join(batch_dir, f"{uuid.uuid4().hex}.tmp")
            _write_staged(tmp, payload)
            ops.append({
                "tmp": tmp,
                "dest": os.path.join(aios_dir, rel_dest),
                "digest": _digest_bytes(payload),
            })

        journal_path = os.path.join(batch_dir, _JOURNAL_V2_NAME)
        journal_tmp = journal_path + ".tmp"
        _write_staged(
            journal_tmp,
            canonical_json({"format": _JOURNAL_FORMAT, "batch_id": batch_id, "ops": ops,
                            "body_digest": _journal_body_digest(batch_id, ops)}).encode("utf-8"),
        )
        _replace(journal_tmp, journal_path)  # commit point (contract 3.1)
        _fsync_dir(batch_dir)

        try:
            for op, parts in zip(ops, plan):
                _apply_op(aios_dir, batch_dir, os.path.basename(op["tmp"]), parts, op["digest"])
        except (_PathEscape, _IntegrityError) as exc:
            _quarantine(aios_dir, batch_dir, "UNRECOVERABLE_COMMITTED",
                        f"staged payload rejected during commit: {exc}")
        except OSError as exc:
            raise RecoveryIncompleteError(
                f"L5 BLOCKED: commit of batch-{batch_id} interrupted ({exc}); "
                "batch retained for replay") from exc

        os.unlink(journal_path)
        shutil.rmtree(batch_dir, ignore_errors=True)
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
