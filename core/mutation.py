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
- Atomicity: staged temp files -> write-ahead journal bound to a protected
  transaction state (``.l5/state.json``) -> CAS installs -> finalization,
  with roll-forward recovery (``recover_pending``) invoked at the start of
  every mutation. See docs/L5_TRUST_MODEL.md for the trust boundary.

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
# L5 atomic commit engine: F-02 confinement + F-03/F-04 trust anchor
#
# Trust model (see docs/L5_TRUST_MODEL.md):
#   * Trust anchor: the protected transaction state ``<store>/.l5/state.json``
#     (service-owned regular file, mode 0600, nlink 1, inside a service-owned
#     0700 directory on the store filesystem). Only a batch named by that state
#     is ever executed, and only when the SHA-256 of its journal bytes equals
#     the digest recorded in the state. The digest is therefore authenticated
#     by the location of the state file, not by the staging writer.
#   * Enforced boundary: a DIFFERENT-UID process. Store root must be owned by
#     the effective uid and not group/other-writable; every ancestor must be
#     owned by root or the euid and not group/other-writable unless sticky;
#     .staging, .quarantine and .l5 must be euid-owned, 0700 (g/o read/exec
#     bits on a pre-existing euid-owned directory are tightened explicitly;
#     g/o write bits are refused), on the store filesystem. Violations raise
#     L5UnsafeLayoutError before anything is read from staging.
#   * NOT defended: a SAME-UID malicious process or a compromised service
#     process (it can rewrite state.json itself; no local key could stop it),
#     root, and untrusted/network filesystems. A local HMAC would add nothing
#     against these because the key would be readable by the same uid.
#
# Persistent state machine (each transition = atomic rename of state.json +
# fsync of the .l5 directory):
#   IDLE -> PREPARED -> COMMIT_POINT -> APPLYING -> FINALIZED -> CLEANUP -> IDLE
#   any committed phase -> QUARANTINED (until operator resolution) -> IDLE
#   PREPARED     seq allocated (never reused); destinations are never written
#                in this phase, so recovery aborts after verifying the batch
#                directory contains only service-owned L5 artefacts.
#   COMMIT_POINT journal published + fsynced, its digest and the batch inode
#                recorded: the transaction is committed.
#   APPLYING     destination writes may have started; recovery rolls forward
#                with per-op CAS (prior -> apply, new -> skip, other -> conflict).
#   FINALIZED    every destination durable; recovery only removes residue.
#   CLEANUP      residue removal in progress; recovery only removes residue.
# ---------------------------------------------------------------------------

_replace = os.replace          # tmp -> destination and journal publication
_state_replace = os.replace    # state.json publication (separate injection point)

STAGING_DIR = ".staging"
QUARANTINE_DIR = ".quarantine"
STATE_DIR = ".l5"
_LOCK_NAME = ".aios.mutation.lock"
_STATE_NAME = "state.json"
_STATE_FORMAT = 1
_JOURNAL_NAME = "journal.v3.json"
_JOURNAL_TMP_NAME = _JOURNAL_NAME + ".tmp"
_JOURNAL_FORMAT = 3
_RESOLVED_NAME = "RESOLVED.json"
_QMETA_NAME = "QUARANTINE.json"
_QEVIDENCE_NAME = "evidence"
_LEGACY_SIDECAR_SUFFIX = ".QUARANTINE.json"
_RESERVED_TOP = frozenset({STAGING_DIR, QUARANTINE_DIR, STATE_DIR})
_RESERVED_FOLDED = frozenset(n.casefold() for n in _RESERVED_TOP)
_PROTECTED_DIR_MODE = 0o700
_PROTECTED_FILE_MODE = 0o600
# Destination permission policy: a replaced file keeps its prior permission
# bits minus group/other write and setuid/setgid/sticky; a new file is 0644
# and a new directory 0755, set explicitly with fchmod (never from umask).
_DEST_NEW_FILE_MODE = 0o644
_DEST_NEW_DIR_MODE = 0o755
_DEST_MODE_MASK = 0o755
_COPY_CHUNK = 1 << 16
_DEST_TMP_SUFFIX = ".l5tmp"
_new_digest = hashlib.sha256  # module-level so tests can inject digest failures
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_STAGED_RE = re.compile(r"[0-9a-f]{32}\.tmp\Z")
_STATE_TMP_RE = re.compile(r"state\.json\.[0-9a-f]{32}\.tmp\Z")
_PHASES = ("IDLE", "PREPARED", "COMMIT_POINT", "APPLYING", "FINALIZED", "CLEANUP", "QUARANTINED")
_COMMITTED_PHASES = ("COMMIT_POINT", "APPLYING")
_DONE_PHASES = ("FINALIZED", "CLEANUP")

_FD_SAFE = (os.name == "posix"
            and os.rename in os.supports_dir_fd and os.unlink in os.supports_dir_fd
            and os.open in os.supports_dir_fd
            and os.mkdir in os.supports_dir_fd and os.stat in os.supports_dir_fd
            and os.rmdir in os.supports_dir_fd
            and os.listdir in os.supports_fd and hasattr(os, "O_NONBLOCK")
            and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
            and hasattr(os, "fchmod") and hasattr(os, "geteuid"))
# ELOOP: Linux/macOS; EMLINK: FreeBSD; EFTYPE: NetBSD (O_NOFOLLOW on a symlink).
_ESCAPE_ERRNOS = frozenset(e for e in (errno.ELOOP, errno.ENOTDIR, getattr(errno, "EMLINK", None),
                                       getattr(errno, "EFTYPE", None)) if e is not None)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


class LedgerBlockedError(StateConflictError):
    """L5 cannot establish commit state; store is BLOCKED pending operator action."""


class L5PlatformUnsupportedError(LedgerBlockedError):
    """The platform lacks the primitives the L5 contract requires; fail closed."""


class L5UnsafeLayoutError(LedgerBlockedError):
    """The trust anchor (ownership/mode/identity of the store layout) is violated."""


class RecoveryIncompleteError(LedgerBlockedError):
    """An I/O failure interrupted a committed transaction; recovery is required."""


class _PathEscape(Exception):
    """A path would leave, or be redirected out of, the store."""


class _IntegrityError(Exception):
    """Bytes copied from a staged payload do not match the journal digest."""


class _Conflict(Exception):
    """Destination matches neither the expected prior nor the new content."""


class _Untrusted(Exception):
    """An object fails the owner/mode/identity checks of the trust anchor."""


class _JournalInvalid(Exception):
    """Journal or state bytes violate the strict schema."""


def _require_fd_safe():
    if not _FD_SAFE:
        raise L5PlatformUnsupportedError(
            "L5 BLOCKED: platform lacks POSIX dir_fd/O_NOFOLLOW/fchmod; the L5 trust "
            "anchor cannot be enforced (fail closed; no path-based fallback)")


def _digest_bytes(payload_bytes):
    return hashlib.sha256(payload_bytes).hexdigest()


def _entity_relpath(entity):
    target = state_layout.ENTITY_TO_DIR.get(entity["entity_type"])
    fname = re.sub(r"[^A-Za-z0-9_.-]", "_", entity["entity_id"]) + ".json"
    return os.path.join(target, fname)


def _event_relpath(event):
    fname = f"EVT-{_utc_ts()}-{event_identity(event)}.json"
    return os.path.join("events", fname)


def _mutation_lock_path(aios_dir):
    return os.path.join(os.path.dirname(os.path.realpath(aios_dir)), _LOCK_NAME)


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _read_fd(fd):
    chunks = []
    while True:
        chunk = os.read(fd, _COPY_CHUNK)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _close_all(fds):
    for fd in fds:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Ownership / mode / identity checks
# ---------------------------------------------------------------------------

def _check_ancestor(st, label):
    if not stat.S_ISDIR(st.st_mode):
        raise L5UnsafeLayoutError(f"L5 BLOCKED: ancestor {label!r} is not a directory")
    if st.st_uid not in (0, os.geteuid()):
        raise L5UnsafeLayoutError(f"L5 BLOCKED: ancestor {label!r} owned by uid {st.st_uid}")
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o022 and not mode & stat.S_ISVTX:
        raise L5UnsafeLayoutError(
            f"L5 BLOCKED: ancestor {label!r} is group/other-writable without sticky bit ({mode:o})")


def _check_store_root(st, label):
    if not stat.S_ISDIR(st.st_mode):
        raise L5UnsafeLayoutError(f"L5 BLOCKED: store root {label!r} is not a directory")
    if st.st_uid != os.geteuid():
        raise L5UnsafeLayoutError(
            f"L5 BLOCKED: store root {label!r} owned by uid {st.st_uid}, expected {os.geteuid()}")
    if stat.S_IMODE(st.st_mode) & 0o022:
        raise L5UnsafeLayoutError(
            f"L5 BLOCKED: store root {label!r} is group/other-writable ({stat.S_IMODE(st.st_mode):o})")


def _check_protected_dir(st, label, root_dev, readonly=False):
    if not stat.S_ISDIR(st.st_mode):
        raise L5UnsafeLayoutError(f"L5 BLOCKED: {label} is not a directory")
    if st.st_uid != os.geteuid():
        raise L5UnsafeLayoutError(f"L5 BLOCKED: {label} owned by uid {st.st_uid}, expected {os.geteuid()}")
    if st.st_dev != root_dev:
        raise L5UnsafeLayoutError(f"L5 BLOCKED: {label} is on a different filesystem than the store root")
    # Read-only inspection tolerates a legacy 0755 layout; anything that
    # mutates requires (and first enforces) 0700.
    if stat.S_IMODE(st.st_mode) & (0o022 if readonly else 0o077):
        raise L5UnsafeLayoutError(f"L5 BLOCKED: {label} mode {stat.S_IMODE(st.st_mode):o}, expected 700")


def _check_private_file(st, label, owners=None):
    owners = (os.geteuid(),) if owners is None else owners
    if not stat.S_ISREG(st.st_mode):
        raise _Untrusted(f"{label} is not a regular file")
    if st.st_nlink != 1:
        raise _Untrusted(f"{label} has {st.st_nlink} hard links")
    if st.st_uid not in owners:
        raise _Untrusted(f"{label} owned by uid {st.st_uid}")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise _Untrusted(f"{label} mode {stat.S_IMODE(st.st_mode):o} is accessible to group/other")


# ---------------------------------------------------------------------------
# Directory-FD primitives (no symlink is ever followed)
# ---------------------------------------------------------------------------

def _valid_component(name):
    return (isinstance(name, str) and name not in ("", os.curdir, os.pardir)
            and "\x00" not in name and os.sep not in name
            and (os.altsep is None or os.altsep not in name))


def _open_dir_at(dir_fd, name, create=False, mode=_DEST_NEW_DIR_MODE):
    """Open (optionally create) a directory relative to ``dir_fd`` without following links.

    A newly created directory receives ``mode`` explicitly via fchmod.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | _CLOEXEC
    created = False
    try:
        try:
            fd = os.open(name, flags, dir_fd=dir_fd)
        except FileNotFoundError:
            if not create:
                raise
            try:
                os.mkdir(name, 0o700, dir_fd=dir_fd)
                created = True
            except FileExistsError:
                pass
            fd = os.open(name, flags, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in _ESCAPE_ERRNOS:
            raise _PathEscape(f"path component {name!r} is a symlink or not a directory") from exc
        raise
    if created:
        try:
            os.fchmod(fd, mode)
        except BaseException:
            os.close(fd)
            raise
    return fd


def _open_regular_at(dir_fd, name, flags=os.O_RDONLY):
    """Open an existing regular file; the type is validated BEFORE open().

    lstat first, so FIFOs/devices/sockets are refused without being opened
    (a device swapped in between lstat and open is caught by the inode
    comparison; O_NONBLOCK keeps a raced FIFO from blocking).
    """
    st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)  # FileNotFoundError propagates
    if not stat.S_ISREG(st.st_mode):
        raise _PathEscape(f"{name!r} is not a regular file")
    try:
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | _CLOEXEC, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in _ESCAPE_ERRNOS:
            raise _PathEscape(f"{name!r} is a symlink") from exc
        raise
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
            raise _PathEscape(f"{name!r} changed between validation and open")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _verify_pinned(parent_fd, name, fd, label):
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise L5UnsafeLayoutError(f"L5 BLOCKED: {label} disappeared after it was pinned") from exc
    opened = os.fstat(fd)
    if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
        raise L5UnsafeLayoutError(f"L5 BLOCKED: {label} was replaced after it was pinned")


def _rmtree_at(parent_fd, name):
    """Remove a tree by dir_fd without following symlinks or raced directories."""
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(before.st_mode):
        os.unlink(name, dir_fd=parent_fd)
        return
    child_fd = _open_dir_at(parent_fd, name)
    try:
        opened = os.fstat(child_fd)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise _PathEscape(f"directory {name!r} changed during cleanup")
        for child in os.listdir(child_fd):
            _rmtree_at(child_fd, child)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise _PathEscape(f"directory {name!r} changed during cleanup")
    finally:
        os.close(child_fd)
    os.rmdir(name, dir_fd=parent_fd)


def _write_new_file_at(dir_fd, name, data, mode=_PROTECTED_FILE_MODE):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | _CLOEXEC,
                 0o600, dir_fd=dir_fd)
    try:
        os.fchmod(fd, mode)
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Store layout: pinned, validated directory FDs
# ---------------------------------------------------------------------------

class _Layout:
    """Pinned FDs for the store parent, root and protected directories."""

    def __init__(self):
        self.parent_fd = self.root_fd = None
        self.staging_fd = self.quarantine_fd = self.state_fd = None
        self.root_name = None
        self.root_dev = None
        self.aios_dir = None
        self.readonly = False

    def close(self):
        _close_all((self.state_fd, self.quarantine_fd, self.staging_fd, self.root_fd, self.parent_fd))
        self.parent_fd = self.root_fd = self.staging_fd = self.quarantine_fd = self.state_fd = None

    def protected(self):
        return ((STAGING_DIR, self.staging_fd), (QUARANTINE_DIR, self.quarantine_fd),
                (STATE_DIR, self.state_fd))

    def reserved_ids(self):
        ids = set()
        for _name, fd in self.protected():
            if fd is not None:
                st = os.fstat(fd)
                ids.add((st.st_dev, st.st_ino))
        return ids

    def verify(self):
        """Re-validate the pinned layout (owner/mode now, name -> inode binding)."""
        _verify_pinned(self.parent_fd, self.root_name, self.root_fd, "store root")
        _check_store_root(os.fstat(self.root_fd), self.aios_dir)
        for name, fd in self.protected():
            if fd is None:
                continue
            _verify_pinned(self.root_fd, name, fd, name)
            _check_protected_dir(os.fstat(fd), name, self.root_dev, readonly=self.readonly)


def _open_root(aios_dir):
    """Walk the resolved store path from '/' with O_NOFOLLOW; return (parent_fd, root_fd, name)."""
    real = os.path.realpath(aios_dir)
    parts = [p for p in real.split(os.sep) if p]
    if not parts:
        raise L5UnsafeLayoutError("L5 BLOCKED: the filesystem root cannot be an L5 store")
    fds = [os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | _CLOEXEC)]
    try:
        _check_ancestor(os.fstat(fds[0]), os.sep)
        cur = ""
        for i, comp in enumerate(parts):
            cur = cur + os.sep + comp
            try:
                fds.append(os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | _CLOEXEC,
                                   dir_fd=fds[-1]))
            except OSError as exc:
                if exc.errno in _ESCAPE_ERRNOS:
                    raise L5UnsafeLayoutError(f"L5 BLOCKED: {cur!r} changed into a symlink") from exc
                raise
            st = os.fstat(fds[-1])
            if i == len(parts) - 1:
                _check_store_root(st, cur)
            else:
                _check_ancestor(st, cur)
        parent_fd, root_fd = fds[-2], fds[-1]
        _close_all(fds[:-2])
        return parent_fd, root_fd, parts[-1]
    except BaseException:
        _close_all(fds)
        raise


def _open_protected(lay, create, tighten=None):
    tighten = create if tighten is None else tighten
    root_st = os.fstat(lay.root_fd)
    lay.root_dev = root_st.st_dev
    for attr, name in (("staging_fd", STAGING_DIR), ("quarantine_fd", QUARANTINE_DIR),
                       ("state_fd", STATE_DIR)):
        # .quarantine is created lazily, so its mere presence stays a signal.
        try:
            fd = _open_dir_at(lay.root_fd, name, create=create and name != QUARANTINE_DIR,
                              mode=_PROTECTED_DIR_MODE)
        except FileNotFoundError:
            continue
        except _PathEscape as exc:
            raise L5UnsafeLayoutError(f"L5 BLOCKED: {name} is a symlink or not a directory") from exc
        setattr(lay, attr, fd)
        st = os.fstat(fd)
        mode = stat.S_IMODE(st.st_mode)
        if (tighten and st.st_uid == os.geteuid() and stat.S_ISDIR(st.st_mode)
                and not mode & 0o022 and mode & 0o077):
            # Legacy layout (e.g. 0755 from umask): tighten explicitly. Group/
            # other WRITE bits are never tightened silently: refused below.
            os.fchmod(fd, _PROTECTED_DIR_MODE)
            st = os.fstat(fd)
        _check_protected_dir(st, name, lay.root_dev, readonly=not tighten)


def _ensure_protected(lay):
    for attr, name in (("staging_fd", STAGING_DIR), ("state_fd", STATE_DIR)):
        if getattr(lay, attr) is None:
            try:
                fd = _open_dir_at(lay.root_fd, name, create=True, mode=_PROTECTED_DIR_MODE)
            except _PathEscape as exc:
                raise L5UnsafeLayoutError(f"L5 BLOCKED: {name} is a symlink or not a directory") from exc
            setattr(lay, attr, fd)
            _check_protected_dir(os.fstat(fd), name, lay.root_dev)
    os.fsync(lay.root_fd)


def _open_layout(aios_dir, create):
    _require_fd_safe()
    lay = _Layout()
    lay.aios_dir = aios_dir
    lay.readonly = not create
    try:
        lay.parent_fd, lay.root_fd, lay.root_name = _open_root(aios_dir)
        _open_protected(lay, create)
        return lay
    except BaseException:
        lay.close()
        raise


class _MutationLock:
    """Exclusive L5 lock; the lock file is opened relative to the validated parent FD."""

    def __init__(self, aios_dir, create=True):
        self.aios_dir = aios_dir
        self.create = create
        self.fd = None
        self.layout = None

    def __enter__(self):
        _require_fd_safe()
        import fcntl
        os.makedirs(self.aios_dir, exist_ok=True)
        parent_fd, root_fd, name = _open_root(self.aios_dir)
        lay = _Layout()
        lay.aios_dir, lay.parent_fd, lay.root_fd, lay.root_name = self.aios_dir, parent_fd, root_fd, name
        try:
            try:
                self.fd = os.open(_LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | _CLOEXEC,
                                  0o600, dir_fd=parent_fd)
            except OSError as exc:
                if exc.errno in _ESCAPE_ERRNOS:
                    raise L5UnsafeLayoutError("L5 BLOCKED: lock file is a symlink") from exc
                raise
            st = os.fstat(self.fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.geteuid()
                    or stat.S_IMODE(st.st_mode) & 0o022):
                raise L5UnsafeLayoutError("L5 BLOCKED: lock file fails owner/mode/type/link checks")
            fcntl.flock(self.fd, fcntl.LOCK_EX)
            named = os.stat(_LOCK_NAME, dir_fd=parent_fd, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (st.st_dev, st.st_ino):
                raise L5UnsafeLayoutError("L5 BLOCKED: lock file was replaced while acquiring it")
            # Standard state directories are created only after the store root
            # and ancestors are proven not to be attacker-writable.
            state_layout.ensure_state_dirs(self.aios_dir)
            _open_protected(lay, create=self.create, tighten=True)
            lay.verify()
            self.layout = lay
            return self
        except BaseException:
            lay.close()
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            raise

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.layout is not None:
                self.layout.close()
        finally:
            if self.fd is not None:
                os.close(self.fd)  # closing the descriptor releases the flock
                self.fd = None
        return False


# ---------------------------------------------------------------------------
# Strict canonical JSON (journal and state)
# ---------------------------------------------------------------------------

def _no_dup_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise _JournalInvalid(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def _reject_constant(name):
    raise _JournalInvalid(f"non-finite JSON constant {name}")


def _strict_loads(raw, label):
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dup_keys,
                         parse_constant=_reject_constant)
        canonical = canonical_json(obj).encode("utf-8")
    except _JournalInvalid:
        raise
    except (ValueError, UnicodeError, TypeError) as exc:
        raise _JournalInvalid(f"{label} is not valid JSON: {type(exc).__name__}") from exc
    if canonical != raw:
        raise _JournalInvalid(f"{label} is not canonically encoded")
    return obj


def _is_int(v, minimum=0):
    return type(v) is int and v >= minimum


def _exact_keys(obj, keys, label):
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise _JournalInvalid(f"{label} has unexpected or missing fields")


def _valid_dest(parts):
    return (isinstance(parts, list) and 1 <= len(parts) <= 32
            and all(_valid_component(p) for p in parts)
            and parts[0].casefold() not in _RESERVED_FOLDED
            and not parts[-1].endswith(_DEST_TMP_SUFFIX))


def _validate_journal(obj, txn, store_id):
    _exact_keys(obj, ("format", "store_id", "batch_id", "batch_name", "seq", "ops"), "journal")
    if obj["format"] != _JOURNAL_FORMAT or type(obj["format"]) is not int:
        raise _JournalInvalid("journal format is not 3 (legacy/unknown formats are never executed)")
    if obj["store_id"] != store_id:
        raise _JournalInvalid("journal store_id does not match this store")
    if (obj["batch_id"] != txn["batch_id"] or obj["batch_name"] != txn["batch_name"]
            or not _is_int(obj["seq"], 1) or obj["seq"] != txn["seq"]):
        raise _JournalInvalid("journal batch identity/sequence does not match protected state")
    ops = obj["ops"]
    if not isinstance(ops, list) or not ops:
        raise _JournalInvalid("journal ops must be a non-empty list")
    srcs, dests = set(), set()
    for op in ops:
        _exact_keys(op, ("src", "dest", "prior", "new"), "journal op")
        if not isinstance(op["src"], str) or not _STAGED_RE.match(op["src"]):
            raise _JournalInvalid("journal op src is not a staged payload name")
        if not _valid_dest(op["dest"]):
            raise _JournalInvalid("journal op dest is not a valid store-relative path")
        if op["prior"] is not None and not (isinstance(op["prior"], str) and _HEX64.match(op["prior"])):
            raise _JournalInvalid("journal op prior digest is invalid")
        if not (isinstance(op["new"], str) and _HEX64.match(op["new"])):
            raise _JournalInvalid("journal op new digest is invalid")
        folded = tuple(p.casefold() for p in op["dest"])
        if op["src"] in srcs or folded in dests:
            raise _JournalInvalid("journal contains duplicate operations")
        srcs.add(op["src"])
        dests.add(folded)
    return ops


def _validate_state(st):
    _exact_keys(st, ("format", "store_id", "next_seq", "last_finalized_seq", "phase", "txn"), "state")
    if st["format"] != _STATE_FORMAT or type(st["format"]) is not int:
        raise _JournalInvalid("state format unknown")
    if not (isinstance(st["store_id"], str) and _HEX32.match(st["store_id"])):
        raise _JournalInvalid("state store_id invalid")
    if not _is_int(st["next_seq"], 1) or not _is_int(st["last_finalized_seq"], 0):
        raise _JournalInvalid("state sequence counters invalid")
    if st["last_finalized_seq"] >= st["next_seq"]:
        raise _JournalInvalid("state finalized sequence is not below next_seq")
    phase, txn = st["phase"], st["txn"]
    if phase not in _PHASES:
        raise _JournalInvalid("state phase unknown")
    if phase == "IDLE":
        if txn is not None:
            raise _JournalInvalid("IDLE state carries a transaction")
        return
    _exact_keys(txn, ("seq", "batch_id", "batch_name", "batch_dev", "batch_ino",
                      "journal_sha256", "quarantine_id"), "state txn")
    if not _is_int(txn["seq"], 1) or txn["seq"] >= st["next_seq"]:
        raise _JournalInvalid("state txn sequence invalid")
    if not (isinstance(txn["batch_id"], str) and _HEX32.match(txn["batch_id"])
            and txn["batch_name"] == "batch-" + txn["batch_id"]):
        raise _JournalInvalid("state txn batch identity invalid")
    bound = (_is_int(txn["batch_dev"]) and _is_int(txn["batch_ino"])
             and isinstance(txn["journal_sha256"], str) and bool(_HEX64.match(txn["journal_sha256"])))
    unbound = txn["batch_dev"] is None and txn["batch_ino"] is None and txn["journal_sha256"] is None
    if phase == "PREPARED" and not unbound:
        raise _JournalInvalid("PREPARED state is already bound to a journal")
    if phase in _COMMITTED_PHASES + _DONE_PHASES and not bound:
        raise _JournalInvalid(f"{phase} state is not bound to a journal")
    if phase in _DONE_PHASES and st["last_finalized_seq"] != txn["seq"]:
        raise _JournalInvalid(f"{phase} state does not record its sequence as finalized")
    if phase == "QUARANTINED":
        if not (isinstance(txn["quarantine_id"], str) and txn["quarantine_id"]):
            raise _JournalInvalid("QUARANTINED state lacks a quarantine id")
    elif txn["quarantine_id"] is not None:
        raise _JournalInvalid("non-quarantined state carries a quarantine id")


# ---------------------------------------------------------------------------
# Protected persistent transaction state
# ---------------------------------------------------------------------------

def _read_state(lay):
    try:
        fd = _open_regular_at(lay.state_fd, _STATE_NAME)
    except FileNotFoundError:
        return None
    except _PathEscape as exc:
        raise L5UnsafeLayoutError(f"L5 BLOCKED: protected state is not a regular file: {exc}") from exc
    try:
        _check_private_file(os.fstat(fd), "protected state")
        raw = _read_fd(fd)
    except _Untrusted as exc:
        raise L5UnsafeLayoutError(f"L5 BLOCKED: {exc}") from exc
    finally:
        os.close(fd)
    try:
        st = _strict_loads(raw, "protected state")
        _validate_state(st)
    except _JournalInvalid as exc:
        raise L5UnsafeLayoutError(f"L5 BLOCKED: protected state is corrupt: {exc}") from exc
    return st


def _write_state(lay, st):
    """Atomically publish state.json (new inode, fsync file and directory)."""
    _validate_state(st)
    data = canonical_json(st).encode("utf-8")
    tmp = f"{_STATE_NAME}.{uuid.uuid4().hex}.tmp"
    try:
        _write_new_file_at(lay.state_fd, tmp, data)
        _state_replace(tmp, _STATE_NAME, src_dir_fd=lay.state_fd, dst_dir_fd=lay.state_fd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=lay.state_fd)
        except OSError:
            pass
        raise
    os.fsync(lay.state_fd)


def _sweep_state_dir(lay):
    for name in os.listdir(lay.state_fd):
        if name == _STATE_NAME:
            continue
        st = os.stat(name, dir_fd=lay.state_fd, follow_symlinks=False)
        if _STATE_TMP_RE.match(name) and stat.S_ISREG(st.st_mode):
            os.unlink(name, dir_fd=lay.state_fd)
            continue
        raise L5UnsafeLayoutError(f"L5 BLOCKED: unexpected entry {name!r} in protected state directory")


def _txn(seq, batch_id):
    return {"seq": seq, "batch_id": batch_id, "batch_name": f"batch-{batch_id}",
            "batch_dev": None, "batch_ino": None, "journal_sha256": None, "quarantine_id": None}


# ---------------------------------------------------------------------------
# Quarantine (service-owned wrappers; resolution needs a protected record)
# ---------------------------------------------------------------------------

def _quarantine(lay, name, classification, reason, seq=None):
    """Move a staging entry (if present) into a fresh service-owned wrapper.

    The entry itself is moved with renameat (a symlink stays a symlink and is
    never followed); its content is never trusted, executed or chowned. The
    wrapper is created by L5 (0700), so only the service uid or root can place
    the resolution record next to the evidence.
    """
    if lay.quarantine_fd is None:
        try:
            lay.quarantine_fd = _open_dir_at(lay.root_fd, QUARANTINE_DIR, create=True,
                                             mode=_PROTECTED_DIR_MODE)
        except _PathEscape as exc:
            raise L5UnsafeLayoutError("L5 BLOCKED: .quarantine is a symlink or not a directory") from exc
        _check_protected_dir(os.fstat(lay.quarantine_fd), QUARANTINE_DIR, lay.root_dev)
        os.fsync(lay.root_fd)
    for _attempt in range(8):
        label = name[:160] if _valid_component(name) else "entry"   # stay below NAME_MAX
        qid = f"{label}~{uuid.uuid4().hex}"
        try:
            os.mkdir(qid, 0o700, dir_fd=lay.quarantine_fd)
            break
        except FileExistsError:
            continue
    else:
        raise LedgerBlockedError("L5 BLOCKED: could not allocate a unique quarantine id")
    wfd = _open_dir_at(lay.quarantine_fd, qid)
    try:
        os.fchmod(wfd, _PROTECTED_DIR_MODE)
        _check_protected_dir(os.fstat(wfd), f"quarantine {qid}", lay.root_dev)
        moved = False
        if name is not None:
            try:
                os.rename(name, _QEVIDENCE_NAME, src_dir_fd=lay.staging_fd, dst_dir_fd=wfd)
                moved = True
            except FileNotFoundError:
                pass
        meta = canonical_json({"classification": classification, "reason": reason,
                               "staging_entry": name, "evidence_moved": moved, "seq": seq,
                               "quarantined_utc": _utc_iso()}).encode("utf-8")
        _write_new_file_at(wfd, _QMETA_NAME, meta)
        os.fsync(wfd)
    finally:
        os.close(wfd)
    os.fsync(lay.quarantine_fd)
    os.fsync(lay.staging_fd)
    return qid


def _quarantine_txn(lay, st, classification, reason, batch_present=True):
    txn = st["txn"]
    qid = _quarantine(lay, txn["batch_name"] if batch_present else None,
                            classification, reason, seq=txn["seq"])
    new = dict(st, phase="QUARANTINED", txn=dict(txn, quarantine_id=qid))
    if new["txn"]["journal_sha256"] is None:
        new["txn"].update(batch_dev=None, batch_ino=None)
    _write_state(lay, new)
    raise LedgerBlockedError(f"L5 BLOCKED: transaction seq {txn['seq']} quarantined as {qid} "
                             f"({classification}: {reason}); operator resolution required")


def _entry_resolved(lay, name):
    try:
        st = os.stat(name, dir_fd=lay.quarantine_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    if not stat.S_ISDIR(st.st_mode):
        return False
    try:
        wfd = _open_dir_at(lay.quarantine_fd, name)
    except (_PathEscape, FileNotFoundError):
        return False
    try:
        wst = os.fstat(wfd)
        if wst.st_uid != os.geteuid() or stat.S_IMODE(wst.st_mode) & 0o022:
            return False  # attacker-owned or writable evidence can never self-resolve
        try:
            rfd = _open_regular_at(wfd, _RESOLVED_NAME)
        except (FileNotFoundError, _PathEscape):
            return False
        try:
            rst = os.fstat(rfd)
            if (rst.st_nlink != 1 or rst.st_uid not in (0, os.geteuid())
                    or stat.S_IMODE(rst.st_mode) & 0o022):
                return False
            return True
        finally:
            os.close(rfd)
    finally:
        os.close(wfd)


def _unresolved(lay):
    if lay.quarantine_fd is None:
        return []
    out = []
    for name in os.listdir(lay.quarantine_fd):
        st = os.stat(name, dir_fd=lay.quarantine_fd, follow_symlinks=False)
        if (name.endswith(_LEGACY_SIDECAR_SUFFIX) and stat.S_ISREG(st.st_mode)
                and st.st_uid == os.geteuid()):
            continue  # metadata sidecar written by the pre-v3 engine
        if not _entry_resolved(lay, name):
            out.append(name)
    return sorted(out)


def unresolved_quarantine(aios_dir):
    """List unresolved quarantine entries (fd-based; raises on an unsafe layout)."""
    if not os.path.isdir(aios_dir):
        return []
    lay = _open_layout(aios_dir, create=False)
    try:
        return _unresolved(lay)
    finally:
        lay.close()


# ---------------------------------------------------------------------------
# Destination access with CAS
# ---------------------------------------------------------------------------

def _dest_rel_parts(rel_dest):
    if not isinstance(rel_dest, str) or not rel_dest or os.path.isabs(rel_dest):
        raise _PathEscape("destination must be a non-empty store-relative path")
    norm = os.path.normpath(rel_dest)
    parts = norm.split(os.sep)
    if norm.startswith(os.pardir) or not _valid_dest(parts):
        raise _PathEscape(f"invalid or reserved destination: {rel_dest!r}")
    return parts


def _walk_dest_parent(lay, parts, create):
    """Return FDs of the destination's parent chain (last = parent); None if absent."""
    fds = []
    reserved = lay.reserved_ids()
    try:
        cur = lay.root_fd
        for i, comp in enumerate(parts[:-1]):
            try:
                cur = _open_dir_at(cur, comp, create=create, mode=_DEST_NEW_DIR_MODE)
            except FileNotFoundError:
                _close_all(fds)
                return None
            fds.append(cur)
            st = os.fstat(cur)
            if i == 0 and (st.st_dev, st.st_ino) in reserved:
                raise _PathEscape(f"destination aliases a reserved L5 directory: {comp!r}")
            if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o022:
                raise _Untrusted(f"destination directory {comp!r} is foreign-owned or group/other-writable")
        return fds
    except BaseException:
        _close_all(fds)
        raise


def _dest_state_at(parent_fd, name):
    """(digest, mode) of a destination, or (None, None) if absent."""
    try:
        fd = _open_regular_at(parent_fd, name)
    except FileNotFoundError:
        return None, None
    try:
        st = os.fstat(fd)
        if st.st_nlink != 1:
            raise _PathEscape(f"destination {name!r} has {st.st_nlink} hard links")
        if st.st_uid != os.geteuid():
            raise _Untrusted(f"destination {name!r} owned by uid {st.st_uid}")
        h = _new_digest()
        while True:
            chunk = os.read(fd, _COPY_CHUNK)
            if not chunk:
                return h.hexdigest(), stat.S_IMODE(st.st_mode)
            h.update(chunk)
    finally:
        os.close(fd)


def _current_dest_digest(lay, parts):
    fds = _walk_dest_parent(lay, parts, create=False)
    if fds is None:
        return None
    try:
        return _dest_state_at(fds[-1] if fds else lay.root_fd, parts[-1])[0]
    finally:
        _close_all(reversed(fds))


def _sweep_stale_dest_tmps(parent_fd, dest_name):
    prefix = f".{dest_name}."
    for name in os.listdir(parent_fd):
        if name.startswith(prefix) and name.endswith(_DEST_TMP_SUFFIX):
            try:
                os.unlink(name, dir_fd=parent_fd)  # unlink never follows symlinks
            except FileNotFoundError:
                pass


def _apply_op(lay, batch_fd, op):
    """CAS-install one staged payload as a new, digest-verified inode.

    current == new   -> already applied (no write)
    current == prior -> copy staged bytes into a new O_EXCL inode, verify the
                        digest of exactly the copied bytes, rename into place
    otherwise        -> _Conflict (never overwrite unrelated data)
    """
    parts, dest_name = op["dest"], op["dest"][-1]
    fds = _walk_dest_parent(lay, parts, create=True)
    parent = fds[-1] if fds else lay.root_fd
    src = dst = tmp_dest = None
    try:
        current, cur_mode = _dest_state_at(parent, dest_name)
        if current == op["new"]:
            return "already-applied"
        if current != op["prior"]:
            raise _Conflict(f"destination {'/'.join(parts)!r} matches neither prior nor new digest")
        try:
            src = _open_regular_at(batch_fd, op["src"])
        except FileNotFoundError as exc:
            raise _IntegrityError(f"staged payload {op['src']!r} missing and destination not applied") from exc
        _check_private_file(os.fstat(src), f"staged payload {op['src']!r}")
        _sweep_stale_dest_tmps(parent, dest_name)
        tmp_dest = f".{dest_name}.{uuid.uuid4().hex}{_DEST_TMP_SUFFIX}"
        dst = os.open(tmp_dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | _CLOEXEC,
                      0o600, dir_fd=parent)
        h = _new_digest()
        while True:
            chunk = os.read(src, _COPY_CHUNK)
            if not chunk:
                break
            h.update(chunk)          # hash exactly the bytes written below
            _write_all(dst, chunk)
        if h.hexdigest() != op["new"]:
            raise _IntegrityError(f"copied bytes of {op['src']!r} do not match journal digest")
        os.fchmod(dst, _DEST_NEW_FILE_MODE if cur_mode is None else cur_mode & _DEST_MODE_MASK)
        os.fsync(dst)
        mine = os.fstat(dst)
        named = os.stat(tmp_dest, dir_fd=parent, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (mine.st_dev, mine.st_ino):
            raise _PathEscape(f"destination temp {tmp_dest!r} was replaced before install")
        if _dest_state_at(parent, dest_name)[0] != current:
            raise _Conflict(f"destination {'/'.join(parts)!r} changed during install")
        _replace(tmp_dest, dest_name, src_dir_fd=parent, dst_dir_fd=parent)
        tmp_dest = None  # consumed by the rename
        installed = os.stat(dest_name, dir_fd=parent, follow_symlinks=False)
        if (installed.st_dev, installed.st_ino) != (mine.st_dev, mine.st_ino):
            raise _PathEscape(f"destination {dest_name!r} changed during install")
        os.fsync(parent)  # durability of the rename is part of success
        return "applied"
    except BaseException:
        if tmp_dest is not None:
            try:
                os.unlink(tmp_dest, dir_fd=parent)
            except OSError:
                pass
        raise
    finally:
        _close_all((dst, src))
        _close_all(reversed(fds))


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------

_REJECT = (_PathEscape, _IntegrityError, _Conflict, _Untrusted, _JournalInvalid)


def _open_txn_batch(lay, st, bound):
    """Open the batch named by the state. Returns fd or None (absent)."""
    txn = st["txn"]
    try:
        bfd = _open_dir_at(lay.staging_fd, txn["batch_name"])
    except FileNotFoundError:
        return None
    try:
        bst = os.fstat(bfd)
        _check_protected_dir(bst, f"batch {txn['batch_name']}", lay.root_dev)
        if bound and (bst.st_dev, bst.st_ino) != (txn["batch_dev"], txn["batch_ino"]):
            raise _Untrusted("batch directory identity differs from protected state")
    except L5UnsafeLayoutError as exc:
        os.close(bfd)
        raise _Untrusted(str(exc)) from exc
    except BaseException:
        os.close(bfd)
        raise
    return bfd


def _abort_prepared(lay, st):
    """PREPARED: no destination was written (writes require durable APPLYING).

    The batch is removed only if it contains nothing but service-owned L5
    artefacts; anything else is preserved as evidence in quarantine.
    """
    txn = st["txn"]
    try:
        bfd = _open_txn_batch(lay, st, bound=False)
    except _REJECT as exc:
        _quarantine_txn(lay, st, "PREPARED_BATCH_UNTRUSTED", str(exc))
    if bfd is not None:
        try:
            for name in os.listdir(bfd):
                if not (_STAGED_RE.match(name) or name in (_JOURNAL_NAME, _JOURNAL_TMP_NAME)):
                    raise _Untrusted(f"unexpected entry {name!r} in prepared batch")
                _check_private_file(os.stat(name, dir_fd=bfd, follow_symlinks=False),
                                    f"prepared batch entry {name!r}")
        except _REJECT as exc:
            os.close(bfd)
            _quarantine_txn(lay, st, "PREPARED_BATCH_UNTRUSTED", str(exc))
        os.close(bfd)
        _rmtree_at(lay.staging_fd, txn["batch_name"])
        os.fsync(lay.staging_fd)
    new = dict(st, phase="IDLE", txn=None)
    _write_state(lay, new)
    return new


def _cleanup_finalized(lay, st):
    """FINALIZED/CLEANUP: remove residue; never replay."""
    if st["phase"] == "FINALIZED":
        st = dict(st, phase="CLEANUP")
        _write_state(lay, st)
    try:
        bfd = _open_txn_batch(lay, st, bound=True)
    except _REJECT as exc:
        _quarantine(lay, st["txn"]["batch_name"], "FINALIZED_RESIDUE_UNTRUSTED", str(exc),
                          seq=st["txn"]["seq"])
        _write_state(lay, dict(st, phase="IDLE", txn=None))
        raise LedgerBlockedError(f"L5 BLOCKED: residue of finalized seq {st['txn']['seq']} "
                                 f"failed identity checks and was quarantined ({exc})")
    if bfd is not None:
        os.close(bfd)
        _rmtree_at(lay.staging_fd, st["txn"]["batch_name"])
        os.fsync(lay.staging_fd)
    new = dict(st, phase="IDLE", txn=None)
    _write_state(lay, new)
    return new


def _load_bound_journal(lay, st, bfd):
    txn = st["txn"]
    try:
        jfd = _open_regular_at(bfd, _JOURNAL_NAME)
    except FileNotFoundError as exc:
        raise _Untrusted("committed journal is missing") from exc
    try:
        _check_private_file(os.fstat(jfd), "journal")
        raw = _read_fd(jfd)
    finally:
        os.close(jfd)
    if _digest_bytes(raw) != txn["journal_sha256"]:
        raise _Untrusted("journal bytes do not match the digest in protected state")
    return _validate_journal(_strict_loads(raw, "journal"), txn, st["store_id"])


def _preverify(lay, bfd, ops):
    """Check EVERY op before ANY install, so a defect in a later op cannot
    leave earlier ops applied (all-or-nothing roll-forward)."""
    for op in ops:
        current = _current_dest_digest(lay, op["dest"])
        if current == op["new"]:
            continue
        if current != op["prior"]:
            raise _Conflict(f"destination {'/'.join(op['dest'])!r} matches neither prior nor new digest")
        try:
            fd = _open_regular_at(bfd, op["src"])
        except FileNotFoundError as exc:
            raise _IntegrityError(f"staged payload {op['src']!r} missing and destination not applied") from exc
        try:
            _check_private_file(os.fstat(fd), f"staged payload {op['src']!r}")
            h = _new_digest()
            while True:
                chunk = os.read(fd, _COPY_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
        finally:
            os.close(fd)
        if h.hexdigest() != op["new"]:
            raise _IntegrityError(f"staged payload {op['src']!r} diverges from the journal digest")


def _roll_forward(lay, st):
    txn = st["txn"]
    try:
        bfd = _open_txn_batch(lay, st, bound=True)
        if bfd is None:
            raise _Untrusted("committed batch directory is missing")
    except _REJECT as exc:
        _quarantine_txn(lay, st, "COMMITTED_BATCH_UNTRUSTED", str(exc))
    try:
        try:
            ops = _load_bound_journal(lay, st, bfd)
        except _REJECT as exc:
            os.close(bfd)
            bfd = None
            _quarantine_txn(lay, st, "COMMITTED_JOURNAL_UNTRUSTED", str(exc))
        if st["phase"] == "COMMIT_POINT":
            st = dict(st, phase="APPLYING")
            _write_state(lay, st)
        try:
            lay.verify()
            try:
                _verify_pinned(lay.staging_fd, txn["batch_name"], bfd, "batch directory")
            except L5UnsafeLayoutError as exc:
                raise _Untrusted(str(exc)) from exc
            _preverify(lay, bfd, ops)
            for op in ops:
                _apply_op(lay, bfd, op)
        except _REJECT as exc:
            os.close(bfd)
            bfd = None
            _quarantine_txn(lay, st, "ROLL_FORWARD_REJECTED", str(exc))
        except OSError as exc:
            raise RecoveryIncompleteError(
                f"L5 BLOCKED: roll-forward of seq {txn['seq']} interrupted ({exc}); retained") from exc
    finally:
        if bfd is not None:
            os.close(bfd)
    st = dict(st, phase="FINALIZED", last_finalized_seq=txn["seq"])
    _write_state(lay, st)
    return _cleanup_finalized(lay, st)


def _recover_pending_unlocked(lay):
    """Bring the store to IDLE or raise LedgerBlockedError. Caller holds the lock."""
    if lay.state_fd is None and lay.staging_fd is None:
        return None                     # fresh store: nothing was ever staged
    if lay.state_fd is None or lay.staging_fd is None:
        _ensure_protected(lay)
    _sweep_state_dir(lay)
    st = _read_state(lay)
    if st is None:
        st = {"format": _STATE_FORMAT, "store_id": uuid.uuid4().hex, "next_seq": 1,
              "last_finalized_seq": 0, "phase": "IDLE", "txn": None}
        _write_state(lay, st)
    if st["phase"] == "QUARANTINED":
        if st["txn"]["quarantine_id"] in _unresolved(lay):
            raise LedgerBlockedError(
                f"L5 BLOCKED: transaction seq {st['txn']['seq']} is quarantined as "
                f"{st['txn']['quarantine_id']}; operator resolution required")
        st = dict(st, phase="IDLE", txn=None)
        _write_state(lay, st)
    blocked = _unresolved(lay)
    if blocked:
        raise LedgerBlockedError(f"L5 BLOCKED: unresolved quarantined batches: {blocked}")
    expected = st["txn"]["batch_name"] if st["txn"] else None
    foreign = [e for e in sorted(os.listdir(lay.staging_fd)) if e != expected]
    if foreign:
        qids = [_quarantine(lay, e, "UNTRACKED_STAGING_ENTRY",
                                  "staging entry is not referenced by protected L5 state; never executed")
                for e in foreign]
        raise LedgerBlockedError(f"L5 BLOCKED: untracked staging entries quarantined: {qids}")
    lay.verify()
    if st["phase"] == "PREPARED":
        return _abort_prepared(lay, st)
    if st["phase"] in _COMMITTED_PHASES:
        return _roll_forward(lay, st)
    if st["phase"] in _DONE_PHASES:
        return _cleanup_finalized(lay, st)
    return st


def inspect_pending(aios_dir):
    """Read-only inventory of the protected state and staging entries."""
    empty = {"phase": None, "pending": [], "quarantined": []}
    if not os.path.isdir(aios_dir):
        return empty
    lay = _open_layout(aios_dir, create=False)
    try:
        st = _read_state(lay) if lay.state_fd is not None else None
        txn = st["txn"] if st else None
        pending = []
        if lay.staging_fd is not None:
            for entry in sorted(os.listdir(lay.staging_fd)):
                cls = st["phase"] if txn and entry == txn["batch_name"] else "UNTRACKED"
                pending.append({"batch": entry, "classification": cls})
        return {"phase": st["phase"] if st else None, "pending": pending,
                "quarantined": _unresolved(lay)}
    finally:
        lay.close()


def recover_pending(aios_dir):
    """Recover the in-flight transaction (if any) under the L5 lock."""
    with _MutationLock(aios_dir, create=False) as lock:
        _recover_pending_unlocked(lock.layout)


# ---------------------------------------------------------------------------
# Commit
# ---------------------------------------------------------------------------

def commit_batch(aios_dir, payloads, precondition=None):
    """Single shared atomic commit engine under the L5 lock (see state machine above)."""
    with _MutationLock(aios_dir) as lock:
        lay = lock.layout
        _ensure_protected(lay)
        st = _recover_pending_unlocked(lay)
        if precondition is not None:
            precondition(aios_dir)
        lay.verify()

        plan, seen, rels = [], set(), []
        for rel_dest, obj in payloads:
            try:
                parts = _dest_rel_parts(rel_dest)
                folded = tuple(p.casefold() for p in parts)
                if folded in seen:
                    raise _PathEscape(f"duplicate destination in batch: {rel_dest!r}")
                seen.add(folded)
                prior = _current_dest_digest(lay, parts)
            except (_PathEscape, _Untrusted) as exc:
                raise StateConflictError(f"commit destination rejected: {rel_dest!r} ({exc})") from exc
            payload = (canonical_json(obj) + "\n").encode("utf-8")
            plan.append(({"src": f"{uuid.uuid4().hex}.tmp", "dest": parts, "prior": prior,
                          "new": _digest_bytes(payload)}, payload))
            rels.append(rel_dest)
        if not plan:
            raise StateConflictError("commit requires at least one payload")

        batch_id, seq = uuid.uuid4().hex, st["next_seq"]
        st = dict(st, next_seq=seq + 1, phase="PREPARED", txn=_txn(seq, batch_id))
        _write_state(lay, st)                                   # seq allocated, never reused
        txn = st["txn"]
        bfd = None
        try:
            os.mkdir(txn["batch_name"], 0o700, dir_fd=lay.staging_fd)
            bfd = _open_dir_at(lay.staging_fd, txn["batch_name"])
            os.fchmod(bfd, _PROTECTED_DIR_MODE)
            bst = os.fstat(bfd)
            _check_protected_dir(bst, "new batch", lay.root_dev)
            os.fsync(lay.staging_fd)
            for op, payload in plan:
                _write_new_file_at(bfd, op["src"], payload)
            journal = canonical_json({"format": _JOURNAL_FORMAT, "store_id": st["store_id"],
                                      "batch_id": batch_id, "batch_name": txn["batch_name"],
                                      "seq": seq, "ops": [op for op, _ in plan]}).encode("utf-8")
            _write_new_file_at(bfd, _JOURNAL_TMP_NAME, journal)
            _replace(_JOURNAL_TMP_NAME, _JOURNAL_NAME, src_dir_fd=bfd, dst_dir_fd=bfd)
            os.fsync(bfd)
            lay.verify()
            _verify_pinned(lay.staging_fd, txn["batch_name"], bfd, "batch directory")
        except BaseException:
            _close_all((bfd,))
            raise                       # still PREPARED: next recovery aborts; nothing installed
        committed = dict(st, phase="COMMIT_POINT",
                         txn=dict(txn, batch_dev=bst.st_dev, batch_ino=bst.st_ino,
                                  journal_sha256=_digest_bytes(journal)))
        try:
            try:
                _write_state(lay, committed)                    # COMMIT POINT
            except OSError as exc:
                raise RecoveryIncompleteError(
                    f"L5 BLOCKED: commit point of seq {seq} has ambiguous durability ({exc}); "
                    f"recovery decides from protected state") from exc
            st = dict(committed, phase="APPLYING")
            try:
                _write_state(lay, st)
                lay.verify()
                for op, _payload in plan:
                    _apply_op(lay, bfd, op)
            except _REJECT as exc:
                os.close(bfd)
                bfd = None
                _quarantine_txn(lay, st, "COMMIT_REJECTED", str(exc))
            except (OSError, L5UnsafeLayoutError) as exc:
                raise RecoveryIncompleteError(
                    f"L5 BLOCKED: seq {seq} committed but not fully applied ({exc}); retained for recovery") from exc
        finally:
            _close_all((bfd,))
        try:
            st = dict(st, phase="FINALIZED", last_finalized_seq=seq)
            _write_state(lay, st)
            _cleanup_finalized(lay, st)
        except OSError as exc:
            raise RecoveryIncompleteError(
                f"L5 BLOCKED: seq {seq} is applied; finalization/cleanup interrupted ({exc})") from exc
        return [os.path.join(aios_dir, rel) for rel in rels]


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
