"""MiniMind Ed25519 private-key isolation boundary (deployment/runtime level).

Supported platform: **Linux only** (dedicated workload UID entered through a
restricted ``sudo`` rule). Every other platform - including Windows and
non-Linux POSIX - is BLOCKED: :meth:`WorkloadIsolation.verify` raises
:class:`IsolationError` and the adapter never runs the workload.

Parent side (:class:`WorkloadIsolation`), checked before every launch, fail closed:

* parent is not root, has no effective/permitted/ambient capabilities and does not
  share the workload UID or primary group;
* ``sudo``, the launcher and every extra trusted path (workload code, config) are
  root-owned with no group/other write anywhere on their path (the parent cannot
  replace the code that runs with the workload identity);
* the parent's ``sudo -n -l`` rights are **exactly** ``(workload_user) <launcher> ""``
  (no arguments, no other rule): the parent can start the workload but cannot run
  any other command as the workload user or as root;
* a real ``open()`` of the private-key path by the parent is refused by the kernel
  with ``EACCES`` (OS-level probe, not a mode-bit inference).

The key path is never passed to the child: the workload reads it from its own
root-owned config. The child gets a minimal environment; ``sudo`` closes inherited
descriptors above stderr. The parent only receives the signed envelope on stdout.

Workload side (:func:`load_workload_signer`): the key is opened with ``O_NOFOLLOW``
and must be a regular, single-link file owned by the workload's effective UID with
no group/other bits, in a directory owned by that UID (or root) with no group/other
bits. Anything else refuses to sign.
"""
from __future__ import annotations

import errno
import os
import re
import stat
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field

SUPPORTED_PLATFORM = "linux"
_CAP_FIELDS = ("CapEff", "CapPrm", "CapAmb")
_MINIMAL_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


class IsolationError(PermissionError):
    """The private-key isolation boundary is not established; the workload must not run."""


def _require_linux() -> None:
    if not sys.platform.startswith(SUPPORTED_PLATFORM):
        raise IsolationError(f"MiniMind key isolation is not implemented on {sys.platform!r}: BLOCKED")


def _process_capabilities() -> dict:
    caps = {}
    with open("/proc/self/status", encoding="ascii") as fh:
        for line in fh:
            name, _, value = line.partition(":")
            if name in _CAP_FIELDS:
                caps[name] = int(value.strip(), 16)
    if set(caps) != set(_CAP_FIELDS):
        raise IsolationError("cannot determine parent capabilities from /proc/self/status")
    return caps


def check_trusted_path(path: str, *, kind: str, executable: bool = False, setuid: bool = False) -> None:
    """``path`` and all its ancestors must be root-owned without group/other write; no symlinks."""
    if not isinstance(path, str) or not os.path.isabs(path):
        raise IsolationError(f"{kind} path must be absolute: {path!r}")
    if os.path.realpath(path) != os.path.normpath(path):
        raise IsolationError(f"{kind} path must not traverse symlinks: {path!r}")
    current = os.path.normpath(path)
    first = True
    while True:
        try:
            st = os.lstat(current)
        except OSError as exc:
            raise IsolationError(f"{kind}: cannot stat {current!r}: {exc.strerror}") from exc
        if st.st_uid != 0:
            raise IsolationError(f"{kind}: {current!r} is not root-owned (uid {st.st_uid})")
        if st.st_mode & 0o022:
            raise IsolationError(f"{kind}: {current!r} is group/other writable ({oct(st.st_mode & 0o777)})")
        if first:
            if stat.S_ISDIR(st.st_mode):
                if executable or setuid:
                    raise IsolationError(f"{kind}: {current!r} is a directory")
            elif not stat.S_ISREG(st.st_mode):
                raise IsolationError(f"{kind}: {current!r} is not a regular file or directory")
            if executable and not st.st_mode & 0o111:
                raise IsolationError(f"{kind}: {current!r} is not executable")
            if setuid != bool(st.st_mode & stat.S_ISUID):
                raise IsolationError(f"{kind}: {current!r} setuid bit {'missing' if setuid else 'present'}")
            first = False
        elif not stat.S_ISDIR(st.st_mode):
            raise IsolationError(f"{kind}: ancestor {current!r} is not a directory")
        parent = os.path.dirname(current)
        if parent == current:
            return
        current = parent


def resolve_trusted_symlinks(path: str, *, kind: str, max_hops: int = 8) -> str:
    """Follow symlinks only if every link is root-owned inside a trusted (root-owned, no g/o write) dir.

    Distributions ship ``/usr/bin/sudo`` via alternatives symlinks; an attacker-controlled hop blocks.
    """
    if not isinstance(path, str) or not os.path.isabs(path):
        raise IsolationError(f"{kind} path must be absolute: {path!r}")
    current = os.path.normpath(path)
    for _ in range(max_hops):
        directory = os.path.dirname(current)
        check_trusted_path(os.path.realpath(directory), kind=f"{kind} directory")
        if os.path.realpath(directory) != directory:
            current = os.path.join(os.path.realpath(directory), os.path.basename(current))
            continue
        try:
            st = os.lstat(current)
        except OSError as exc:
            raise IsolationError(f"{kind}: cannot stat {current!r}: {exc.strerror}") from exc
        if not stat.S_ISLNK(st.st_mode):
            return current
        if st.st_uid != 0:
            raise IsolationError(f"{kind}: symlink {current!r} is not root-owned")
        current = os.path.normpath(os.path.join(directory, os.readlink(current)))
    raise IsolationError(f"{kind}: too many symlink hops")


_RULE = re.compile(r"^\((?P<runas>[^)]*)\)\s+(?P<rest>.+)$")
_TAG = re.compile(r"^(?:[A-Z_]+:\s*)+")


def check_sudo_rules(listing: str, *, workload_user: str, launcher: str) -> None:
    """Parsed ``sudo -n -l`` output must grant only ``(workload_user) launcher ""``."""
    marker = "may run the following commands"
    if marker not in listing:
        raise IsolationError("sudo -l output has no command section; parent sudo rights are unknown")
    section = listing.split(marker, 1)[1].splitlines()[1:]
    rules = [line.strip() for line in section if line.strip()]
    if not rules:
        raise IsolationError("parent has no sudo rule for the workload launcher")
    expected = f'{launcher} ""'
    for rule in rules:
        match = _RULE.match(rule)
        if not match:
            raise IsolationError(f"unrecognised sudo rule (fail closed): {rule!r}")
        runas = [part.strip() for part in match.group("runas").split(":")]
        if runas[0] != workload_user or (len(runas) > 1 and runas[1] not in ("", workload_user)) or len(runas) > 2:
            raise IsolationError(f"parent may run commands as {match.group('runas')!r}; only "
                                 f"({workload_user}) is permitted")
        commands = _TAG.sub("", match.group("rest").strip())
        if [c.strip() for c in commands.split(",")] != [expected]:
            raise IsolationError(f"parent sudo rule is broader than {expected!r}: {commands!r}")


def probe_key_unreadable(key_path: str) -> str:
    """Real OS probe: the parent's ``open()`` of the key must fail with EACCES."""
    if not isinstance(key_path, str) or not os.path.isabs(key_path):
        raise IsolationError("key_path must be absolute")
    try:
        fd = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except PermissionError:
        return "EACCES"
    except OSError as exc:
        raise IsolationError(f"key path probe returned {errno.errorcode.get(exc.errno, exc.errno)} instead of "
                             "EACCES; the key directory must be untraversable by the parent") from exc
    os.close(fd)
    raise IsolationError("AIOS parent process can open the MiniMind private key: isolation BLOCKED")


@dataclass(frozen=True)
class WorkloadIsolation:
    """Linux dedicated-UID boundary for the MiniMind workload."""

    workload_user: str
    launcher: str
    key_path: str
    trusted_paths: tuple = field(default_factory=tuple)
    sudo: str = "/usr/bin/sudo"
    sudo_timeout: float = 10.0

    def launch_command(self) -> list:
        return [self.sudo, "-n", "-u", self.workload_user, "--", self.launcher]

    @staticmethod
    def child_environment() -> dict:
        return dict(_MINIMAL_ENV)

    def verify(self) -> dict:
        """Establish the boundary or raise :class:`IsolationError`. Returns non-secret evidence."""
        _require_linux()
        import pwd

        if not isinstance(self.workload_user, str) or not self.workload_user.strip():
            raise IsolationError("workload_user must be a non-empty string")
        try:
            workload = pwd.getpwnam(self.workload_user)
        except KeyError as exc:
            raise IsolationError(f"workload user {self.workload_user!r} does not exist") from exc
        uids = {os.getuid(), os.geteuid()}
        if 0 in uids:
            raise IsolationError("AIOS parent runs as root and can read any key: isolation BLOCKED")
        if workload.pw_uid == 0:
            raise IsolationError("workload user must not be root")
        if workload.pw_uid in uids:
            raise IsolationError("workload user is the parent's own UID: same-UID execution is not isolation")
        if workload.pw_gid in {os.getgid(), os.getegid(), *os.getgroups()}:
            raise IsolationError("parent is a member of the workload's primary group")
        caps = _process_capabilities()
        if any(caps.values()):
            raise IsolationError(f"parent holds Linux capabilities {caps}: isolation BLOCKED")

        check_trusted_path(resolve_trusted_symlinks(self.sudo, kind="sudo"), kind="sudo", executable=True,
                           setuid=True)
        check_trusted_path(self.launcher, kind="launcher", executable=True)
        for extra in self.trusted_paths:
            check_trusted_path(extra, kind="trusted path")

        try:
            listing = subprocess.run([self.sudo, "-n", "-l"], stdin=subprocess.DEVNULL, capture_output=True,
                                     timeout=self.sudo_timeout, env=dict(_MINIMAL_ENV), check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise IsolationError(f"cannot list parent sudo rights: {exc}") from exc
        if listing.returncode != 0:
            raise IsolationError("parent has no usable non-interactive sudo rule for the workload")
        check_sudo_rules(listing.stdout.decode("utf-8", "replace"), workload_user=self.workload_user,
                         launcher=self.launcher)
        probe = probe_key_unreadable(self.key_path)
        return {"platform": sys.platform, "parent_uid": os.geteuid(), "workload_uid": workload.pw_uid,
                "key_probe": probe, "launcher": self.launcher}


def _check_private(st: os.stat_result, *, what: str, euid: int, allow_root: bool) -> None:
    owners = {euid, 0} if allow_root else {euid}
    if st.st_uid not in owners:
        raise IsolationError(f"{what} is owned by uid {st.st_uid}, not the workload")
    if st.st_mode & 0o077:
        raise IsolationError(f"{what} grants group/other access ({oct(st.st_mode & 0o777)})")


def read_workload_key(path: str) -> bytes:
    """Workload side: read the PEM key only if it is private to the workload identity."""
    _require_linux()
    euid = os.geteuid()
    if euid == 0:
        raise IsolationError("workload must not run as root")
    if not os.path.isabs(path):
        raise IsolationError("key path must be absolute")
    _check_private(os.lstat(os.path.dirname(path)), what="key directory", euid=euid, allow_root=True)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise IsolationError(f"cannot open workload key without following links: {exc.strerror}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise IsolationError("workload key is not a regular file")
        if st.st_nlink != 1:
            raise IsolationError("workload key has extra hard links (possible redirection)")
        _check_private(st, what="workload key", euid=euid, allow_root=False)
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def load_workload_signer(provider: str, path: str, ttl_seconds: float = 300):
    from cryptography.hazmat.primitives import serialization

    from core.provider_ed25519 import Ed25519ReceiptSigner

    pem = read_workload_key(path)
    key = serialization.load_pem_private_key(pem, password=None)
    del pem
    return Ed25519ReceiptSigner(provider, key, ttl_seconds)


def iter_uid_processes(uid: int) -> Iterable[int]:
    """PIDs owned by ``uid`` (readable /proc metadata only); used by adversarial tests/ops checks."""
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                if os.stat(f"/proc/{entry}").st_uid == uid:
                    yield int(entry)
            except OSError:
                continue


__all__ = [
    "SUPPORTED_PLATFORM",
    "IsolationError",
    "WorkloadIsolation",
    "check_sudo_rules",
    "check_trusted_path",
    "iter_uid_processes",
    "load_workload_signer",
    "probe_key_unreadable",
    "read_workload_key",
    "resolve_trusted_symlinks",
]
