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
* the complete executable chain is derived from the launcher itself (exact two-line form binding one
  interpreter, one code tree and one config): interpreter (root-owned symlink hops only), every file
  of the workload code tree, the config, and the receipt launcher (sha256 bound in the config);
  caller-supplied ``trusted_paths`` are optional extras, never proof;
* the receipt command (the MiniMind workload proper, not trusted with the key) runs as a separate
  ``runner_user`` UID that is neither the signer, the parent nor root;
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


_PYTHON_IMPORT_SUFFIXES = (".py", ".pyc", ".pyo", ".so", ".pyd", ".dll", ".zip", ".egg")
_VERSIONED_NATIVE_LIBRARY = re.compile(r"\.so(?:\.\d+)+$", re.IGNORECASE)


def _is_importable_python_code(path: str) -> bool:
    """Classify Python modules and native code-bearing import dependencies."""
    lowered = path.lower()
    if lowered.endswith(_PYTHON_IMPORT_SUFFIXES) or _VERSIONED_NATIVE_LIBRARY.search(lowered):
        return True
    # Native ELF shared objects may be versioned unusually or have no suffix.
    try:
        with open(path, "rb") as stream:
            return stream.read(4) == b"\x7fELF"
    except OSError as exc:
        raise IsolationError(f"cannot inspect import candidate {path!r}: {exc}") from exc


def _check_trusted_import_directories(root: str, *, kind: str) -> None:
    """Require every directory in a symlinked import subtree to be immutable by non-root.

    Data files may be writable for distro resource packages, but no untrusted user
    may be able to add/replace an importable file after this check.
    """
    pending = [os.path.realpath(root)]
    visited = set()
    while pending:
        directory = pending.pop()
        if directory in visited:
            continue
        visited.add(directory)
        check_trusted_path(directory, kind=f"{kind} directory")
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(entry.path)
                        elif entry.is_symlink():
                            st = entry.stat(follow_symlinks=False)
                            if st.st_uid != 0:
                                raise IsolationError(
                                    f"{kind}: symlink inside import subtree is not root-owned: {entry.path!r}"
                                )
                            target = os.path.realpath(entry.path)
                            target_st = os.stat(entry.path)
                            if stat.S_ISDIR(target_st.st_mode):
                                pending.append(target)
                            elif stat.S_ISREG(target_st.st_mode) and _is_importable_python_code(target):
                                check_trusted_path(target, kind=f"{kind} symlink code target")
                        elif entry.is_file(follow_symlinks=False) and _is_importable_python_code(entry.path):
                            check_trusted_path(entry.path, kind=f"{kind} code file")
                    except OSError as exc:
                        raise IsolationError(f"cannot inspect import-tree entry {entry.path!r}: {exc}") from exc
        except OSError as exc:
            raise IsolationError(f"cannot inspect import-tree directory {directory!r}: {exc}") from exc


def _tree_contains_importable_python_code(root: str) -> bool:
    """Return whether a directory tree contains files Python can import as code.

    Site-package trees can contain symlinked locale/resource data that is writable
    by a data owner. Such files cannot supply modules through normal Python import
    resolution. Code-bearing targets are fully validated.
    """
    pending = [root]
    visited = set()
    while pending:
        directory = pending.pop()
        real = os.path.realpath(directory)
        if real in visited:
            continue
        visited.add(real)
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=True):
                            pending.append(entry.path)
                        elif entry.is_file(follow_symlinks=True) and _is_importable_python_code(entry.path):
                            return True
                    except OSError as exc:
                        raise IsolationError(f"cannot inspect import-tree entry {entry.path!r}: {exc}") from exc
        except OSError as exc:
            raise IsolationError(f"cannot inspect import-tree directory {directory!r}: {exc}") from exc
    return False


def check_trusted_tree(root: str, *, kind: str, _visited: set | None = None) -> int:
    """Validate a root-owned import tree, including the targets of internal symlinks.

    Some distro packages expose importable modules through symlinked directories.
    Their targets are recursively checked; symlink traversal is cycle-safe.
    """
    real_root = os.path.realpath(root)
    visited = _visited if _visited is not None else set()
    if real_root in visited:
        return 0
    visited.add(real_root)
    check_trusted_path(root, kind=kind)
    count = 0

    def fail_on_walk_error(exc: OSError) -> None:
        # os.walk silently ignores traversal errors unless onerror is supplied.
        # A partial trust scan is never sufficient evidence for signer execution.
        raise IsolationError(f"{kind}: cannot traverse trusted tree: {exc}") from exc

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=fail_on_walk_error):
        for name in list(dirnames) + filenames:
            entry = os.path.join(dirpath, name)
            st = os.lstat(entry)
            if stat.S_ISLNK(st.st_mode):
                if st.st_uid != 0:
                    raise IsolationError(f"{kind}: symlink inside trusted tree is not root-owned: {entry!r}")
                target = os.path.realpath(entry)
                try:
                    target_st = os.stat(entry)
                except OSError as exc:
                    raise IsolationError(f"{kind}: broken/unreadable symlink {entry!r}") from exc
                if stat.S_ISDIR(target_st.st_mode):
                    # Even data-only targets must have immutable directory structure:
                    # otherwise code could be added after classification (TOCTOU).
                    _check_trusted_import_directories(target, kind=f"{kind} symlink directory target")
                    if _tree_contains_importable_python_code(target):
                        count += check_trusted_tree(target, kind=f"{kind} symlink directory target",
                                                    _visited=visited)
                elif stat.S_ISREG(target_st.st_mode):
                    # Data symlinks (for example Babel's global.dat) are not Python
                    # import targets. A .py/.so/.zip symlink remains executable code
                    # and its resolved target must satisfy the full trust policy.
                    if _is_importable_python_code(entry):
                        check_trusted_path(target, kind=f"{kind} symlink file target")
                        count += 1
                else:
                    raise IsolationError(f"{kind}: symlink target is not a regular file or directory: {entry!r}")
                continue
            if st.st_uid != 0:
                raise IsolationError(f"{kind}: {entry!r} is not root-owned (uid {st.st_uid})")
            if st.st_mode & 0o022:
                raise IsolationError(f"{kind}: {entry!r} is group/other writable ({oct(st.st_mode & 0o777)})")
            if stat.S_ISREG(st.st_mode):
                count += 1
            elif not stat.S_ISDIR(st.st_mode):
                raise IsolationError(f"{kind}: {entry!r} is not a regular file or directory")
    return count


def prepare_trusted_python_imports(lib: str) -> int:
    """Validate every Python import root before third-party code is allowed to import.

    The signer launcher uses -S, so Python has not processed site directories or .pth files.
    This function validates the stdlib roots, the AIOS code tree, and known platform
    site/dist-packages roots before adding those dependency roots to sys.path.
    """
    import sysconfig

    checked = set()
    roots = set()
    for key in ("stdlib", "platstdlib", "purelib", "platlib"):
        value = sysconfig.get_paths().get(key)
        if value:
            roots.add(os.path.abspath(value))
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    roots.update({
        f"/usr/lib/python{version}",
        "/usr/lib/python3/dist-packages",
        f"/usr/local/lib/python{version}/site-packages",
        f"/usr/local/lib/python{version}/dist-packages",
        f"/usr/lib/python{version}/site-packages",
    })
    roots.update(os.path.abspath(p) for p in sys.path if p)
    roots.add(os.path.abspath(lib))

    for root in sorted(roots):
        if root in checked or not os.path.exists(root):
            continue
        checked.add(root)
        if os.path.isdir(root):
            check_trusted_tree(root, kind=f"Python import tree {root}")
        else:
            check_trusted_path(root, kind=f"Python import file {root}")

    # Only add package roots after their complete trees passed the trust check.
    for key in ("purelib", "platlib"):
        value = sysconfig.get_paths().get(key)
        if value and os.path.isdir(value) and value not in sys.path:
            sys.path.append(value)
    for root in ("/usr/lib/python3/dist-packages",
                 f"/usr/local/lib/python{version}/site-packages",
                 f"/usr/local/lib/python{version}/dist-packages",
                 f"/usr/lib/python{version}/site-packages"):
        if os.path.isdir(root) and root not in sys.path:
            sys.path.append(root)
    return len(checked)


def check_trusted_executable(path: str, *, kind: str) -> str:
    """Resolve root-owned symlink hops, then require a trusted executable. Returns the resolved path."""
    real = resolve_trusted_symlinks(path, kind=kind)
    check_trusted_path(real, kind=kind, executable=True)
    return real


def sha256_file(path: str) -> str:
    import hashlib
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
    finally:
        os.close(fd)


_LAUNCHER_EXEC = re.compile(r"^exec (?P<interp>/\S+) -I -S -B (?P<entry>/\S+/adapters/minimind/workload_entry\.py) "
                            r"(?P<config>/\S+\.json)$")


def parse_signer_launcher(path: str) -> dict:
    """The signer launcher must be exactly ``#!/bin/sh`` + ``exec <python> -I -S -B <lib>/...workload_entry.py <config>``.

    This binds the launcher (which the parent may start) to one interpreter, one code tree and one
    root-owned config; nothing in it comes from the caller.
    """
    with open(path, encoding="utf-8") as fh:
        lines = [line.rstrip("\n") for line in fh.read(4096).splitlines()]
    if len(lines) != 2 or lines[0] != "#!/bin/sh":
        raise IsolationError("signer launcher must be exactly '#!/bin/sh' + one exec line")
    match = _LAUNCHER_EXEC.match(lines[1])
    if not match:
        raise IsolationError("signer launcher exec line has an unexpected form")
    entry = match.group("entry")
    lib = entry[: -len("/adapters/minimind/workload_entry.py")]
    return {"interpreter": match.group("interp"), "entry": entry, "lib": lib, "config": match.group("config")}


CONFIG_KEYS = frozenset({"provider", "key_path", "runner_user", "receipt_launcher", "receipt_launcher_sha256",
                         "timeout", "ttl"})


def load_workload_config(config_path: str) -> dict:
    """Load and validate the root-owned workload config (both parent and workload side)."""
    check_trusted_path(config_path, kind="workload config")
    import json
    with open(config_path, encoding="utf-8") as fh:
        config = json.load(fh)
    if not isinstance(config, dict) or set(config) != CONFIG_KEYS:
        raise IsolationError(f"workload config keys must be exactly {sorted(CONFIG_KEYS)} "
                             "(legacy 'receipt_command' is not accepted)")
    for name in ("provider", "key_path", "runner_user", "receipt_launcher", "receipt_launcher_sha256"):
        if not isinstance(config[name], str) or not config[name]:
            raise IsolationError(f"workload config {name} must be a non-empty string")
    return config


_RECEIPT_LAUNCHER_EXEC = re.compile(
    r"^exec (?P<interp>/\S+) -I -S -B (?P<script>/\S+\.py)$"
)


def parse_receipt_launcher(path: str) -> dict:
    """Require a fixed isolated-Python invocation with no caller-controlled arguments."""
    try:
        with open(path, encoding="utf-8") as fh:
            lines = [line.rstrip("\n") for line in fh.read(4096).splitlines()]
    except OSError as exc:
        raise IsolationError(f"cannot read receipt launcher: {exc}") from exc
    if len(lines) != 2 or lines[0] != "#!/bin/sh":
        raise IsolationError("receipt launcher must be exactly '#!/bin/sh' + one exec line")
    match = _RECEIPT_LAUNCHER_EXEC.fullmatch(lines[1])
    if not match:
        raise IsolationError("receipt launcher must invoke an absolute interpreter with exactly -I -S -B and one .py script")
    return {"interpreter": match.group("interp"), "script": match.group("script")}


def validate_receipt_command(config: dict, *, signer_uid: int, parent_uids=()) -> dict:
    """Validate the key-isolated receipt runner and its immutable launcher.

    The launcher is hash-bound and its invocation is constrained to isolated Python
    startup (-I -S -B), with one root-owned script and no additional arguments.
    Returns the resolved launcher path and runner UID; raises IsolationError otherwise.
    """
    import pwd
    try:
        runner = pwd.getpwnam(config["runner_user"])
    except KeyError as exc:
        raise IsolationError(f"receipt runner user {config['runner_user']!r} does not exist") from exc
    if runner.pw_uid == 0 or runner.pw_uid == signer_uid or runner.pw_uid in set(parent_uids):
        raise IsolationError("receipt command must run as a dedicated non-root UID distinct from the "
                             "signing identity and the parent")
    launcher = config["receipt_launcher"]
    real = check_trusted_executable(launcher, kind="receipt launcher")
    if real != os.path.normpath(launcher):
        raise IsolationError("receipt launcher must be referenced by its real path (sudo matches it literally)")
    actual = sha256_file(real)
    if actual != config["receipt_launcher_sha256"]:
        raise IsolationError("receipt launcher content does not match the config-bound sha256 (changed)")
    invocation = parse_receipt_launcher(real)
    check_trusted_executable(invocation["interpreter"], kind="receipt interpreter")
    check_trusted_path(invocation["script"], kind="receipt script")
    return {"receipt_launcher": real, "runner_uid": runner.pw_uid,
            "receipt_launcher_sha256": actual, "receipt_interpreter": invocation["interpreter"],
            "receipt_script": invocation["script"]}


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
        # The complete trust set is derived from the launcher and its config, never from the caller.
        bound = parse_signer_launcher(self.launcher)
        check_trusted_executable(bound["interpreter"], kind="signer interpreter")
        check_trusted_tree(bound["lib"], kind="workload code")
        config = load_workload_config(bound["config"])
        if os.path.normpath(config["key_path"]) != os.path.normpath(self.key_path):
            raise IsolationError("key_path does not match the root-owned workload config")
        receipt = validate_receipt_command(config, signer_uid=workload.pw_uid, parent_uids=uids)
        for extra in self.trusted_paths:  # optional extras only; never a substitute for the above
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
                "key_probe": probe, "launcher": self.launcher, "config": bound["config"],
                "runner_uid": receipt["runner_uid"], "receipt_launcher_sha256": receipt["receipt_launcher_sha256"]}


def _check_private(st: os.stat_result, *, what: str, euid: int, allow_root: bool) -> None:
    owners = {euid, 0} if allow_root else {euid}
    if st.st_uid not in owners:
        raise IsolationError(f"{what} is owned by uid {st.st_uid}, not the workload")
    if st.st_mode & 0o077:
        raise IsolationError(f"{what} grants group/other access ({oct(st.st_mode & 0o777)})")


def _open_private_key_directory(path: str, *, euid: int) -> int:
    """Open the key directory component-by-component without following symlinks.

    Keep the directory descriptors pinned until the key has been opened. This prevents
    an attacker from swapping an ancestor after its permissions have been checked.
    Root-owned non-writable ancestors and the sticky shared temporary directory are
    accepted; every other ancestor must be owned by root/the workload and not writable
    by group or other users. The final key directory is private to root/the workload.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    current_fd = os.open("/", flags)
    try:
        parts = [part for part in os.path.normpath(path).split(os.sep) if part]
        if not parts:
            raise IsolationError("key path must name a file below a directory")
        for index, part in enumerate(parts):
            try:
                next_fd = os.open(part, flags, dir_fd=current_fd)
            except OSError as exc:
                raise IsolationError(
                    f"cannot safely open key path directory component {part!r}: {exc.strerror}"
                ) from exc
            st = os.fstat(next_fd)
            if not stat.S_ISDIR(st.st_mode):
                os.close(next_fd)
                raise IsolationError(f"key path component {part!r} is not a directory")
            is_key_directory = index == len(parts) - 1
            if is_key_directory:
                try:
                    _check_private(st, what="key directory", euid=euid, allow_root=True)
                except Exception:
                    os.close(next_fd)
                    raise
            else:
                if st.st_uid not in (0, euid):
                    os.close(next_fd)
                    raise IsolationError(
                        f"key path ancestor {part!r} is owned by untrusted uid {st.st_uid}"
                    )
                writable = bool(st.st_mode & 0o022)
                sticky_shared = bool(st.st_mode & stat.S_ISVTX)
                if writable and not sticky_shared:
                    os.close(next_fd)
                    raise IsolationError(
                        f"key path ancestor {part!r} is group/other writable"
                    )
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def read_workload_key(path: str) -> bytes:
    """Workload side: read the PEM key only if its entire path is private and stable."""
    _require_linux()
    euid = os.geteuid()
    if euid == 0:
        raise IsolationError("workload must not run as root")
    if not isinstance(path, str) or not os.path.isabs(path):
        raise IsolationError("key path must be absolute")
    normalized = os.path.normpath(path)
    key_name = os.path.basename(normalized)
    if key_name in ("", ".", ".."):
        raise IsolationError("key path must name a file")
    directory_fd = _open_private_key_directory(os.path.dirname(normalized), euid=euid)
    try:
        try:
            fd = os.open(key_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
        except OSError as exc:
            raise IsolationError(
                f"cannot open workload key without following links: {exc.strerror}"
            ) from exc
    finally:
        os.close(directory_fd)
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
