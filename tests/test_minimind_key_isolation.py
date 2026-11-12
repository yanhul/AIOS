"""MiniMind Ed25519 private-key isolation: adversarial, OS-level tests.

Two layers:
* Always-run tests: fail-closed gating and the workload-side key loader against real files.
* OS end-to-end tests (``AIOS_MINIMIND_ISOLATION_ROLE`` = ``parent`` | ``agent``): run under real,
  distinct Linux UIDs provisioned by ``scripts/minimind_isolation_e2e.sh``. Without that
  provisioning they skip, which means the boundary is UNKNOWN in that environment, never PASS.
"""
import json
import os
import subprocess
import sys
import threading
import time

import pytest

from adapters.minimind.isolation import (
    IsolationError,
    WorkloadIsolation,
    check_sudo_rules,
    iter_uid_processes,
    probe_key_unreadable,
    read_workload_key,
    resolve_trusted_symlinks,
    validate_receipt_command,
)
from adapters.minimind.runner import MiniMindAdapter

ROLE = os.environ.get("AIOS_MINIMIND_ISOLATION_ROLE", "")
FIXTURE_PATH = os.environ.get("AIOS_MINIMIND_ISOLATION_FIXTURE", "")
LINUX = sys.platform.startswith("linux")
ROOT = LINUX and os.geteuid() == 0
LAUNCHER = "/usr/lib/aios-minimind/bin/minimind-workload"


def _fixture():
    if not FIXTURE_PATH:
        pytest.fail("AIOS_MINIMIND_ISOLATION_ROLE set without AIOS_MINIMIND_ISOLATION_FIXTURE")
    with open(FIXTURE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _isolation(fx, **override):
    kw = {"workload_user": fx["workload_user"], "launcher": fx["launcher"], "key_path": fx["key_path"]}
    kw.update(override)
    return WorkloadIsolation(**kw)


def _read(path, mode="rb"):
    with open(path, mode) as fh:
        return fh.read(1)


def _contract():
    return {"task_id": "iso-task-1", "capabilities": ["minimind.learning@1"]}


def _effect():
    return {"effect_id": "EF-iso-1", "contract_id": "C-iso-1", "permit_id": "P-iso-1"}


parent_only = pytest.mark.skipif(ROLE != "parent", reason="OS isolation e2e not provisioned (parent role): UNKNOWN")
agent_only = pytest.mark.skipif(ROLE != "agent", reason="OS isolation e2e not provisioned (agent role): UNKNOWN")
non_root_linux = pytest.mark.skipif(not LINUX or ROOT, reason="workload loader checks need a non-root Linux UID")


# --- 6. missing isolation blocks execution (always run) -------------------------------------

def test_adapter_without_isolation_refuses_to_start(tmp_path):
    marker = tmp_path / "ran"
    adapter = MiniMindAdapter(command=[sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"])
    assert adapter.isolation_status == "MISSING"
    with pytest.raises(IsolationError, match="not configured"):
        adapter.execute(contract=_contract(), effect=_effect(), attempt_id="a-1")
    assert not marker.exists(), "workload must not start without an isolation boundary"


def test_isolated_adapter_rejects_custom_command():
    iso = WorkloadIsolation(workload_user="nobody", launcher=LAUNCHER, key_path="/nonexistent/key")
    with pytest.raises(ValueError, match="command must be empty"):
        MiniMindAdapter(command=["/bin/true"], isolation=iso).execute(
            contract=_contract(), effect=_effect(), attempt_id="a-1")


@pytest.mark.skipif(not LINUX, reason="Linux UID check")
def test_same_uid_workload_is_not_isolation():
    import pwd
    me = pwd.getpwuid(os.geteuid()).pw_name
    with pytest.raises(IsolationError, match="root|own UID"):
        WorkloadIsolation(workload_user=me, launcher=LAUNCHER, key_path="/nonexistent/key").verify()


def test_unsupported_platform_is_blocked(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(IsolationError, match="BLOCKED"):
        WorkloadIsolation(workload_user="minimind", launcher=LAUNCHER, key_path="C:/k").verify()


@pytest.mark.parametrize("rule", [
    "(ALL : ALL) ALL",
    "(root) NOPASSWD: /usr/bin/id",
    "(aios-minimind) NOPASSWD: ALL",
    f"(aios-minimind) NOPASSWD: {LAUNCHER}",
    f'(aios-minimind) NOPASSWD: {LAUNCHER} "", /bin/cat',
    f'(aios-minimind : ALL) NOPASSWD: {LAUNCHER} ""',
])
def test_sudo_rights_broader_than_launcher_are_rejected(rule):
    listing = f"User p may run the following commands on h:\n    {rule}\n"
    with pytest.raises(IsolationError):
        check_sudo_rules(listing, workload_user="aios-minimind", launcher=LAUNCHER)


@pytest.mark.skipif(not LINUX, reason="Linux path trust")
def test_untrusted_symlink_to_sudo_is_rejected(tmp_path):
    link = tmp_path / "sudo"
    os.symlink("/usr/bin/sudo", link)
    with pytest.raises(IsolationError):
        resolve_trusted_symlinks(str(link), kind="sudo")


def test_sudo_rights_exact_launcher_rule_accepted():
    listing = ("Matching Defaults entries for p on h:\n    env_reset\n\n"
               f'User p may run the following commands on h:\n    (aios-minimind) NOPASSWD: {LAUNCHER} ""\n')
    check_sudo_rules(listing, workload_user="aios-minimind", launcher=LAUNCHER)


# --- 3. key replacement / redirection on the workload side (real files, real O_NOFOLLOW) -----

def _private_key_file(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    keydir = tmp_path / "keys"
    keydir.mkdir(mode=0o700)
    os.chmod(keydir, 0o700)
    key = keydir / "ed25519.pem"
    key.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(key, 0o600)
    return keydir, key


@non_root_linux
def test_workload_loader_accepts_private_key(tmp_path):
    _, key = _private_key_file(tmp_path)
    assert read_workload_key(str(key)).startswith(b"-----BEGIN " + b"PRIVATE KEY")


@non_root_linux
def test_workload_loader_rejects_symlink_redirect(tmp_path):
    keydir, key = _private_key_file(tmp_path)
    link = keydir / "redirect.pem"
    os.symlink(key, link)
    with pytest.raises(IsolationError, match="without following links"):
        read_workload_key(str(link))


@non_root_linux
def test_workload_loader_rejects_hardlink_redirect(tmp_path):
    keydir, key = _private_key_file(tmp_path)
    os.link(key, keydir / "second.pem")
    with pytest.raises(IsolationError, match="hard links"):
        read_workload_key(str(key))


@non_root_linux
def test_workload_loader_rejects_shared_key_or_directory(tmp_path):
    keydir, key = _private_key_file(tmp_path)
    os.chmod(key, 0o640)
    with pytest.raises(IsolationError, match="group/other"):
        read_workload_key(str(key))
    os.chmod(key, 0o600)
    os.chmod(keydir, 0o750)
    with pytest.raises(IsolationError, match="key directory"):
        read_workload_key(str(key))


# --- OS end-to-end: parent identity -----------------------------------------------------------

@parent_only
def test_parent_cannot_read_private_key():
    fx = _fixture()
    for attempt in (lambda: _read(fx["key_path"]), lambda: os.stat(fx["key_path"]),
                    lambda: os.listdir(os.path.dirname(fx["key_path"]))):
        with pytest.raises(PermissionError):
            attempt()


@parent_only
def test_parent_cannot_replace_or_redirect_key_or_workload_code(tmp_path):
    fx = _fixture()
    keydir = os.path.dirname(fx["key_path"])
    with pytest.raises(PermissionError):
        os.symlink(str(tmp_path / "attacker.pem"), os.path.join(keydir, "evil.pem"))
    with pytest.raises(PermissionError):
        os.rename(fx["key_path"], fx["key_path"] + ".moved")
    for target in [fx["launcher"], *fx["trusted_files"]]:
        with pytest.raises(PermissionError):
            _read(target, "ab")
    for directory in fx["trusted_dirs"]:
        with pytest.raises(PermissionError):
            _read(os.path.join(directory, "injected.py"), "w")
    # Pointing the boundary at a parent-controlled key is refused by the probe.
    own = tmp_path / "own.pem"
    own.write_text("x")
    with pytest.raises(IsolationError, match="can open"):
        probe_key_unreadable(str(own))
    os.symlink(fx["key_path"], tmp_path / "link.pem")
    with pytest.raises(IsolationError, match="ELOOP"):
        probe_key_unreadable(str(tmp_path / "link.pem"))
    # The caller cannot redirect the boundary to another key: key_path is bound by the root-owned config.
    with pytest.raises(IsolationError, match="does not match the root-owned workload config"):
        _isolation(fx, key_path=str(own)).verify()


@parent_only
def test_parent_cannot_run_arbitrary_commands_as_workload_or_root():
    fx = _fixture()
    for cmd in (["/usr/bin/sudo", "-n", "-u", fx["workload_user"], "/bin/cat", fx["key_path"]],
                ["/usr/bin/sudo", "-n", "-u", fx["workload_user"], fx["launcher"], "--extra"],
                ["/usr/bin/sudo", "-n", "/bin/cat", fx["key_path"]]):
        done = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=20, check=False)
        assert done.returncode != 0, cmd
        assert b"PRIVATE KEY" not in done.stdout + done.stderr


@parent_only
def test_misconfigured_boundary_blocks_execution():
    fx = _fixture()
    with pytest.raises(IsolationError, match="can open"):
        probe_key_unreadable(fx["neg_readable_key"])
    for override, pattern in (({"key_path": fx["neg_readable_key"]}, "does not match"),
                              ({"launcher": fx["neg_launcher"]}, "not root-owned"),
                              ({"workload_user": "aios-no-such-user"}, "does not exist")):
        adapter = MiniMindAdapter(isolation=_isolation(fx, **override))
        with pytest.raises(IsolationError, match=pattern):
            adapter.execute(contract=_contract(), effect=_effect(), attempt_id="a-neg")


NEG_CHAIN = (
    ("agent-exec", "not root-owned"),            # receipt executable writable by another agent
    ("open-ancestor", "group/other writable"),   # writable ancestor directory
    ("symlink-agent", "not root-owned"),         # symlink redirection to an agent-owned file
    ("symlink-trusted", "real path"),            # symlink alias (sudo matches literally)
    ("sha-mismatch", "changed"),                 # launcher content not bound by config
    ("legacy", "legacy 'receipt_command'"),      # inline command list is never accepted
)


@parent_only
def test_untrusted_receipt_chain_blocks_parent_side():
    fx = _fixture()
    cases = [*NEG_CHAIN, ("agent-lib", "workload code")]  # script in signer code tree writable by agent
    for name, pattern in cases:
        adapter = MiniMindAdapter(isolation=_isolation(fx, launcher=f"{fx['neg']}/{name}-launcher"))
        with pytest.raises(IsolationError, match=pattern):
            adapter.execute(contract=_contract(), effect=_effect(), attempt_id=f"a-{name}")


@parent_only
def test_receipt_command_cannot_read_private_key():
    import pwd
    fx = _fixture()
    if os.path.exists(fx["runner_probe"]):
        os.unlink(fx["runner_probe"])
    MiniMindAdapter(isolation=_isolation(fx)).execute(contract=_contract(), effect=_effect(), attempt_id="a-probe")
    with open(fx["runner_probe"], encoding="utf-8") as fh:
        probe = json.load(fh)
    assert probe == {"uid": pwd.getpwnam(fx["runner_user"]).pw_uid, "key_probe": "EACCES"}
    assert probe["uid"] != pwd.getpwnam(fx["workload_user"]).pw_uid


@parent_only
def test_isolated_run_returns_only_signed_receipt_and_public_material():
    from core.provider_ed25519 import ProviderPublicKeyring, ed25519_payload
    fx = _fixture()
    adapter = MiniMindAdapter(isolation=_isolation(fx))
    assert adapter.isolation_status == "DEDICATED_UID"
    evidence = adapter.isolation.verify()
    assert evidence["key_probe"] == "EACCES" and evidence["workload_uid"] != os.geteuid()
    result = adapter.execute(contract=_contract(), effect=_effect(), attempt_id="a-1")
    auth = result.authentication
    assert result.outcome == "OBSERVED_SUCCESS" and auth["key_id"] == fx["key_id"]
    ring = ProviderPublicKeyring({"minimind": {"key_id": fx["key_id"], "public_key": fx["public_key"],
                                               "revoked": False}})
    payload = ed25519_payload(key_id=auth["key_id"], receipt_id=auth["receipt_id"], effect_id="EF-iso-1",
                              contract_id=auth["contract_id"], permit_id=auth["permit_id"], attempt_id="a-1",
                              provider="minimind", provider_operation_id=result.provider_operation_id,
                              outcome=result.outcome, observation=result.observation,
                              issued_at=auth["issued_at"], expires_at=auth["expires_at"])
    ring.verify("minimind", auth["key_id"], auth["signature"], payload)
    blob = json.dumps({"obs": result.observation, "auth": auth})
    assert "PRIVATE KEY" not in blob and fx["key_path"] not in blob


@parent_only
def test_parent_cannot_reach_key_via_workload_process_fds_env_or_argv():
    import pwd
    fx = _fixture()
    uid = pwd.getpwnam(fx["workload_user"]).pw_uid
    adapter = MiniMindAdapter(isolation=_isolation(fx))
    env = adapter.isolation.child_environment()
    assert not any(k.startswith("AIOS_") for k in env)
    assert fx["key_path"] not in " ".join(adapter.isolation.launch_command())
    box = {}
    runner = threading.Thread(target=lambda: box.setdefault("r", adapter.execute(
        contract=_contract(), effect=_effect(), attempt_id="a-2")))
    runner.start()
    seen = {}
    deadline = time.monotonic() + 15
    while runner.is_alive() and time.monotonic() < deadline:
        for pid in iter_uid_processes(uid):
            if pid in seen:
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as fh:
                    seen[pid] = fh.read()
            except OSError:
                continue
            for probe, target in ((_read, f"/proc/{pid}/environ"), (os.listdir, f"/proc/{pid}/fd"),
                                  (_read, f"/proc/{pid}/mem"), (os.readlink, f"/proc/{pid}/cwd")):
                with pytest.raises(PermissionError):
                    probe(target)
        time.sleep(0.05)
    runner.join(30)
    assert "r" in box, "isolated workload did not complete"
    assert seen, "no workload-UID process observed; boundary not exercised"
    for argv in seen.values():
        assert fx["key_path"].encode() not in argv and b"PRIVATE" not in argv
    for fd in os.listdir("/proc/self/fd"):
        try:
            assert os.readlink(f"/proc/self/fd/{fd}") != fx["key_path"]
        except OSError:
            pass


# --- OS end-to-end: a different agent identity ------------------------------------------------

@agent_only
def test_other_agent_cannot_read_key_or_start_workload():
    fx = _fixture()
    with pytest.raises(PermissionError):
        _read(fx["key_path"])
    with pytest.raises(PermissionError):
        os.listdir(os.path.dirname(fx["key_path"]))
    done = subprocess.run(["/usr/bin/sudo", "-n", "-u", fx["workload_user"], fx["launcher"]],
                          stdin=subprocess.DEVNULL, capture_output=True, timeout=20, check=False)
    assert done.returncode != 0
    with pytest.raises(IsolationError):
        _isolation(fx).verify()


@agent_only
def test_other_agent_cannot_modify_executable_chain():
    fx = _fixture()
    for target in fx["trusted_files"]:
        with pytest.raises(PermissionError):
            _read(target, "ab")
        with pytest.raises(PermissionError):
            os.rename(target, target + ".moved")
    for directory in fx["trusted_dirs"]:
        with pytest.raises(PermissionError):
            _read(os.path.join(directory, "injected.py"), "w")


# --- OS end-to-end: root harness (signer-side enforcement, independent of the parent) ---------

root_only = pytest.mark.skipif(ROLE != "root", reason="OS isolation e2e not provisioned (root role): UNKNOWN")


def _run_entry(fx, lib, config):
    request = json.dumps({"contract": _contract(), "effect": _effect(), "attempt_id": "a-root"}).encode()
    return subprocess.run(["/usr/bin/sudo", "-n", "-u", fx["workload_user"], "/usr/bin/python3", "-I", "-S", "-B",
                           f"{lib}/adapters/minimind/workload_entry.py", config],
                          input=request, capture_output=True, timeout=60, check=False, cwd="/")


@root_only
def test_signer_startup_does_not_execute_pth_code():
    """A root-owned executable .pth fixture must remain inert under the production -S launch."""
    import tempfile

    site_dir = "/usr/lib/python3/dist-packages"
    if not os.path.isdir(site_dir):
        pytest.skip("system dist-packages directory is absent")
    marker = os.path.join(tempfile.gettempdir(), f"aios-pth-executed-{os.getpid()}")
    pth = os.path.join(site_dir, f"aios-hostile-{os.getpid()}.pth")
    with open(pth, "w", encoding="utf-8") as fh:
        fh.write("import pathlib; pathlib.Path(" + repr(marker) + ").write_text('executed')")
    os.chmod(pth, 0o644)
    try:
        fx = _fixture()
        done = _run_entry(fx, fx["lib"], fx["config"])
        assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
        assert not os.path.exists(marker), "executable .pth code ran before signer trust checks"
    finally:
        for path in (pth, marker):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


@root_only
def test_signer_entry_refuses_untrusted_receipt_chain():
    fx = _fixture()
    for name, pattern in NEG_CHAIN:
        done = _run_entry(fx, fx["lib"], f"{fx['neg']}/{name}.json")
        assert done.returncode == 3 and done.stdout == b"", (name, done.stderr)
        assert pattern.encode() in done.stderr, (name, done.stderr)
    done = _run_entry(fx, f"{fx['neg']}/lib", fx["config"])  # agent-writable script in signer code
    assert done.returncode == 3 and b"not root-owned" in done.stderr and done.stdout == b""


@root_only
def test_receipt_command_changed_after_validation_is_blocked():
    import hashlib
    import pwd
    import shutil
    fx = _fixture()
    mut = f"{fx['neg']}/mut"
    launcher, config = f"{mut}/receipt-launcher", f"{mut}/workload.json"
    shutil.copyfile(fx["receipt_launcher"], launcher)
    os.chmod(launcher, 0o755)
    with open(fx["config"], encoding="utf-8") as fh:
        cfg = json.load(fh)
    with open(launcher, "rb") as fh:
        cfg.update(receipt_launcher=launcher, receipt_launcher_sha256=hashlib.sha256(fh.read()).hexdigest())
    with open(config, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh)
    os.chmod(config, 0o644)
    signer_uid = pwd.getpwnam(fx["workload_user"]).pw_uid
    assert validate_receipt_command(cfg, signer_uid=signer_uid)["receipt_launcher"] == launcher
    with open(launcher, "a", encoding="utf-8") as fh:
        fh.write(f"cat {fx['key_path']}\n")
    with pytest.raises(IsolationError, match="changed"):
        validate_receipt_command(cfg, signer_uid=signer_uid)
    done = _run_entry(fx, fx["lib"], config)
    assert done.returncode == 3 and b"changed" in done.stderr and done.stdout == b""
