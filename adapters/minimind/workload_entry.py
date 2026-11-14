"""Isolated MiniMind signer entry point (runs as the dedicated key-owning workload UID).

Started only by the root-owned launcher through ``sudo -n -u <workload_user> -- <launcher>``.
Usage (inside the launcher): ``python3 -I -S -B <lib>/adapters/minimind/workload_entry.py <config.json>``

Trust split (audit P1, executable trust boundary):

* This process holds the signing key and executes **only** immutable root-owned code. Before the
  key is read it verifies its interpreter, every file of its code tree and every loaded module file
  (root-owned, no group/other write, no attacker-controlled symlink or ancestor).
* The receipt command (the MiniMind workload proper) is **not** trusted with the key. It runs as a
  separate ``runner_user`` UID through a root-owned ``receipt_launcher`` whose sha256 is bound in the
  root-owned config, via the signer's own exact sudo rule. It cannot open the key (different UID,
  ``0700``/``0600``) and only returns ``{"minimind_receipt": {...}}`` on stdout.
* The key path comes only from the config; the key is read after the receipt command has exited and
  is never written to stdout/stderr/argv/env.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

_LIB = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)

# Import only the stdlib-backed isolation module before the trust check. The launcher
# uses -I -S: site.py and executable .pth files have not run at this point.
from adapters.minimind.isolation import (
    IsolationError,
    check_sudo_rules,
    check_trusted_executable,
    check_trusted_path,
    check_trusted_tree,
    load_workload_config,
    load_workload_signer,
    prepare_trusted_python_imports,
    resolve_trusted_symlinks,
    validate_receipt_command,
)


SUDO = "/usr/bin/sudo"
_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
MAX_REQUEST_BYTES = 128 * 1024
MAX_RECEIPT_BYTES = 256 * 1024
MAX_RECEIPT_STDERR_BYTES = 64 * 1024


def verify_signer_code() -> int:
    """Interpreter, code tree and every loaded module file must be immutable root-owned code."""
    check_trusted_executable(sys.executable, kind="signer interpreter")
    count = check_trusted_tree(_LIB, kind="signer code")
    for entry in sys.path:  # import roots: lazily imported code must come from trusted dirs too
        if not entry:
            raise IsolationError("empty sys.path entry (cwd) is not allowed in the signer")
        target = entry if os.path.exists(entry) else os.path.dirname(entry)
        check_trusted_path(resolve_trusted_symlinks(os.path.abspath(target), kind="import root"),
                           kind="import root")
    for name, module in list(sys.modules.items()):
        origin = getattr(module, "__file__", None)
        if not origin:
            continue
        real = resolve_trusted_symlinks(os.path.abspath(origin), kind=f"module {name}")
        check_trusted_path(real, kind=f"module {name}")
    return count


def run_receipt_command(config: dict, raw: bytes, timeout: float) -> bytes:
    runner = validate_receipt_command(config, signer_uid=os.geteuid(),
                                      parent_uids=[int(os.environ["SUDO_UID"])] if
                                      os.environ.get("SUDO_UID", "").isdigit() else [])
    check_trusted_path(resolve_trusted_symlinks(SUDO, kind="sudo"), kind="sudo", executable=True, setuid=True)
    listing = subprocess.run([SUDO, "-n", "-l"], stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
                             env=dict(_ENV), check=False)
    if listing.returncode != 0:
        raise IsolationError("signer has no usable sudo rule for the receipt runner")
    check_sudo_rules(listing.stdout.decode("utf-8", "replace"), workload_user=config["runner_user"],
                     launcher=runner["receipt_launcher"])
    # The receipt runner is workload code and is not trusted with the signer's key.
    # Enforce both stream caps while it is running; checking len(stdout) after
    # subprocess.run(capture_output=True) would already have allowed unbounded
    # memory growth inside this key-owning signer process.
    from adapters.bounded_process import run_bounded

    done = run_bounded(
        [SUDO, "-n", "-u", config["runner_user"], "--", runner["receipt_launcher"]],
        input=raw,
        timeout=timeout,
        max_stdout_bytes=MAX_RECEIPT_BYTES,
        max_stderr_bytes=MAX_RECEIPT_STDERR_BYTES,
        cwd="/",
        env=dict(_ENV),
    )
    if done.returncode != 0:
        raise RuntimeError(f"receipt command exited {done.returncode}")
    return done.stdout


def _fail(message: str) -> int:
    sys.stderr.write(f"minimind workload refused: {message}\n")
    return 3


def main(argv) -> int:
    if len(argv) != 2:
        return _fail("usage: workload_entry.py <config.json>")
    try:
        if os.geteuid() == 0:
            return _fail("signer must not run as root")
        verify_signer_code()
        prepare_trusted_python_imports(_LIB)
        # Third-party and remaining AIOS modules are imported only after their complete roots
        # have been checked while Python site initialization was disabled with -S.
        from cryptography.hazmat.primitives import serialization  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401
        import core.provider_ed25519  # noqa: F401
        from adapters.minimind.contract import (
            MINIMIND_CAPABILITY, outcome_for_terminal_state, validate_receipt,
        )
        config = load_workload_config(argv[1])
        provider, key_path = config["provider"], config["key_path"]
        timeout, ttl = float(config["timeout"]), float(config["ttl"])

        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            return _fail("request exceeds input limit")
        request = json.loads(raw.decode("utf-8"))
        contract, effect, attempt = request["contract"], request["effect"], request["attempt_id"]
        task_id = contract["task_id"]
        if MINIMIND_CAPABILITY not in contract.get("capabilities", []):
            return _fail("capability not granted")

        stdout = run_receipt_command(config, raw, timeout)
        if len(stdout) > MAX_RECEIPT_BYTES:
            return _fail("receipt exceeds output limit")
        produced = json.loads(stdout.decode("utf-8"))
        receipt = validate_receipt(produced["minimind_receipt"])
        if receipt["task_id"] != task_id or receipt["capability"] != MINIMIND_CAPABILITY:
            return _fail("receipt binding mismatch")
        outcome = outcome_for_terminal_state(receipt["terminal_state"])
        operation_id = f"{provider}:{task_id}:{attempt}"

        verify_signer_code()  # re-check right before the key is read
        signer = load_workload_signer(provider, key_path, ttl)
        authentication = signer.sign(effect=effect, attempt_id=attempt, provider_operation_id=operation_id,
                                     outcome=outcome, observation={"minimind_receipt": receipt})
        del signer
    except Exception as exc:  # noqa: BLE001 - fail closed; never echo key material (exceptions carry no key bytes)
        return _fail(f"{type(exc).__name__}: {exc}")
    envelope = {"minimind_receipt": receipt, "outcome": outcome, "provider_operation_id": operation_id,
                "authentication": authentication}
    sys.stdout.write(json.dumps(envelope, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
