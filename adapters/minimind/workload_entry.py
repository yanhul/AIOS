"""Isolated MiniMind workload entry point (runs as the dedicated workload UID).

Started only by the root-owned launcher through ``sudo -n -u <workload_user> -- <launcher>``.
Usage (inside the launcher): ``python3 -I -B <lib>/adapters/minimind/workload_entry.py <config.json>``

* The config is root-owned and not writable by group/other; the parent cannot change it.
* The request (contract/effect/attempt) arrives on stdin; the private key path comes only from
  the config, never from the parent, argv, environment or stdin.
* ``receipt_command`` (the MiniMind workload proper) is run without the key loaded and must
  print ``{"minimind_receipt": {...}}``. The entry validates it, then loads the key
  (:func:`load_workload_signer`), signs, and prints only the signed envelope.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

_LIB = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)

from adapters.minimind.contract import (
    MINIMIND_CAPABILITY,
    outcome_for_terminal_state,
    validate_receipt,
)
from adapters.minimind.isolation import (
    check_trusted_path,
    load_workload_signer,
)

MAX_REQUEST_BYTES = 128 * 1024
MAX_RECEIPT_BYTES = 256 * 1024


def _fail(message: str) -> int:
    sys.stderr.write(f"minimind workload refused: {message}\n")
    return 3


def main(argv) -> int:
    if len(argv) != 2:
        return _fail("usage: workload_entry.py <config.json>")
    config_path = argv[1]
    try:
        check_trusted_path(config_path, kind="workload config")
        with open(config_path, encoding="utf-8") as fh:
            config = json.load(fh)
        provider = config.get("provider", "minimind")
        key_path = config["key_path"]
        command = config["receipt_command"]
        timeout = float(config.get("timeout", 60))
        ttl = float(config.get("ttl", 300))
        if not isinstance(command, list) or not command or not all(isinstance(c, str) and c for c in command):
            return _fail("receipt_command must be a non-empty list of strings")

        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            return _fail("request exceeds input limit")
        request = json.loads(raw.decode("utf-8"))
        contract, effect, attempt = request["contract"], request["effect"], request["attempt_id"]
        task_id = contract["task_id"]
        if MINIMIND_CAPABILITY not in contract.get("capabilities", []):
            return _fail("capability not granted")

        done = subprocess.run(command, input=raw, capture_output=True, timeout=timeout, check=False,
                              close_fds=True, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        if done.returncode != 0:
            return _fail(f"receipt command exited {done.returncode}")
        if len(done.stdout) > MAX_RECEIPT_BYTES:
            return _fail("receipt exceeds output limit")
        produced = json.loads(done.stdout.decode("utf-8"))
        receipt = validate_receipt(produced["minimind_receipt"])
        if receipt["task_id"] != task_id or receipt["capability"] != MINIMIND_CAPABILITY:
            return _fail("receipt binding mismatch")
        outcome = outcome_for_terminal_state(receipt["terminal_state"])
        operation_id = f"{provider}:{task_id}:{attempt}"

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
