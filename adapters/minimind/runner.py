"""Bounded subprocess adapter for an externally owned MiniMind workload.

Trust boundary (audit F-04, model A: provider-authenticated execution)
----------------------------------------------------------------------
The MiniMind workload is a separately installed process. It - not this
adapter - signs its own receipt with the ``minimind`` provider key, which it
obtains from its own secret store (separate uid/container/secret mount). The
AIOS parent process and the executing agent never hold that key:

* this adapter has no signer and never signs or re-signs a workload result;
* it refuses to run (fail closed) if the parent environment exposes the
  ``minimind`` signing key, because then the parent could forge receipts;
* it withholds every AIOS signing key and verifier keyring from the child
  environment (an HMAC verifier keyring would let the child forge too).

The adapter only validates the workload receipt schema and its bindings and
derives the effect outcome from the workload's terminal state:
``PROMOTE`` -> ``OBSERVED_SUCCESS``; ``REJECT``/``INCONCLUSIVE``/``BLOCKED``
-> ``OBSERVED_FAILURE``. ``core.effect_authority.observe`` verifies the
signature against the deployment ``AIOS_PROVIDER_KEYRING``; anything not
verifiable stays ``UNKNOWN``.
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from typing import Mapping, Sequence

from adapters.bounded_process import OutputLimitExceeded, output_limit_error, run_bounded, timeout_error

from core.effect_authority import PROVIDER_KEYRING_ENV, RETRY_KEYRING_ENV
from core.provider_authority import PROVIDER_SIGNING_KEYS_ENV
from core.runtime import ProviderReceipt

from .contract import MINIMIND_CAPABILITY, outcome_for_terminal_state, validate_receipt

# Never forwarded to the workload process.
WITHHELD_ENV = frozenset({PROVIDER_SIGNING_KEYS_ENV, PROVIDER_KEYRING_ENV, RETRY_KEYRING_ENV})
_ENVELOPE_REQUIRED = {"minimind_receipt", "outcome", "provider_operation_id"}
_ENVELOPE_ALLOWED = _ENVELOPE_REQUIRED | {"authentication"}


def provider_operation_id(provider: str, task_id: str, attempt_id: str) -> str:
    """Deterministic operation id the workload must sign (shared with the workload side)."""
    return f"{provider}:{task_id}:{attempt_id}"


def _parent_holds_key(provider: str, environ: Mapping[str, str]) -> bool:
    raw = environ.get(PROVIDER_SIGNING_KEYS_ENV)
    if not raw:
        return False
    try:
        keys = json.loads(raw)
    except ValueError:
        return True  # unparseable: cannot prove the key is absent -> fail closed
    return not isinstance(keys, dict) or provider in keys


@dataclass(frozen=True)
class MiniMindAdapter:
    """Execute one bounded MiniMind workload operation through a subprocess."""

    command: Sequence[str]
    name: str = "minimind"
    timeout_seconds: float = 60.0
    max_output_bytes: int = 256 * 1024
    max_input_bytes: int = 128 * 1024

    def child_environment(self, environ: Mapping[str, str] | None = None) -> dict:
        source = os.environ if environ is None else environ
        if _parent_holds_key(self.name, source):
            raise PermissionError(
                f"AIOS parent environment exposes the {self.name!r} provider signing key; "
                "workload receipts would be forgeable by the parent (fail closed)")
        return {k: v for k, v in source.items() if k not in WITHHELD_ENV}

    def execute(self, *, contract: dict, effect: dict, attempt_id: str) -> ProviderReceipt:
        if not self.name.strip():
            raise ValueError("provider name must be non-empty")
        if not self.command or any(not isinstance(part, str) or not part for part in self.command):
            raise ValueError("command must contain non-empty strings")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_output_bytes <= 0 or self.max_input_bytes <= 0:
            raise ValueError("I/O limits must be positive")
        capability = self._capability(contract)
        task_id = contract.get("task_id")
        if not isinstance(task_id, str) or not task_id.strip():
            raise ValueError("contract task_id must be a non-empty string")
        env = self.child_environment()

        request = json.dumps(
            {"contract": dict(contract), "effect": dict(effect), "attempt_id": attempt_id},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(request) > self.max_input_bytes:
            raise ValueError("MiniMind request exceeds input limit")

        try:
            completed = run_bounded(
                list(self.command),
                input=request,
                timeout=self.timeout_seconds,
                max_stdout_bytes=self.max_output_bytes,
                max_stderr_bytes=self.max_output_bytes,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise timeout_error("MiniMind workload timed out", exc) from exc
        except OutputLimitExceeded as exc:
            raise output_limit_error(f"MiniMind {exc.stream} exceeds output limit", exc) from exc

        if completed.returncode != 0:
            raise RuntimeError(f"MiniMind workload exited with code {completed.returncode}")

        try:
            envelope = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("MiniMind stdout is not valid JSON") from exc
        if (not isinstance(envelope, dict) or not _ENVELOPE_REQUIRED.issubset(envelope)
                or not set(envelope).issubset(_ENVELOPE_ALLOWED)):
            raise ValueError("MiniMind signed receipt envelope schema mismatch")

        receipt = validate_receipt(envelope["minimind_receipt"])
        if receipt["task_id"] != task_id:
            raise ValueError("MiniMind receipt task binding mismatch")
        if receipt["capability"] != capability:
            raise ValueError("MiniMind receipt capability binding mismatch")
        expected_outcome = outcome_for_terminal_state(receipt["terminal_state"])
        if envelope["outcome"] != expected_outcome:
            raise ValueError(f"MiniMind outcome {envelope['outcome']!r} does not match terminal_state "
                             f"{receipt['terminal_state']!r} (expected {expected_outcome})")
        operation_id = provider_operation_id(self.name, task_id, attempt_id)
        if envelope["provider_operation_id"] != operation_id:
            raise ValueError("MiniMind provider_operation_id binding mismatch")

        return ProviderReceipt(
            provider=self.name,
            effect_id=effect["effect_id"],
            attempt_id=attempt_id,
            provider_operation_id=operation_id,
            outcome=expected_outcome,
            observation={"minimind_receipt": receipt},
            # Signed by the workload itself; absent/invalid -> observe() keeps UNKNOWN.
            # The parent passes it through unmodified and never signs on its behalf.
            authentication=envelope.get("authentication"),
        )

    @staticmethod
    def _capability(contract: dict) -> str:
        if MINIMIND_CAPABILITY not in contract.get("capabilities", []):
            raise PermissionError("MiniMind capability is not granted by contract")
        return MINIMIND_CAPABILITY


__all__ = ["MiniMindAdapter", "WITHHELD_ENV", "provider_operation_id"]
