"""Bounded subprocess adapter for an externally owned MiniMind workload.

The adapter does not import MiniMind. It sends one JSON request to a separately
installed workload runner and accepts only a validated MiniMind workload receipt.
AIOS runtime remains responsible for authorization and durable state.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Sequence

from core.runtime import ProviderReceipt

from .contract import validate_receipt


@dataclass(frozen=True)
class MiniMindAdapter:
    """Execute one bounded MiniMind workload operation through a subprocess."""

    command: Sequence[str]
    name: str = "minimind"
    timeout_seconds: float = 60.0
    max_output_bytes: int = 256 * 1024
    max_input_bytes: int = 128 * 1024

    def execute(self, *, contract: dict, effect: dict, attempt_id: str) -> ProviderReceipt:
        if not self.name.strip():
            raise ValueError("provider name must be non-empty")
        if not self.command or any(not isinstance(part, str) or not part for part in self.command):
            raise ValueError("command must contain non-empty strings")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_output_bytes <= 0 or self.max_input_bytes <= 0:
            raise ValueError("I/O limits must be positive")

        request = json.dumps(
            {"contract": dict(contract), "effect": dict(effect), "attempt_id": attempt_id},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(request) > self.max_input_bytes:
            raise ValueError("MiniMind request exceeds input limit")

        try:
            completed = subprocess.run(
                list(self.command),
                input=request,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("MiniMind workload timed out") from exc

        if len(completed.stdout) > self.max_output_bytes:
            raise ValueError("MiniMind stdout exceeds output limit")
        if completed.returncode != 0:
            raise RuntimeError(f"MiniMind workload exited with code {completed.returncode}")

        try:
            receipt = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("MiniMind stdout is not valid JSON") from exc

        validate_receipt(receipt)
        if receipt["task_id"] != contract.get("task_id"):
            raise ValueError("MiniMind receipt task binding mismatch")
        if receipt["capability"] != self._capability(contract):
            raise ValueError("MiniMind receipt capability binding mismatch")

        return ProviderReceipt(
            provider=self.name,
            effect_id=effect["effect_id"],
            attempt_id=attempt_id,
            provider_operation_id=f"{self.name}:{receipt['task_id']}:{attempt_id}",
            outcome="OBSERVED_SUCCESS",
            observation={"minimind_receipt": receipt},
        )

    @staticmethod
    def _capability(contract: dict) -> str:
        capabilities = contract.get("capabilities", [])
        expected = "minimind.learning@1"
        if expected not in capabilities:
            raise PermissionError("MiniMind capability is not granted by contract")
        return expected


__all__ = ["MiniMindAdapter"]
