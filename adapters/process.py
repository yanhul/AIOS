"""Capability-only bounded subprocess provider adapter."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Sequence

from core.runtime import ProviderReceipt


@dataclass(frozen=True)
class SubprocessAdapter:
    name: str
    command: Sequence[str]
    timeout_seconds: float = 30.0
    max_output_bytes: int = 64 * 1024
    max_input_bytes: int = 64 * 1024

    def execute(self, *, contract: dict, effect: dict, attempt_id: str) -> ProviderReceipt:
        if not self.name.strip():
            raise ValueError("provider name must be non-empty")
        if not self.command or any(not isinstance(part, str) or not part for part in self.command):
            raise ValueError("command must contain non-empty strings")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_output_bytes <= 0 or self.max_input_bytes <= 0:
            raise ValueError("I/O limits must be positive")

        required = ("target_sha", "evidence_ref", "lineage_ref", "idempotency_key", "attempt_fence")
        if any(field not in effect for field in required):
            raise ValueError("effect is missing mandatory Gateway receipt bindings")

        request = json.dumps({"contract": dict(contract), "effect": dict(effect), "attempt_id": attempt_id}, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(request) > self.max_input_bytes:
            raise ValueError("provider request exceeds input limit")
        try:
            completed = subprocess.run(list(self.command), input=request, capture_output=True, timeout=self.timeout_seconds, check=False, shell=False)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("provider timed out") from exc
        if len(completed.stdout) > self.max_output_bytes:
            raise ValueError("provider stdout exceeds output limit")
        if completed.returncode != 0:
            raise RuntimeError(f"provider exited with code {completed.returncode}")
        try:
            payload = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("provider stdout is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("provider receipt must be a JSON object")

        return ProviderReceipt(
            provider=payload.get("provider", ""), effect_id=payload.get("effect_id", ""),
            attempt_id=payload.get("attempt_id", ""), provider_operation_id=payload.get("provider_operation_id", ""),
            outcome=payload.get("outcome", ""), observation=payload.get("observation", {}),
            target_sha=effect["target_sha"], evidence_ref=effect["evidence_ref"],
            lineage_ref=effect["lineage_ref"], idempotency_key=effect["idempotency_key"],
            attempt_fence=effect["attempt_fence"],
        )


__all__ = ["SubprocessAdapter"]
