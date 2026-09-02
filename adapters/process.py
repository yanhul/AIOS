"""Capability-only subprocess provider adapter.

This adapter is deliberately generic: AIOS owns authorization and durable
state; the subprocess only receives a bounded JSON request and must return a
single JSON receipt. No subprocess is allowed to write AIOS state directly.
"""

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

    def execute(self, *, contract: dict, effect: dict, attempt_id: str) -> ProviderReceipt:
        if not self.name.strip():
            raise ValueError("provider name must be non-empty")
        if not self.command:
            raise ValueError("command must not be empty")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        request = {
            "contract": dict(contract),
            "effect": dict(effect),
            "attempt_id": attempt_id,
        }
        completed = subprocess.run(
            list(self.command),
            input=json.dumps(request, sort_keys=True),
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"provider exited with code {completed.returncode}")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise ValueError("provider stdout is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("provider receipt must be a JSON object")

        return ProviderReceipt(
            provider=payload.get("provider", ""),
            effect_id=payload.get("effect_id", ""),
            attempt_id=payload.get("attempt_id", ""),
            provider_operation_id=payload.get("provider_operation_id", ""),
            outcome=payload.get("outcome", ""),
            observation=payload.get("observation", {}),
        )


__all__ = ["SubprocessAdapter"]
