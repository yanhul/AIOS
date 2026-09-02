"""Thin durable-runtime adapter contract.

AIOS owns authorization and evidence semantics. External runtimes own
scheduling, persistence, retry timing, and agent execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol


@dataclass(frozen=True)
class RuntimeSubmission:
    effect_id: str
    attempt_id: str
    provider: str


class DurableRuntime(Protocol):
    """Minimal runtime surface; no policy authority is delegated here."""

    name: str

    def submit(self, *, effect: Mapping[str, Any], attempt_id: str) -> RuntimeSubmission:
        ...

    def resume(self, *, effect: Mapping[str, Any], attempt_id: str) -> RuntimeSubmission:
        ...

    def retry(self, *, effect: Mapping[str, Any], attempt_id: str, attempt: int) -> RuntimeSubmission:
        ...


def validate_submission(
    effect: Mapping[str, Any],
    submission: RuntimeSubmission,
    attempt_id: str,
    provider_name: str,
) -> None:
    """Fail closed unless runtime acknowledgement binds to this effect/attempt/provider."""
    if not isinstance(submission, RuntimeSubmission):
        raise ValueError("runtime must return RuntimeSubmission")
    if submission.effect_id != effect.get("effect_id"):
        raise ValueError("runtime submission effect mismatch")
    if submission.attempt_id != attempt_id:
        raise ValueError("runtime submission attempt mismatch")
    if submission.provider != provider_name:
        raise ValueError("runtime submission provider mismatch")


__all__ = ["DurableRuntime", "RuntimeSubmission", "validate_submission"]
