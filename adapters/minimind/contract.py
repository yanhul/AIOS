"""MiniMind workload contract validation.

AIOS remains the authority. This module only validates the receipt returned by
an already-authorized external MiniMind workload.
"""

from __future__ import annotations

MINIMIND_CAPABILITY = "minimind.learning@1"
_REQUIRED_ARTIFACTS = {
    "workload_revision",
    "dataset_digest",
    "tokenizer_digest",
    "model_digest",
    "environment_digest",
}
_REQUIRED_EVIDENCE = {
    "training_receipt",
    "evaluation_receipt",
    "provenance",
}
_TERMINAL_STATES = {"PROMOTE", "REJECT", "INCONCLUSIVE", "BLOCKED"}


def _nonempty(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def validate_receipt(receipt: dict) -> dict:
    """Fail closed unless a MiniMind result has complete lineage/evidence."""
    if not isinstance(receipt, dict):
        raise ValueError("receipt must be a dict")
    required = {"capability", "task_id", "terminal_state", "artifacts", "evidence"}
    if set(receipt) != required:
        raise ValueError("MiniMind receipt schema mismatch")
    if receipt["capability"] != MINIMIND_CAPABILITY:
        raise ValueError("MiniMind capability mismatch")
    _nonempty(receipt["task_id"], "task_id")
    if receipt["terminal_state"] not in _TERMINAL_STATES:
        raise ValueError("invalid terminal_state")

    artifacts = receipt["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != _REQUIRED_ARTIFACTS:
        raise ValueError("complete artifact lineage is required")
    for name, value in artifacts.items():
        _nonempty(value, f"artifacts.{name}")

    evidence = receipt["evidence"]
    if not isinstance(evidence, dict) or not _REQUIRED_EVIDENCE.issubset(evidence):
        raise ValueError("training, evaluation, and provenance evidence are required")
    for name in _REQUIRED_EVIDENCE:
        if not isinstance(evidence[name], dict) or not evidence[name]:
            raise ValueError(f"evidence.{name} must be a non-empty object")

    # Reward is explicitly not a promotion authority. A promotion-capable
    # receipt must carry independent evaluation evidence.
    if receipt["terminal_state"] == "PROMOTE":
        evaluation = evidence["evaluation_receipt"]
        if evaluation.get("independent") is not True:
            raise ValueError("promotion requires independent evaluation evidence")
        if evaluation.get("holdout") is not True:
            raise ValueError("promotion requires locked holdout evidence")

    return receipt


__all__ = ["MINIMIND_CAPABILITY", "validate_receipt"]
