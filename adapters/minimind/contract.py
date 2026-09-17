"""MiniMind workload contract validation.

AIOS remains the authority. This module validates receipts returned by an
already-authorized external MiniMind workload and binds evidence to artifacts.
"""
from __future__ import annotations

MINIMIND_CAPABILITY = "minimind.learning@1"
_REQUIRED_ARTIFACTS = {"workload_revision", "dataset_digest", "tokenizer_digest", "model_digest", "environment_digest"}
_REQUIRED_EVIDENCE = {"training_receipt", "evaluation_receipt", "provenance"}
_TERMINAL_STATES = {"PROMOTE", "REJECT", "INCONCLUSIVE", "BLOCKED"}
_BINDINGS = ("workload_revision", "dataset_digest", "tokenizer_digest", "model_digest", "environment_digest")
_GATEWAY_BINDINGS = {"target_sha", "evidence_ref", "lineage_ref", "idempotency_key", "attempt_fence"}

def _nonempty(value, name):
    if not isinstance(value, str) or not value.strip(): raise ValueError(f"{name} must be a non-empty string")

def _require_artifact_bindings(evidence, artifacts, name):
    if not isinstance(evidence, dict) or not evidence: raise ValueError(f"evidence.{name} must be a non-empty object")
    for field in _BINDINGS:
        if evidence.get(field) != artifacts[field]:
            raise ValueError(f"evidence.{name}.{field} does not match declared artifact lineage")

def validate_receipt(receipt: dict) -> dict:
    """Fail closed unless workload lineage and Gateway bindings are present."""
    if not isinstance(receipt, dict): raise ValueError("receipt must be a dict")
    required = {"capability", "task_id", "terminal_state", "artifacts", "evidence"} | _GATEWAY_BINDINGS
    if set(receipt) != required: raise ValueError("MiniMind receipt schema mismatch")
    if receipt["capability"] != MINIMIND_CAPABILITY: raise ValueError("MiniMind capability mismatch")
    _nonempty(receipt["task_id"], "task_id")
    if receipt["terminal_state"] not in _TERMINAL_STATES: raise ValueError("invalid terminal_state")
    for field in ("target_sha", "evidence_ref", "lineage_ref", "idempotency_key"):
        _nonempty(receipt[field], field)
    if not isinstance(receipt["attempt_fence"], int) or isinstance(receipt["attempt_fence"], bool) or receipt["attempt_fence"] < 0:
        raise ValueError("attempt_fence must be a non-negative integer")
    artifacts = receipt["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != _REQUIRED_ARTIFACTS: raise ValueError("complete artifact lineage is required")
    for name, value in artifacts.items(): _nonempty(value, f"artifacts.{name}")
    evidence = receipt["evidence"]
    if not isinstance(evidence, dict) or not _REQUIRED_EVIDENCE.issubset(evidence): raise ValueError("training, evaluation, and provenance evidence are required")
    _require_artifact_bindings(evidence["training_receipt"], artifacts, "training_receipt")
    _require_artifact_bindings(evidence["evaluation_receipt"], artifacts, "evaluation_receipt")
    _require_artifact_bindings(evidence["provenance"], artifacts, "provenance")
    if receipt["terminal_state"] == "PROMOTE":
        evaluation = evidence["evaluation_receipt"]
        if evaluation.get("independent") is not True: raise ValueError("promotion requires independent evaluation evidence")
        if evaluation.get("holdout") is not True: raise ValueError("promotion requires locked holdout evidence")
    return receipt

__all__ = ["MINIMIND_CAPABILITY", "validate_receipt"]
