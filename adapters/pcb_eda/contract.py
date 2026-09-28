"""AIOS-governed contract for the external PCB/EDA workload.

The PCB implementation remains independently owned. This module owns only the
AIOS boundary: capability binding, artifact lineage, evidence requirements,
and promotion-safe receipt validation.
"""
from __future__ import annotations

PCB_CAPABILITY = "pcb.eda@1"
_ALLOWED_OPERATIONS = {"audit", "repair", "optimize"}
_TERMINAL_STATES = {"PASS", "BLOCKED", "INCONCLUSIVE"}
_REQUIRED_ARTIFACTS = {"input_digest", "output_digest", "workload_revision"}
_REQUIRED_EVIDENCE = {"intake", "connectivity", "placement", "routing", "provenance"}


def _nonempty(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def validate_receipt(receipt: dict, *, expected_operation: str | None = None) -> dict:
    """Fail closed unless the PCB workload receipt is complete and bound."""
    if not isinstance(receipt, dict):
        raise ValueError("receipt must be a dict")
    required = {"capability", "task_id", "operation", "terminal_state", "artifacts", "evidence"}
    if set(receipt) != required:
        raise ValueError("PCB receipt schema mismatch")
    if receipt["capability"] != PCB_CAPABILITY:
        raise ValueError("PCB capability mismatch")
    _nonempty(receipt["task_id"], "task_id")
    operation = receipt["operation"]
    if operation not in _ALLOWED_OPERATIONS:
        raise ValueError("invalid PCB operation")
    if expected_operation is not None and operation != expected_operation:
        raise ValueError("PCB operation binding mismatch")
    if receipt["terminal_state"] not in _TERMINAL_STATES:
        raise ValueError("invalid terminal_state")

    artifacts = receipt["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != _REQUIRED_ARTIFACTS:
        raise ValueError("complete PCB artifact lineage is required")
    for name, value in artifacts.items():
        _nonempty(value, f"artifacts.{name}")

    evidence = receipt["evidence"]
    if not isinstance(evidence, dict) or not _REQUIRED_EVIDENCE.issubset(evidence):
        raise ValueError("PCB verification evidence is incomplete")
    for name in _REQUIRED_EVIDENCE:
        if not isinstance(evidence[name], dict) or not evidence[name]:
            raise ValueError(f"evidence.{name} must be a non-empty object")

    if receipt["terminal_state"] == "PASS":
        for gate in ("connectivity", "placement", "routing"):
            if evidence[gate].get("status") != "VERIFIED":
                raise ValueError(f"PASS requires {gate}=VERIFIED")
    if operation == "optimize" and receipt["terminal_state"] == "PASS":
        quality = evidence.get("routing", {})
        if quality.get("optimization_status") != "VERIFIED":
            raise ValueError("optimization PASS requires optimization_status=VERIFIED")
    return receipt


__all__ = ["PCB_CAPABILITY", "validate_receipt"]
