"""Governed contract for PCB EDA capabilities.

AIOS owns authorization, evidence requirements, lifecycle, and terminal
promotion. The external PCB toolchain owns design-specific parsing/planning/
mutation. This module deliberately contains no PCB heuristics.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Mapping

TERMINAL_STATES = frozenset({"PASS", "BLOCKED", "INCONCLUSIVE"})


@dataclass(frozen=True)
class PcbEdaRequest:
    task_id: str
    input_dir: str
    output_dir: str
    kit_root: str
    config: str | None = None
    repair: bool = True
    max_retries: int = 3
    policy_digest: str | None = None

    def validate(self) -> None:
        for name in ("task_id", "input_dir", "output_dir", "kit_root"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} is required")
        if self.max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if self.config is not None and not isinstance(self.config, str):
            raise ValueError("config must be a string or None")


def validate_kit_receipt(receipt: Mapping[str, Any]) -> None:
    """Fail closed unless the Kit emitted a terminal result with evidence."""
    if not isinstance(receipt, Mapping):
        raise ValueError("PCB EDA receipt is not a mapping")
    status = receipt.get("status")
    if status not in TERMINAL_STATES:
        raise ValueError(f"unauthorized PCB EDA terminal status: {status!r}")
    schema = receipt.get("schema")
    if schema != "altium-audit-kit-result.v4":
        raise ValueError("unsupported PCB EDA receipt schema")
    if not isinstance(receipt.get("terminal_reason"), str) and status != "PASS":
        raise ValueError("non-PASS PCB EDA result requires terminal_reason")
    if status == "PASS":
        gates = receipt.get("gates")
        if not isinstance(gates, Mapping):
            raise ValueError("PASS PCB EDA result requires gate evidence")
        required = ("G3_CONNECTIVITY", "G6_PLACEMENT", "G7_ROUTING")
        if any(gates.get(k) != "VERIFIED" for k in required):
            raise ValueError("PASS PCB EDA result lacks connectivity/placement/routing closure")


def reconcile_pcb_eda(request: PcbEdaRequest, receipt: Mapping[str, Any]) -> Mapping[str, Any]:
    request.validate()
    validate_kit_receipt(receipt)
    return {
        "task_id": request.task_id,
        "status": receipt["status"],
        "requires_aios_verification": True,
        "promotion_authority": "AIOS_CONTROL_PLANE",
        "kit_schema": receipt["schema"],
        "terminal_reason": receipt.get("terminal_reason"),
    }


__all__ = ["PcbEdaRequest", "TERMINAL_STATES", "validate_kit_receipt", "reconcile_pcb_eda"]
