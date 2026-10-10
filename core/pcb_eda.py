"""Governed contract for PCB EDA capabilities.

AIOS owns authorization, evidence requirements, lifecycle, and terminal
promotion. The external PCB toolchain owns design-specific parsing/planning/
mutation. This module deliberately contains no PCB heuristics.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Mapping

TERMINAL_STATES = frozenset({"PASS", "BLOCKED", "INCONCLUSIVE"})
SCHEMATIC_PHASE = "SCHEMATIC"
SCHEMATIC_REQUIRED_GATES = ("G0_INTAKE", "G1_PARSE", "G2_COMPILE", "G3_CONNECTIVITY")


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
    phase: str = "PCB"

    def validate(self) -> None:
        for name in ("task_id", "input_dir", "output_dir", "kit_root"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} is required")
        if self.max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if self.config is not None and not isinstance(self.config, str):
            raise ValueError("config must be a string or None")
        if self.phase not in {"PCB", SCHEMATIC_PHASE}:
            raise ValueError("phase must be PCB or SCHEMATIC")


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


def validate_schematic_receipt(receipt: Mapping[str, Any]) -> None:
    """Fail closed on schematic evidence without requiring PCB closure gates."""
    if not isinstance(receipt, Mapping):
        raise ValueError("schematic receipt is not a mapping")
    if receipt.get("schema") != "altium-audit-e2e-phase/v2":
        raise ValueError("unsupported schematic receipt schema")
    if receipt.get("phase") != SCHEMATIC_PHASE:
        raise ValueError("receipt is not a schematic phase receipt")
    status = receipt.get("status")
    if status not in {"PASS", "BLOCKED"}:
        raise ValueError(f"unauthorized schematic phase status: {status!r}")
    evidence = receipt.get("evidence")
    if not isinstance(evidence, Mapping):
        raise ValueError("schematic receipt requires evidence")
    gates = evidence.get("required_gates")
    if not isinstance(gates, Mapping):
        raise ValueError("schematic receipt requires required_gates evidence")
    if status == "PASS" and any(gates.get(k) != "VERIFIED" for k in SCHEMATIC_REQUIRED_GATES):
        raise ValueError("schematic PASS lacks G0/G1/G2/G3 verification")
    inventory = evidence.get("finding_inventory")
    if not isinstance(inventory, Mapping):
        raise ValueError("schematic receipt requires finding inventory")
    deferred = inventory.get("deferred_non_gating")
    if not isinstance(deferred, list):
        raise ValueError("schematic receipt must preserve deferred findings explicitly")
    unknown = inventory.get("unknown")
    if not isinstance(unknown, list):
        raise ValueError("schematic receipt requires an explicit UNKNOWN finding inventory")
    required_unknown = evidence.get("required_unknown_findings", [])
    if not isinstance(required_unknown, list):
        raise ValueError("required_unknown_findings must be a list")
    deferred_ids = {
        item.get("id") for item in deferred
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    unresolved_schematic = [
        item for item in unknown
        if isinstance(item, Mapping)
        and item.get("domain") == "schematic"
        and item.get("id") not in deferred_ids
    ]
    if status == "PASS" and (inventory.get("errors") or inventory.get("blocking")):
        raise ValueError("schematic PASS contains effective blocking findings")
    if status == "PASS" and required_unknown:
        raise ValueError("schematic PASS contains unresolved required UNKNOWN findings")
    if status == "PASS" and unresolved_schematic:
        raise ValueError("schematic PASS contains UNKNOWN schematic findings outside explicit deferrals")


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


__all__ = ["PcbEdaRequest", "TERMINAL_STATES", "SCHEMATIC_PHASE", "SCHEMATIC_REQUIRED_GATES", "validate_kit_receipt", "validate_schematic_receipt", "reconcile_pcb_eda"]
