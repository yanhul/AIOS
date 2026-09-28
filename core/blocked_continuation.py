"""Governed BLOCKED continuation planning for external capabilities.

This module classifies only observed blocker evidence. It never invents PCB
values, topology, placement, routing, or electrical limits.
"""
from __future__ import annotations
from typing import Any, Mapping

BLOCKER_REQUIREMENTS = {
    "board_edge_clearance": ("placement_geometry", "board_outline", "clearance_rule"),
    "assembly_access": ("mechanical_envelope", "assembly_constraint", "placement_authority"),
    "current_capacity": ("load_requirement", "copper_capacity_rule", "electrical_authority"),
    "topology": ("net_connectivity_evidence", "routing_authority", "closure_verification"),
}

def classify_blockers(verification: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = verification.get("blockers") or verification.get("findings") or []
    if not isinstance(raw, list):
        raise ValueError("blocker evidence must be a list")
    out = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        ident = str(item.get("id") or item.get("code") or item.get("domain") or "").lower()
        if "edge" in ident:
            kind = "board_edge_clearance"
        elif "assembly" in ident or "access" in ident:
            kind = "assembly_access"
        elif "current" in ident or "capacity" in ident:
            kind = "current_capacity"
        elif "topology" in ident or "routing" in ident or "connect" in ident:
            kind = "topology"
        else:
            continue
        out.append({"kind": kind, "source": dict(item)})
    return out

def plan_blocked_continuation(verification: Mapping[str, Any], state: Mapping[str, Any]) -> Mapping[str, Any] | None:
    blockers = classify_blockers(verification)
    if not blockers:
        return None
    completed = set(state.get("verified_evidence_refs") or [])
    required = []
    for b in blockers:
        for ref in BLOCKER_REQUIREMENTS[b["kind"]]:
            if ref not in required:
                required.append(ref)
    missing = [x for x in required if x not in completed]
    # Discovery is allowed to produce a task plan, but redispatch is allowed
    # only after evidence has been independently verified and persisted.
    if missing:
        return {
            "authority": "AIOS_CONTROL_PLANE",
            "evidence_refs": [f"DISCOVERY_REQUIRED:{x}" for x in missing],
            "next_operation_id": "pcb.eda.discover_evidence",
            "reason": "BLOCKED requires verified evidence before pcb.eda redispatch",
            "blockers": blockers,
            "requires_verification": missing,
        }
    refs = sorted(completed)
    return {
        "authority": "AIOS_CONTROL_PLANE",
        "evidence_refs": refs,
        "next_operation_id": "pcb.eda@1",
        "reason": "verified blocker evidence permits a new PCB EDA attempt",
        "blockers": blockers,
    }

__all__ = ["BLOCKER_REQUIREMENTS", "classify_blockers", "plan_blocked_continuation"]
