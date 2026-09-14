"""AIOS evidence classification and promotion gate.

Advisory findings are never authoritative. Only evidence satisfying an explicit
policy may advance a claim toward promotion. UNKNOWN/ERROR/NOT_RUN fail closed.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Mapping

NON_AUTHORITATIVE = frozenset({"ADVISORY", "UNKNOWN", "ERROR", "NOT_RUN"})
VERIFIED_LEVELS = frozenset({"VERIFIED_DIGITAL", "VERIFIED_PHYSICAL", "PROMOTED"})

@dataclass(frozen=True)
class EvidenceDecision:
    allowed: bool
    reason: str
    level: str | None = None


def classify_evidence(record: Mapping[str, Any]) -> str:
    """Return the evidence level without promoting it."""
    level = record.get("level")
    if level in NON_AUTHORITATIVE or level is None:
        return "UNKNOWN" if level is None else str(level)
    return str(level)


def gate_promotion(record: Mapping[str, Any], *, required_level: str = "VERIFIED_DIGITAL") -> EvidenceDecision:
    """Fail-closed promotion gate for claims such as EDGE_FOUND."""
    level = classify_evidence(record)
    if level in NON_AUTHORITATIVE:
        return EvidenceDecision(False, f"non-authoritative evidence level: {level}", level)
    if level != required_level and level != "PROMOTED":
        return EvidenceDecision(False, f"insufficient evidence level: {level}; required {required_level}", level)
    if not record.get("run_id") or not record.get("source_ref") or not record.get("claim"):
        return EvidenceDecision(False, "missing evidence provenance fields", level)
    return EvidenceDecision(True, "evidence satisfies promotion gate", level)


__all__ = ["NON_AUTHORITATIVE", "VERIFIED_LEVELS", "EvidenceDecision", "classify_evidence", "gate_promotion"]
