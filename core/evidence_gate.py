"""AIOS evidence classification and authenticated promotion gate."""
from __future__ import annotations
from dataclasses import dataclass
import os
from typing import Any, Mapping
from .evidence import verify_evidence_attestation

NON_AUTHORITATIVE = frozenset({"ADVISORY", "UNKNOWN", "ERROR", "NOT_RUN"})
VERIFIED_LEVELS = frozenset({"VERIFIED_DIGITAL", "VERIFIED_PHYSICAL", "PROMOTED"})
EVIDENCE_ATTESTATION_SECRET_ENV = "AIOS_EVIDENCE_SIGNING_SECRET"

@dataclass(frozen=True)
class EvidenceDecision:
    allowed: bool
    reason: str
    level: str | None = None

def classify_evidence(record: Mapping[str, Any]) -> str:
    level = record.get("level")
    if level in NON_AUTHORITATIVE or level is None:
        return "UNKNOWN" if level is None else str(level)
    return str(level)

def gate_promotion(record: Mapping[str, Any], *, required_level: str = "VERIFIED_DIGITAL",
                   attestation_secret: str | None = None) -> EvidenceDecision:
    level = classify_evidence(record)
    if level in NON_AUTHORITATIVE:
        return EvidenceDecision(False, f"non-authoritative evidence level: {level}", level)
    if level != required_level and level != "PROMOTED":
        return EvidenceDecision(False, f"insufficient evidence level: {level}; required {required_level}", level)
    if not record.get("run_id") or not record.get("source_ref") or not record.get("claim"):
        return EvidenceDecision(False, "missing evidence provenance fields", level)
    secret = attestation_secret if attestation_secret is not None else os.environ.get(EVIDENCE_ATTESTATION_SECRET_ENV)
    if not secret or not verify_evidence_attestation(record, secret):
        return EvidenceDecision(False, "missing or invalid trusted evidence attestation", level)
    return EvidenceDecision(True, "authenticated evidence satisfies promotion gate", level)

__all__ = ["NON_AUTHORITATIVE", "VERIFIED_LEVELS", "EvidenceDecision",
           "EVIDENCE_ATTESTATION_SECRET_ENV", "classify_evidence", "gate_promotion"]
