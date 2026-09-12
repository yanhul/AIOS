"""AIOS-owned append-only evidence/provenance records."""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Mapping

LEVELS = ("OBSERVED", "EVIDENCED", "VERIFIED_DIGITAL", "VERIFIED_PHYSICAL", "PROMOTED")

@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    level: str
    source_ref: str
    claim: str
    run_id: str
    provider: str
    artifact_ref: str | None = None
    parent_evidence_id: str | None = None

    def __post_init__(self) -> None:
        if self.level not in LEVELS:
            raise ValueError("invalid evidence level")
        if not all(isinstance(v, str) and v.strip() for v in (self.evidence_id, self.source_ref, self.claim, self.run_id, self.provider)):
            raise ValueError("evidence identity/source/claim/run/provider are required")

    @property
    def digest(self) -> str:
        data = {"evidence_id": self.evidence_id, "level": self.level, "source_ref": self.source_ref,
                "claim": self.claim, "run_id": self.run_id, "provider": self.provider,
                "artifact_ref": self.artifact_ref, "parent_evidence_id": self.parent_evidence_id}
        return sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def as_record(self) -> dict[str, Any]:
        return {"evidence_id": self.evidence_id, "level": self.level, "source_ref": self.source_ref,
                "claim": self.claim, "run_id": self.run_id, "provider": self.provider,
                "artifact_ref": self.artifact_ref, "parent_evidence_id": self.parent_evidence_id,
                "digest": self.digest}


def verify_evidence(record: Mapping[str, Any]) -> bool:
    try:
        obj = EvidenceRecord(str(record["evidence_id"]), str(record["level"]), str(record["source_ref"]),
                             str(record["claim"]), str(record["run_id"]), str(record["provider"]),
                             record.get("artifact_ref"), record.get("parent_evidence_id"))
    except (KeyError, TypeError, ValueError):
        return False
    return obj.digest == record.get("digest")

__all__ = ["LEVELS", "EvidenceRecord", "verify_evidence"]
