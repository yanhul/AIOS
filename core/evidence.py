"""AIOS-owned append-only evidence/provenance records with trusted attestations."""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
import hashlib, hmac, json
from typing import Any, Mapping

LEVELS = ("OBSERVED", "EVIDENCED", "VERIFIED_DIGITAL", "VERIFIED_PHYSICAL", "PROMOTED")
ATTESTATION_TYPE = "AIOS_EVIDENCE_ATTESTATION"

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

def attest_evidence(record: Mapping[str, Any], secret: str) -> dict[str, str]:
    if not isinstance(secret, str) or len(secret) < 16:
        raise ValueError("evidence signing secret must contain at least 16 characters")
    if not verify_evidence(record):
        raise ValueError("cannot attest invalid evidence record")
    message = (ATTESTATION_TYPE + "\\n" + str(record["digest"]) + "\\n" +
               str(record["provider"]) + "\\n" + str(record["run_id"])).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return {"type": ATTESTATION_TYPE, "algorithm": "HMAC-SHA256", "signature": signature}

def verify_evidence_attestation(record: Mapping[str, Any], secret: str) -> bool:
    if not isinstance(secret, str) or len(secret) < 16 or not verify_evidence(record):
        return False
    auth = record.get("attestation")
    if not isinstance(auth, Mapping) or set(auth) != {"type", "algorithm", "signature"}:
        return False
    if auth.get("type") != ATTESTATION_TYPE or auth.get("algorithm") != "HMAC-SHA256":
        return False
    message = (ATTESTATION_TYPE + "\\n" + str(record["digest"]) + "\\n" +
               str(record["provider"]) + "\\n" + str(record["run_id"])).encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return isinstance(auth.get("signature"), str) and hmac.compare_digest(auth["signature"], expected)

__all__ = ["LEVELS", "EvidenceRecord", "verify_evidence", "attest_evidence",
           "verify_evidence_attestation", "ATTESTATION_TYPE"]
