"""Provider-neutral research-worker contract and reconciliation boundary."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

@dataclass(frozen=True)
class ResearchRequest:
    task_id: str
    objective: str
    constraints: tuple[str, ...] = ()
    evidence_requirements: tuple[str, ...] = ()
    max_steps: int = 1

@dataclass(frozen=True)
class ResearchFinding:
    finding_id: str
    source_ref: str
    claim: str
    evidence_ref: str
    confidence: str = "UNKNOWN"

class ResearchWorker(Protocol):
    capability_id: str
    def research(self, request: ResearchRequest) -> tuple[ResearchFinding, ...]: ...


def validate_findings(request: ResearchRequest, findings: tuple[ResearchFinding, ...]) -> None:
    """Validate shape only; this never promotes findings or changes policy."""
    if not request.task_id.strip() or not request.objective.strip():
        raise ValueError("research task identity/objective required")
    if request.max_steps < 1:
        raise ValueError("max_steps must be >= 1")
    for finding in findings:
        if not all(isinstance(v, str) and v.strip() for v in (finding.finding_id, finding.source_ref, finding.claim, finding.evidence_ref)):
            raise ValueError("research finding requires source and evidence references")


def reconcile_research(request: ResearchRequest, findings: tuple[ResearchFinding, ...]) -> Mapping[str, Any]:
    validate_findings(request, findings)
    return {"task_id": request.task_id, "finding_count": len(findings),
            "finding_ids": [f.finding_id for f in findings], "requires_aios_verification": True,
            "promotion_authority": "AIOS_CONTROL_PLANE"}

__all__ = ["ResearchRequest", "ResearchFinding", "ResearchWorker", "validate_findings", "reconcile_research"]
