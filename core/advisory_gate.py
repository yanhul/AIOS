"""Governance boundary for non-authoritative advisory findings.

Holmes-Kit-inspired primitive: advisory analysis may propose findings, but it
cannot promote them into authoritative evidence or terminal outcomes.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

ADVISORY = "ADVISORY"
AUTHORITATIVE = "AUTHORITATIVE"
_FORBIDDEN_PROMOTIONS = frozenset({"EDGE_FOUND", "NO_EDGE_FOUND", "PASS", "PROMOTED"})


@dataclass(frozen=True)
class AdvisoryFinding:
    finding_id: str
    claim: str
    source_ref: str
    provider: str
    run_id: str
    status: str = ADVISORY

    def __post_init__(self) -> None:
        for name, value in (("finding_id", self.finding_id), ("claim", self.claim),
                            ("source_ref", self.source_ref), ("provider", self.provider),
                            ("run_id", self.run_id)):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty")
        if self.status != ADVISORY:
            raise ValueError("advisory finding must remain ADVISORY")


def require_authoritative_evidence(
    finding: AdvisoryFinding,
    evidence: Mapping[str, Any] | None,
) -> None:
    """Fail closed unless an independently recorded evidence object is supplied."""
    if evidence is None:
        raise PermissionError("advisory finding cannot authorize a transition without evidence")
    required = {"evidence_id", "level", "run_id", "provider", "claim", "digest"}
    if not required.issubset(evidence):
        raise PermissionError("authoritative evidence schema is incomplete")
    if evidence["run_id"] != finding.run_id or evidence["provider"] != finding.provider:
        raise PermissionError("evidence is not bound to advisory finding execution context")
    if evidence["claim"] != finding.claim:
        raise PermissionError("evidence claim does not bind to advisory claim")


def authorize_promotion(
    finding: AdvisoryFinding,
    evidence: Mapping[str, Any] | None,
    target_state: str,
) -> None:
    """Advisory output never directly grants promotion or terminal authority."""
    if target_state in _FORBIDDEN_PROMOTIONS:
        raise PermissionError("advisory output cannot directly authorize promotion/terminal state")
    require_authoritative_evidence(finding, evidence)


__all__ = ["ADVISORY", "AUTHORITATIVE", "AdvisoryFinding", "require_authoritative_evidence", "authorize_promotion"]
