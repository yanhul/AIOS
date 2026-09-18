"""Non-authoritative cognitive proposal boundary.

Cognitive modules may emit observations, desires, plans, risk findings, critics,
and other proposals. None of these artifacts is an authority grant. Governance
must remain in the AIOS control plane.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Mapping

PROPOSAL = "PROPOSAL"
_AUTHORITY_FIELDS = frozenset({
    "authority", "authority_granted", "permit", "permit_id", "issuer",
    "policy_override", "promotion", "promotion_authorized", "terminal_authorized",
})

@dataclass(frozen=True)
class CognitiveProposal:
    """A model/module output that is explicitly non-authoritative."""
    content: Mapping[str, Any]
    source: str
    kind: str = "proposal"
    status: str = PROPOSAL
    def __post_init__(self) -> None:
        if not isinstance(self.content, Mapping):
            raise TypeError("proposal content must be a mapping")
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("proposal source must be a non-empty string")
        if not isinstance(self.kind, str) or not self.kind.strip():
            raise ValueError("proposal kind must be a non-empty string")
        if self.status != PROPOSAL:
            raise ValueError("cognitive proposal status must remain PROPOSAL")
        reject_authority_fields(self.content)

def reject_authority_fields(value: Mapping[str, Any]) -> None:
    """Fail closed if cognitive output attempts to carry governance authority."""
    if not isinstance(value, Mapping):
        raise TypeError("cognitive output must be a mapping")
    present = sorted(_AUTHORITY_FIELDS.intersection(value.keys()))
    if present:
        raise PermissionError(
            "cognitive output cannot carry authority fields: " + ", ".join(present)
        )

def validate_cognitive_output(value: Any) -> Any:
    """Validate a cognitive output while preserving legacy mapping APIs."""
    if isinstance(value, CognitiveProposal):
        return value
    if isinstance(value, Mapping):
        reject_authority_fields(value)
        return value
    raise TypeError("cognitive output must be a mapping or CognitiveProposal")

__all__ = ["PROPOSAL", "CognitiveProposal", "reject_authority_fields", "validate_cognitive_output"]
