"""AIOS epistemic and discovery primitives adapted from external agent research.

These helpers turn model-level discipline into machine-checkable boundaries.
They do not grant authority, mutate world state, or promote claims by themselves.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable

from .capabilities import Capability


class ClaimStatus(str, Enum):
    FACT = "FACT"
    ASSUMPTION = "ASSUMPTION"
    DECISION = "DECISION"
    VERIFIED = "VERIFIED"
    UNKNOWN = "UNKNOWN"


class Volatility(str, Enum):
    STABLE = "STABLE"
    CURRENT = "CURRENT"
    RECENT = "RECENT"
    UNKNOWN = "UNKNOWN"


_DISCOVERY_REQUIRED = frozenset({Volatility.CURRENT, Volatility.RECENT, Volatility.UNKNOWN})


def requires_discovery(volatility: Volatility | str) -> bool:
    try:
        value = Volatility(volatility)
    except ValueError as exc:
        raise ValueError(f"invalid volatility: {volatility!r}") from exc
    return value in _DISCOVERY_REQUIRED


def classify_claim(*, source_kind: str, verified: bool = False) -> ClaimStatus:
    kind = source_kind.strip().lower() if isinstance(source_kind, str) else ""
    if verified:
        return ClaimStatus.VERIFIED
    if kind in {"measurement", "direct_source", "authoritative_record"}:
        return ClaimStatus.FACT
    if kind in {"decision", "approved_decision"}:
        return ClaimStatus.DECISION
    if kind in {"assumption", "placeholder", "model_guess"}:
        return ClaimStatus.ASSUMPTION
    return ClaimStatus.UNKNOWN


@dataclass(frozen=True)
class ToolResult:
    """Raw provider/tool output. A successful result is not world-state proof."""
    provider: str
    invocation_id: str
    payload: Any
    success: bool = True

    def __post_init__(self) -> None:
        if not self.provider.strip() or not self.invocation_id.strip():
            raise ValueError("provider and invocation_id are required")


@dataclass(frozen=True)
class Observation:
    """Independent observation of world state derived from a tool effect."""
    observation_id: str
    source_ref: str
    claim: str
    tool_invocation_id: str
    verified: bool = False

    def __post_init__(self) -> None:
        if not all(
            isinstance(v, str) and v.strip()
            for v in (self.observation_id, self.source_ref, self.claim, self.tool_invocation_id)
        ):
            raise ValueError("observation identity/provenance fields are required")


def observe_tool_result(result: ToolResult, *, observation_id: str, source_ref: str, claim: str) -> Observation:
    """Create an observation record; never silently mark it verified."""
    if not result.success:
        raise ValueError("failed tool result cannot become an observation")
    return Observation(
        observation_id=observation_id,
        source_ref=source_ref,
        claim=claim,
        tool_invocation_id=result.invocation_id,
        verified=False,
    )


def promote_observation(observation: Observation, *, verification_evidence: Iterable[str]) -> Observation:
    """Promote only when explicit independent verification evidence exists."""
    evidence = tuple(x for x in verification_evidence if isinstance(x, str) and x.strip())
    if not evidence:
        raise PermissionError("observation cannot be promoted without verification evidence")
    return Observation(
        observation_id=observation.observation_id,
        source_ref=observation.source_ref,
        claim=observation.claim,
        tool_invocation_id=observation.tool_invocation_id,
        verified=True,
    )


def route_capabilities(
    capabilities: Iterable[Capability],
    *,
    required_inputs: Iterable[str] = (),
    required_outputs: Iterable[str] = (),
    environment: str | None = None,
    permission: str | None = None,
) -> list[Capability]:
    """Select descriptive capability candidates; routing is not authorization."""
    req_in = set(required_inputs)
    req_out = set(required_outputs)
    candidates: list[Capability] = []
    for capability in capabilities:
        if capability.status == "DEPRECATED":
            continue
        if req_in - set(capability.inputs) or req_out - set(capability.outputs):
            continue
        if environment and environment not in capability.environments:
            continue
        if permission and permission not in capability.permissions:
            continue
        candidates.append(capability)
    return sorted(candidates, key=lambda item: item.key)


__all__ = [
    "ClaimStatus", "Volatility", "ToolResult", "Observation",
    "requires_discovery", "classify_claim", "observe_tool_result",
    "promote_observation", "route_capabilities",
]
