"""AIOS epistemic and discovery primitives adapted from external agent research.

These helpers turn model-level discipline into machine-checkable boundaries.
They do not grant authority, mutate world state, or promote claims by themselves.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable

from .capabilities import Capability
from .verification import apply_verification


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


def assert_authoritative_claim(
    *,
    claim_id: str,
    status: ClaimStatus,
    volatility: Volatility | str,
    verification_evidence: Iterable[tuple[str, str]],
    aios_dir: str,
    verifier: str,
) -> None:
    """Enforce the epistemic authority boundary with persisted evidence."""
    if not isinstance(claim_id, str) or not claim_id.strip():
        raise ValueError("claim_id must be a non-empty string")
    if status not in {ClaimStatus.FACT, ClaimStatus.VERIFIED}:
        raise PermissionError(f"claim status {status.value} is not authoritative")
    refs = [list(ref) for ref in verification_evidence]
    if not refs:
        raise PermissionError("authoritative claim requires persisted verification evidence")
    reason = (
        f"discovery required for volatility={Volatility(volatility).value}"
        if requires_discovery(volatility)
        else "authoritative claim provenance"
    )
    result = apply_verification(
        aios_dir, "CLAIM", claim_id, refs, verifier, reason=reason,
    )
    if result["outcome"] != "VERIFIED":
        raise PermissionError("claim cannot cross authority boundary: evidence is unsupported")


def classify_claim(*, source_kind: str) -> ClaimStatus:
    """Classify an unverified claim; VERIFIED is only a promotion outcome.

    Deliberately has no ``verified``/confidence override. A caller cannot
    manufacture VERIFIED state by passing a boolean; verification belongs to
    the persisted verification/receipt path and ``promote_observation``.
    """
    kind = source_kind.strip().lower() if isinstance(source_kind, str) else ""
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


def promote_observation(
    observation: Observation,
    *,
    aios_dir: str,
    verification_evidence: Iterable[tuple[str, str]],
    verifier: str,
) -> Observation:
    """Promote only from persisted AIOS verification evidence.

    Raw strings, provider success, and caller-supplied booleans are not
    evidence. The native verification kernel resolves every EVIDENCE ref
    against persisted state and records an append-only verification attempt.
    """
    refs = [list(ref) for ref in verification_evidence]
    if not refs:
        raise PermissionError("observation cannot be promoted without persisted verification evidence")
    result = apply_verification(
        aios_dir, "OBSERVATION", observation.observation_id, refs, verifier,
        reason=observation.claim,
    )
    if result["outcome"] != "VERIFIED":
        raise PermissionError("observation cannot be promoted: verification evidence is unsupported")
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
    "promote_observation", "assert_authoritative_claim", "route_capabilities",
]
