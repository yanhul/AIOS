"""Model-neutral decision-provider boundary for AIOS.

Absorbed from compact non-generative decision-model patterns: runtime-defined
candidate sets, typed decision modes, distributions/scores, calibration
metadata, and explicit abstention. A provider is advisory only.

This module deliberately has no execute/commit/memory-write surface. A
DecisionResult is not evidence, verification, permission, or authority.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Protocol, Sequence


DECIDED = "DECIDED"
ABSTAINED = "ABSTAINED"
INCONCLUSIVE = "INCONCLUSIVE"
_DECISION_STATUSES = frozenset({DECIDED, ABSTAINED, INCONCLUSIVE})
_DECISION_TYPES = frozenset({"choice", "score", "boolean"})


def _nonempty(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _refs(value: Sequence[str], name: str) -> tuple[str, ...]:
    result = tuple(value)
    if not result or any(not isinstance(v, str) or not v.strip() for v in result):
        raise ValueError(f"{name} must contain non-empty strings")
    return result


def _mapping(value: Mapping[str, float] | None, name: str) -> Mapping[str, float]:
    if value is None:
        return MappingProxyType({})
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a mapping")
    result = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError(f"{name} keys must be non-empty strings")
        if not isinstance(item, (int, float)) or isinstance(item, bool):
            raise ValueError(f"{name} values must be numeric")
        result[key] = float(item)
    return MappingProxyType(result)


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DecisionRequest:
    """Immutable, lineage-bearing input to a decision provider."""

    decision_id: str
    state_ref: str
    question: str
    decision_type: str
    candidates: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    policy_ref: str
    provider_ref: str

    def __post_init__(self) -> None:
        for value, name in (
            (self.decision_id, "decision_id"),
            (self.state_ref, "state_ref"),
            (self.question, "question"),
            (self.policy_ref, "policy_ref"),
            (self.provider_ref, "provider_ref"),
        ):
            _nonempty(value, name)
        if self.decision_type not in _DECISION_TYPES:
            raise ValueError("unsupported decision_type")
        candidates = tuple(self.candidates)
        if not 2 <= len(candidates) <= 20:
            raise ValueError("candidates must contain 2..20 options")
        if any(not isinstance(v, str) or not v.strip() for v in candidates):
            raise ValueError("candidates must contain non-empty strings")
        if len(set(candidates)) != len(candidates):
            raise ValueError("candidates must be unique")
        object.__setattr__(self, "candidates", candidates)
        object.__setattr__(self, "evidence_refs", _refs(self.evidence_refs, "evidence_refs"))

    @property
    def input_hash(self) -> str:
        return _digest(
            {
                "decision_id": self.decision_id,
                "state_ref": self.state_ref,
                "question": self.question,
                "decision_type": self.decision_type,
                "candidates": self.candidates,
                "evidence_refs": self.evidence_refs,
                "policy_ref": self.policy_ref,
                "provider_ref": self.provider_ref,
            }
        )


@dataclass(frozen=True)
class DecisionResult:
    """Provider output. It carries no authority and cannot be an evidence record."""

    decision_id: str
    provider_ref: str
    provider_revision: str
    status: str
    selected: str | None
    distribution: Mapping[str, float]
    raw_scores: Mapping[str, float]
    calibrated_scores: Mapping[str, float]
    calibration_ref: str | None
    input_hash: str
    output_hash: str

    def __post_init__(self) -> None:
        for value, name in (
            (self.decision_id, "decision_id"),
            (self.provider_ref, "provider_ref"),
            (self.provider_revision, "provider_revision"),
            (self.input_hash, "input_hash"),
            (self.output_hash, "output_hash"),
        ):
            _nonempty(value, name)
        if self.status not in _DECISION_STATUSES:
            raise ValueError("invalid decision status")
        if self.selected is not None and (not isinstance(self.selected, str) or not self.selected.strip()):
            raise ValueError("selected must be a non-empty string or None")
        if self.calibration_ref is not None:
            _nonempty(self.calibration_ref, "calibration_ref")
        object.__setattr__(self, "distribution", _mapping(self.distribution, "distribution"))
        object.__setattr__(self, "raw_scores", _mapping(self.raw_scores, "raw_scores"))
        object.__setattr__(self, "calibrated_scores", _mapping(self.calibrated_scores, "calibrated_scores"))

    @property
    def advisory(self) -> bool:
        return True


class DecisionProvider(Protocol):
    """Provider contract: decision only; no execution or authority methods."""

    provider_ref: str
    provider_revision: str

    def decide(self, request: DecisionRequest) -> DecisionResult:
        """Return an advisory decision result for the supplied request."""


def validate_result(request: DecisionRequest, result: DecisionResult) -> None:
    """Fail closed on provider/request lineage or candidate mismatches."""
    if result.decision_id != request.decision_id:
        raise ValueError("decision result is bound to a different decision_id")
    if result.provider_ref != request.provider_ref:
        raise ValueError("decision result provider_ref does not match request")
    if result.input_hash != request.input_hash:
        raise ValueError("decision result input_hash does not match request")
    for name, values in (
        ("distribution", result.distribution),
        ("raw_scores", result.raw_scores),
        ("calibrated_scores", result.calibrated_scores),
    ):
        unknown = set(values) - set(request.candidates)
        if unknown:
            raise ValueError(f"{name} contains unknown candidates: {sorted(unknown)}")
    if result.selected is not None and result.selected not in request.candidates:
        raise ValueError("selected candidate is outside the request candidate set")
    if result.status == DECIDED and result.selected is None:
        raise ValueError("DECIDED result requires selected")
    if result.status != DECIDED and result.selected is not None:
        raise ValueError("ABSTAINED/INCONCLUSIVE result cannot select a candidate")


def result_hash_payload(result: DecisionResult) -> dict:
    return {
        "decision_id": result.decision_id,
        "provider_ref": result.provider_ref,
        "provider_revision": result.provider_revision,
        "status": result.status,
        "selected": result.selected,
        "distribution": dict(result.distribution),
        "raw_scores": dict(result.raw_scores),
        "calibrated_scores": dict(result.calibrated_scores),
        "calibration_ref": result.calibration_ref,
        "input_hash": result.input_hash,
    }


__all__ = [
    "ABSTAINED",
    "DECIDED",
    "INCONCLUSIVE",
    "DecisionProvider",
    "DecisionRequest",
    "DecisionResult",
    "result_hash_payload",
    "validate_result",
]
