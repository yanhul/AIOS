"""Evidence-bound evaluation records for the governed execution plane.

Evaluation is derived from immutable execution evidence. It never grants
authority and cannot repair missing or mismatched execution lineage.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping


def _nonempty(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _frozen_mapping(value: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError(f"{name} must be a non-empty mapping")
    return MappingProxyType(dict(value))


@dataclass(frozen=True)
class ExecutionReceipt:
    effect_id: str
    attempt_id: str
    status: str
    evidence: Mapping[str, Any]

    def __post_init__(self) -> None:
        _nonempty(self.effect_id, "effect_id")
        _nonempty(self.attempt_id, "attempt_id")
        if self.status not in {"OBSERVED", "UNKNOWN"}:
            raise ValueError("receipt status must be OBSERVED or UNKNOWN")
        object.__setattr__(self, "evidence", _frozen_mapping(self.evidence, "evidence"))


@dataclass(frozen=True)
class EvaluationRecord:
    evaluation_id: str
    effect_id: str
    attempt_id: str
    receipt_id: str
    evaluator_version: str
    rubric_version: str
    evidence_refs: tuple[str, ...]
    verdict: str
    timestamp: str
    result: Mapping[str, Any]

    def __post_init__(self) -> None:
        for value, name in (
            (self.evaluation_id, "evaluation_id"),
            (self.effect_id, "effect_id"),
            (self.attempt_id, "attempt_id"),
            (self.receipt_id, "receipt_id"),
            (self.evaluator_version, "evaluator_version"),
            (self.rubric_version, "rubric_version"),
            (self.verdict, "verdict"),
            (self.timestamp, "timestamp"),
        ):
            _nonempty(value, name)
        if not self.evidence_refs or not all(isinstance(v, str) and v.strip() for v in self.evidence_refs):
            raise ValueError("evidence_refs must contain non-empty strings")
        object.__setattr__(self, "result", _frozen_mapping(self.result, "result"))


def evaluate_receipt(
    receipt: ExecutionReceipt,
    *,
    evaluation_id: str,
    receipt_id: str,
    evaluator_version: str,
    rubric_version: str,
    verdict: str,
    result: Mapping[str, Any],
    evidence_refs: tuple[str, ...],
    timestamp: str | None = None,
) -> EvaluationRecord:
    """Create an evaluation only when receipt lineage and evidence are valid."""
    if not isinstance(receipt, ExecutionReceipt):
        raise ValueError("evaluation requires an ExecutionReceipt")
    if receipt.status != "OBSERVED":
        raise ValueError("UNKNOWN receipt cannot produce a governed evaluation")
    refs = tuple(evidence_refs)
    if not refs or any(ref not in receipt.evidence for ref in refs):
        raise ValueError("evaluation evidence_refs do not resolve to receipt evidence")
    return EvaluationRecord(
        evaluation_id=evaluation_id,
        effect_id=receipt.effect_id,
        attempt_id=receipt.attempt_id,
        receipt_id=receipt_id,
        evaluator_version=evaluator_version,
        rubric_version=rubric_version,
        evidence_refs=refs,
        verdict=verdict,
        timestamp=timestamp or datetime.now(timezone.utc).isoformat(),
        result=result,
    )


__all__ = ["ExecutionReceipt", "EvaluationRecord", "evaluate_receipt"]
