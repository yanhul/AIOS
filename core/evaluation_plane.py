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
    receipt_id: str | None = None

    def __post_init__(self) -> None:
        _nonempty(self.effect_id, "effect_id")
        if self.receipt_id is not None:
            _nonempty(self.receipt_id, "receipt_id")
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
    if receipt.receipt_id is not None and receipt.receipt_id != receipt_id:
        raise ValueError("evaluation receipt_id does not match the receipt being evaluated")
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


def evaluate_persisted_receipt(
    aios_dir: str,
    receipt_id: str,
    *,
    evaluator_version: str,
    rubric_version: str,
    verdict: str,
    result: Mapping[str, Any],
    timestamp: str | None = None,
) -> EvaluationRecord:
    """Evaluate an AIOS-persisted provider receipt and persist the evaluation.

    The receipt must exist, hash to its own receipt_id, and still be the
    receipt of record for its effect. The evaluation is bound to the exact
    (effect_id, attempt_id, receipt_id) triple and is written atomically.
    """
    import hashlib
    import os
    from .effect_authority import load_receipt
    from .mutation import canonical_json, commit_batch

    stored = load_receipt(aios_dir, receipt_id)
    evidence = stored["evidence"]
    receipt = ExecutionReceipt(effect_id=stored["effect_id"], attempt_id=stored["attempt_id"],
                               status="OBSERVED", evidence={evidence["evidence_id"]: evidence},
                               receipt_id=receipt_id)
    identity = {"receipt_id": receipt_id, "evaluator_version": evaluator_version,
                "rubric_version": rubric_version}
    evaluation_id = "EVAL-" + hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    path = os.path.join(aios_dir, "evaluations", evaluation_id + ".json")
    if os.path.exists(path):
        raise ValueError("evaluation already recorded for this receipt/evaluator/rubric")
    record = evaluate_receipt(receipt, evaluation_id=evaluation_id, receipt_id=receipt_id,
                              evaluator_version=evaluator_version, rubric_version=rubric_version,
                              verdict=verdict, result=result,
                              evidence_refs=(evidence["evidence_id"],), timestamp=timestamp)
    payload = {"record_type": "EVALUATION", "evaluation_id": record.evaluation_id,
               "effect_id": record.effect_id, "attempt_id": record.attempt_id,
               "receipt_id": record.receipt_id, "evaluator_version": record.evaluator_version,
               "rubric_version": record.rubric_version, "evidence_refs": list(record.evidence_refs),
               "verdict": record.verdict, "timestamp": record.timestamp, "result": dict(record.result)}
    commit_batch(aios_dir, [(os.path.join("evaluations", evaluation_id + ".json"), payload)])
    return record


__all__ = ["ExecutionReceipt", "EvaluationRecord", "evaluate_receipt", "evaluate_persisted_receipt"]
