"""Executable evaluation-plane boundary.

Evaluation consumes immutable execution evidence; it never creates authority.
Receipts are created at observation time and bind one effect to one attempt and
one evidence record. Evaluation must resolve that exact lineage before it can
be persisted.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Mapping

from .evidence import verify_evidence
from .mutation import TransitionError, canonical_json, commit_batch, recover_pending


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(dict(value)).encode("utf-8")).hexdigest()


def _receipt_path(aios_dir: str, receipt_id: str) -> str:
    return os.path.join(aios_dir, "receipts", receipt_id + ".json")


def _evaluation_path(aios_dir: str, evaluation_id: str) -> str:
    return os.path.join(aios_dir, "evaluations", evaluation_id + ".json")


@dataclass(frozen=True)
class EvaluationReceipt:
    receipt_id: str
    effect_id: str
    attempt_id: str
    provider: str
    evidence: Mapping[str, Any]

    def __post_init__(self) -> None:
        for name, value in (("receipt_id", self.receipt_id), ("effect_id", self.effect_id),
                            ("attempt_id", self.attempt_id), ("provider", self.provider)):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} is required")
        if not isinstance(self.evidence, Mapping) or not verify_evidence(self.evidence):
            raise ValueError("receipt requires valid AIOS evidence")
        if self.evidence.get("provider") != self.provider:
            raise ValueError("receipt evidence provider mismatch")

    def as_record(self) -> dict[str, Any]:
        body = {"record_type": "EXECUTION_RECEIPT", "receipt_id": self.receipt_id,
                "effect_id": self.effect_id, "attempt_id": self.attempt_id,
                "provider": self.provider, "evidence": dict(self.evidence)}
        body["digest"] = _digest(body)
        return body


def make_receipt(aios_dir: str, effect: Mapping[str, Any], observation: Mapping[str, Any]) -> dict[str, Any]:
    """Create the authoritative receipt for one observed execution attempt."""
    effect_id = effect.get("effect_id")
    attempt_id = effect.get("attempt_id")
    provider = effect.get("provider")
    evidence = observation.get("evidence")
    if not all(isinstance(v, str) and v.strip() for v in (effect_id, attempt_id, provider)):
        raise TransitionError("cannot receipt an effect without exact attempt/provider binding")
    if not isinstance(evidence, Mapping) or not verify_evidence(evidence):
        raise ValueError("receipt requires valid evidence")
    if evidence.get("provider") != provider:
        raise ValueError("receipt evidence provider mismatch")
    seed = {"effect_id": effect_id, "attempt_id": attempt_id,
            "provider": provider, "evidence_digest": evidence["digest"]}
    receipt_id = "RC-" + _digest(seed)
    rec = EvaluationReceipt(receipt_id, effect_id, attempt_id, provider, evidence).as_record()
    recover_pending(aios_dir)
    path = _receipt_path(aios_dir, receipt_id)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            existing = json.load(fh)
        if canonical_json(existing) == canonical_json(rec):
            return existing
        raise TransitionError("receipt identity collision")
    event = {"kind": "execution_receipt", "action": "create", "receipt_id": receipt_id,
             "effect_id": effect_id, "attempt_id": attempt_id, "provider": provider}
    commit_batch(aios_dir, [(os.path.join("receipts", receipt_id + ".json"), rec),
                            (os.path.join("events", "receipt-" + receipt_id + ".json"), event)])
    return rec


def _load(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _verify_receipt(rec: Mapping[str, Any]) -> None:
    required = ("record_type", "receipt_id", "effect_id", "attempt_id", "provider", "evidence", "digest")
    if any(key not in rec for key in required) or rec.get("record_type") != "EXECUTION_RECEIPT":
        raise TransitionError("invalid execution receipt schema")
    if rec["digest"] != _digest({k: rec[k] for k in rec if k != "digest"}):
        raise TransitionError("execution receipt digest mismatch")
    EvaluationReceipt(rec["receipt_id"], rec["effect_id"], rec["attempt_id"], rec["provider"], rec["evidence"])


def evaluate(aios_dir: str, effect_id: str, receipt_id: str, evaluator: str,
             evaluator_version: str, rubric_version: str, verdict: str,
             test_results: list[Mapping[str, Any]] | None = None,
             rubric_results: list[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Persist a derived evaluation only after exact execution lineage resolves."""
    for name, value in (("effect_id", effect_id), ("receipt_id", receipt_id),
                        ("evaluator", evaluator), ("evaluator_version", evaluator_version),
                        ("rubric_version", rubric_version), ("verdict", verdict)):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} is required")
    if verdict not in ("PASS", "FAIL", "INCONCLUSIVE"):
        raise ValueError("invalid evaluation verdict")
    recover_pending(aios_dir)
    effect_path = os.path.join(aios_dir, "effects", effect_id + ".json")
    receipt_path = _receipt_path(aios_dir, receipt_id)
    if not os.path.exists(effect_path) or not os.path.exists(receipt_path):
        raise TransitionError("evaluation requires resolvable effect and execution receipt")
    effect = _load(effect_path)
    receipt = _load(receipt_path)
    _verify_receipt(receipt)
    if receipt["effect_id"] != effect_id:
        raise TransitionError("receipt effect binding mismatch")
    if receipt["attempt_id"] != effect.get("attempt_id"):
        raise TransitionError("receipt attempt does not match current effect attempt")
    if receipt["provider"] != effect.get("provider"):
        raise TransitionError("receipt provider binding mismatch")
    evidence = receipt["evidence"]
    if not verify_evidence(evidence):
        raise TransitionError("evaluation evidence is invalid")
    evaluation_body = {
        "record_type": "EVALUATION", "effect_id": effect_id,
        "attempt_id": receipt["attempt_id"], "receipt_id": receipt_id,
        "evaluator": evaluator, "evaluator_version": evaluator_version,
        "rubric_version": rubric_version, "evidence_refs": [evidence["evidence_id"]],
        "test_results": list(test_results or []), "rubric_results": list(rubric_results or []),
        "verdict": verdict,
    }
    evaluation_id = "EVL-" + _digest(evaluation_body)
    rec = dict(evaluation_body, evaluation_id=evaluation_id)
    rec["digest"] = _digest(rec)
    path = _evaluation_path(aios_dir, evaluation_id)
    if os.path.exists(path):
        existing = _load(path)
        if canonical_json(existing) == canonical_json(rec):
            return existing
        raise TransitionError("evaluation identity collision")
    event = {"kind": "evaluation", "action": "create", "evaluation_id": evaluation_id,
             "effect_id": effect_id, "attempt_id": receipt["attempt_id"], "receipt_id": receipt_id,
             "evaluator": evaluator, "rubric_version": rubric_version, "verdict": verdict}
    commit_batch(aios_dir, [(os.path.join("evaluations", evaluation_id + ".json"), rec),
                            (os.path.join("events", "evaluation-" + evaluation_id + ".json"), event)])
    return rec


__all__ = ["EvaluationReceipt", "make_receipt", "evaluate"]
