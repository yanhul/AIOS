"""AIOS evidence-bound evaluation records.

Evaluation is a derived artifact downstream of an accepted observation. It never
changes effect authority and cannot manufacture receipt/evidence lineage.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import datetime
import json
import os
from typing import Any, Mapping

from .authority import authorize, load_contract, load_permit
from .contract import verify_permit
from .evidence import verify_evidence
from .mutation import TransitionError, canonical_json, commit_batch, event_identity, recover_pending
from .receipt import load_receipt, verify_receipt_binding


EVALUATION_DIR = "evaluations"
VERDICTS = ("PASS", "BLOCKED", "INCONCLUSIVE")


@dataclass(frozen=True)
class EvaluationRecord:
    evaluation_id: str
    effect_id: str
    attempt_id: str
    receipt_id: str
    evidence_id: str
    evidence_digest: str
    evaluator: str
    evaluator_version: str
    rubric_version: str
    verdict: str
    components: dict[str, Any]
    provenance: dict[str, Any]

    @property
    def identity(self) -> str:
        data = {
            "effect_id": self.effect_id,
            "attempt_id": self.attempt_id,
            "receipt_id": self.receipt_id,
            "evidence_id": self.evidence_id,
            "evidence_digest": self.evidence_digest,
            "evaluator": self.evaluator,
            "evaluator_version": self.evaluator_version,
            "rubric_version": self.rubric_version,
            "verdict": self.verdict,
            "components": self.components,
            "provenance": self.provenance,
        }
        return sha256(canonical_json(data).encode("utf-8")).hexdigest()

    def as_record(self) -> dict[str, Any]:
        return {
            "record_type": "EVALUATION",
            "evaluation_id": self.evaluation_id,
            "effect_id": self.effect_id,
            "attempt_id": self.attempt_id,
            "receipt_id": self.receipt_id,
            "evidence_id": self.evidence_id,
            "evidence_digest": self.evidence_digest,
            "evaluator": self.evaluator,
            "evaluator_version": self.evaluator_version,
            "rubric_version": self.rubric_version,
            "verdict": self.verdict,
            "components": dict(self.components),
            "provenance": dict(self.provenance),
            "identity": self.identity,
        }


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _load_effect(aios_dir: str, effect_id: str) -> dict[str, Any]:
    path = os.path.join(aios_dir, "effects", effect_id + ".json")
    if not os.path.exists(path):
        raise KeyError(f"unknown effect: {effect_id}")
    with open(path, "r", encoding="utf-8") as fh:
        effect = json.load(fh)
    if not isinstance(effect, dict) or effect.get("effect_id") != effect_id:
        raise TransitionError("persisted effect is invalid")
    authorize(aios_dir, effect["contract_id"], effect["permit_id"])
    contract = load_contract(aios_dir, effect["contract_id"])
    permit = load_permit(aios_dir, effect["permit_id"])
    verify_permit(contract, permit)
    return effect


def evaluate(aios_dir: str, effect_id: str, attempt_id: str, receipt_id: str,
             evidence: Mapping[str, Any], evaluator: str,
             evaluator_version: str, rubric_version: str, verdict: str,
             components: Mapping[str, Any] | None = None,
             provenance: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Create an immutable evaluation from one accepted execution lineage."""
    _text(effect_id, "effect_id")
    _text(attempt_id, "attempt_id")
    _text(receipt_id, "receipt_id")
    _text(evaluator, "evaluator")
    _text(evaluator_version, "evaluator_version")
    _text(rubric_version, "rubric_version")
    if verdict not in VERDICTS:
        raise ValueError("invalid evaluation verdict")
    if not isinstance(evidence, Mapping) or not verify_evidence(evidence):
        raise ValueError("evaluation requires a valid evidence record")
    if evidence.get("effect_id") != effect_id:
        raise TransitionError("evaluation evidence effect binding mismatch")
    if evidence.get("attempt_id") != attempt_id:
        raise TransitionError("evaluation evidence attempt binding mismatch")
    if evidence.get("receipt_id") != receipt_id:
        raise TransitionError("evaluation evidence receipt binding mismatch")

    recover_pending(aios_dir)
    effect = _load_effect(aios_dir, effect_id)
    if effect.get("state") not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise TransitionError("evaluation requires an accepted terminal observation")
    if effect.get("attempt_id") != attempt_id:
        raise TransitionError("evaluation attempt does not match current effect attempt")
    provider = effect.get("provider")
    receipt = verify_receipt_binding(aios_dir, receipt_id, effect, attempt_id, provider)
    if receipt["outcome"] != effect["state"]:
        raise TransitionError("evaluation receipt outcome does not match observed effect state")
    if evidence.get("provider") != provider:
        raise TransitionError("evaluation evidence provider binding mismatch")
    if evidence.get("artifact_ref") != receipt["provider_operation_id"]:
        raise TransitionError("evaluation evidence artifact does not match receipt")

    rec = EvaluationRecord(
        evaluation_id="EVL-" + sha256(canonical_json({
            "effect_id": effect_id, "attempt_id": attempt_id, "receipt_id": receipt_id,
            "evidence_id": evidence["evidence_id"], "evidence_digest": evidence["digest"],
            "evaluator": evaluator, "evaluator_version": evaluator_version,
            "rubric_version": rubric_version, "verdict": verdict,
            "components": dict(components or {}), "provenance": dict(provenance or {}),
        }).encode("utf-8")).hexdigest(),
        effect_id=effect_id, attempt_id=attempt_id, receipt_id=receipt_id,
        evidence_id=evidence["evidence_id"], evidence_digest=evidence["digest"],
        evaluator=evaluator, evaluator_version=evaluator_version,
        rubric_version=rubric_version, verdict=verdict,
        components=dict(components or {}), provenance=dict(provenance or {}),
    ).as_record()
    path = os.path.join(aios_dir, EVALUATION_DIR, rec["evaluation_id"] + ".json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            existing = json.load(fh)
        if canonical_json(existing) == canonical_json(rec):
            return existing
        raise TransitionError("evaluation identity collision with different content")

    event = {
        "kind": "mutation",
        "action": "evaluation.recorded",
        "actor": evaluator,
        "evaluation_id": rec["evaluation_id"],
        "effect_id": effect_id,
        "attempt_id": attempt_id,
        "receipt_id": receipt_id,
        "evidence_id": evidence["evidence_id"],
        "evidence_digest": evidence["digest"],
        "verdict": verdict,
    }
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    event_id = event_identity(event)
    event["event_id"] = event_id
    event["timestamp_utc"] = timestamp
    commit_batch(aios_dir, [
        (os.path.join(EVALUATION_DIR, rec["evaluation_id"] + ".json"), rec),
        (os.path.join("events", "EVT-" + timestamp.replace(":", "") + "-" + event_id + ".json"), event),
    ])
    return rec


def load_evaluation(aios_dir: str, evaluation_id: str) -> dict[str, Any]:
    _text(evaluation_id, "evaluation_id")
    path = os.path.join(aios_dir, EVALUATION_DIR, evaluation_id + ".json")
    if not os.path.exists(path):
        raise KeyError(f"unknown evaluation: {evaluation_id}")
    with open(path, "r", encoding="utf-8") as fh:
        rec = json.load(fh)
    if rec.get("record_type") != "EVALUATION":
        raise TransitionError("persisted evaluation is invalid")
    return rec


__all__ = ["EVALUATION_DIR", "VERDICTS", "EvaluationRecord", "evaluate", "load_evaluation"]
