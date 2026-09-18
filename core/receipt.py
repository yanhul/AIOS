"""Durable provider receipts bound to one AIOS effect attempt.

A receipt is the durable anchor between an execution attempt and evidence.
It is immutable: the same receipt identity may only be persisted with identical
content.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from typing import Any, Mapping

from .mutation import TransitionError, canonical_json, commit_batch, recover_pending


@dataclass(frozen=True)
class ReceiptRecord:
    receipt_id: str
    effect_id: str
    attempt_id: str
    provider: str
    provider_operation_id: str
    outcome: str
    observation: dict[str, Any]

    @property
    def digest(self) -> str:
        data = {
            "receipt_id": self.receipt_id,
            "effect_id": self.effect_id,
            "attempt_id": self.attempt_id,
            "provider": self.provider,
            "provider_operation_id": self.provider_operation_id,
            "outcome": self.outcome,
            "observation": self.observation,
        }
        return sha256(canonical_json(data).encode("utf-8")).hexdigest()

    def as_record(self) -> dict[str, Any]:
        data = {
            "record_type": "PROVIDER_RECEIPT",
            "receipt_id": self.receipt_id,
            "effect_id": self.effect_id,
            "attempt_id": self.attempt_id,
            "provider": self.provider,
            "provider_operation_id": self.provider_operation_id,
            "outcome": self.outcome,
            "observation": dict(self.observation),
        }
        data["digest"] = self.digest
        return data


def _receipt_id(effect_id: str, attempt_id: str, provider: str, provider_operation_id: str) -> str:
    value = {
        "effect_id": effect_id,
        "attempt_id": attempt_id,
        "provider": provider,
        "provider_operation_id": provider_operation_id,
    }
    return "RC-" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _validate(record: Mapping[str, Any]) -> bool:
    try:
        values = (
            record["receipt_id"], record["effect_id"], record["attempt_id"],
            record["provider"], record["provider_operation_id"], record["outcome"],
        )
        if not all(isinstance(v, str) and v.strip() for v in values):
            return False
        if record["outcome"] not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
            return False
        if not isinstance(record["observation"], dict) or not record["observation"]:
            return False
        expected_id = _receipt_id(record["effect_id"], record["attempt_id"],
                                  record["provider"], record["provider_operation_id"])
        if record["receipt_id"] != expected_id:
            return False
        obj = ReceiptRecord(
            record["receipt_id"], record["effect_id"], record["attempt_id"],
            record["provider"], record["provider_operation_id"],
            record["outcome"], record["observation"],
        )
        return obj.digest == record.get("digest")
    except (KeyError, TypeError, ValueError):
        return False


def persist_receipt(aios_dir: str, effect: Mapping[str, Any], attempt_id: str,
                    provider: str, provider_operation_id: str, outcome: str,
                    observation: dict[str, Any]) -> dict[str, Any]:
    """Persist exactly one validated receipt for the current effect attempt."""
    effect_id = effect.get("effect_id")
    if not all(isinstance(v, str) and v.strip() for v in
               (effect_id, attempt_id, provider, provider_operation_id)):
        raise ValueError("receipt identity fields are required")
    if attempt_id != effect.get("attempt_id"):
        raise TransitionError("receipt attempt does not match effect attempt")
    if provider != effect.get("provider"):
        raise TransitionError("receipt provider does not match effect provider")
    if outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ValueError("receipt outcome must be an observed terminal outcome")
    if not isinstance(observation, dict) or not observation:
        raise ValueError("receipt observation must be a non-empty dict")

    rec = ReceiptRecord(
        _receipt_id(effect_id, attempt_id, provider, provider_operation_id),
        effect_id, attempt_id, provider, provider_operation_id, outcome, observation,
    ).as_record()
    recover_pending(aios_dir)
    path = os.path.join(aios_dir, "receipts", rec["receipt_id"] + ".json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            existing = json.load(fh)
        if canonical_json(existing) != canonical_json(rec):
            raise TransitionError("receipt identity collision with different content")
        if not _validate(existing):
            raise TransitionError("persisted receipt is invalid")
        return existing
    commit_batch(aios_dir, [(os.path.join("receipts", rec["receipt_id"] + ".json"), rec)])
    return rec


def load_receipt(aios_dir: str, receipt_id: str) -> dict[str, Any]:
    if not isinstance(receipt_id, str) or not receipt_id.strip():
        raise ValueError("receipt_id must be a non-empty string")
    path = os.path.join(aios_dir, "receipts", receipt_id + ".json")
    if not os.path.exists(path):
        raise KeyError(f"unknown receipt: {receipt_id}")
    with open(path, "r", encoding="utf-8") as fh:
        rec = json.load(fh)
    if rec.get("record_type") != "PROVIDER_RECEIPT" or not _validate(rec):
        raise TransitionError("persisted receipt is invalid")
    return rec


def verify_receipt_binding(aios_dir: str, receipt_id: str, effect: Mapping[str, Any],
                           attempt_id: str, provider: str) -> dict[str, Any]:
    rec = load_receipt(aios_dir, receipt_id)
    if rec["effect_id"] != effect.get("effect_id"):
        raise TransitionError("receipt effect binding mismatch")
    if rec["attempt_id"] != attempt_id:
        raise TransitionError("receipt attempt binding mismatch")
    if rec["provider"] != provider:
        raise TransitionError("receipt provider binding mismatch")
    return rec


__all__ = ["ReceiptRecord", "persist_receipt", "load_receipt", "verify_receipt_binding"]
