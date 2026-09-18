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

from .authority import authorize, load_contract, load_permit
from .contract import verify_permit
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
    """Persist a receipt only for the authoritative durable current attempt.

    The caller-supplied effect is treated as a hint for identity only. The
    durable effect record is reloaded and its authorization/attempt/provider
    binding is verified before a receipt can be created.
    """
    effect_id = effect.get("effect_id") if isinstance(effect, Mapping) else None
    if not all(isinstance(v, str) and v.strip() for v in
               (effect_id, attempt_id, provider, provider_operation_id)):
        raise ValueError("receipt identity fields are required")
    if outcome not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        raise ValueError("receipt outcome must be an observed terminal outcome")
    if not isinstance(observation, dict) or not observation:
        raise ValueError("receipt observation must be a non-empty dict")

    recover_pending(aios_dir)
    effect_path = os.path.join(aios_dir, "effects", effect_id + ".json")
    if not os.path.exists(effect_path):
        raise KeyError(f"unknown effect: {effect_id}")
    with open(effect_path, "r", encoding="utf-8") as fh:
        authoritative = json.load(fh)
    if not isinstance(authoritative, dict):
        raise TransitionError("persisted effect is invalid")
    required = ("effect_id", "contract_id", "permit_id", "actor", "effect_type",
                "policy_digest", "max_attempts", "state", "attempt",
                "attempt_id", "provider")
    if any(key not in authoritative for key in required):
        raise TransitionError("persisted effect schema is incomplete")
    if authoritative["effect_id"] != effect_id:
        raise TransitionError("persisted effect identity mismatch")
    authorize(aios_dir, authoritative["contract_id"], authoritative["permit_id"])
    contract = load_contract(aios_dir, authoritative["contract_id"])
    permit = load_permit(aios_dir, authoritative["permit_id"])
    verify_permit(contract, permit)
    if authoritative["actor"] != contract["actor"]:
        raise TransitionError("persisted effect actor is not authorized by contract")
    if authoritative["effect_type"] not in contract["allowed_effects"]:
        raise TransitionError("persisted effect type is not authorized by contract")
    if authoritative["policy_digest"] != contract["policy_digest"]:
        raise TransitionError("effect policy digest differs from authorized contract")
    if authoritative["max_attempts"] != contract["max_attempts"]:
        raise TransitionError("effect attempt budget differs from authorized contract")
    if authoritative["state"] not in ("DISPATCHED", "UNKNOWN"):
        raise TransitionError("receipt requires a currently DISPATCHED or UNKNOWN effect")
    if authoritative["attempt_id"] != attempt_id:
        raise TransitionError("receipt attempt does not match authoritative effect attempt")
    if authoritative["provider"] != provider:
        raise TransitionError("receipt provider does not match authoritative effect provider")
    if not any(isinstance(ref, str) and ref.split("@", 1)[0] == provider
               for ref in contract.get("capabilities", [])):
        raise TransitionError("provider capability is not authorized by contract")

    rec = ReceiptRecord(
        _receipt_id(effect_id, attempt_id, provider, provider_operation_id),
        effect_id, attempt_id, provider, provider_operation_id, outcome, observation,
    ).as_record()
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
