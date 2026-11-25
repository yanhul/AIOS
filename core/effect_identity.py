"""Canonical logical-operation identity shared by L3 (loop intent) and L5 (effect ledger).

Decision A (B-1): L3 owns the logical operation identity
``(contract_id, logical_operation_id, actor)``. Both layers derive the effect
and attempt identities from it with these functions only, so one logical
operation has exactly one effect identity across restarts and retries.
"""
from __future__ import annotations

import hashlib
from typing import Any, Mapping

from .mutation import canonical_json

IDENTITY_VERSION = 2
_FIELDS = ("identity_version", "contract_id", "actor", "logical_operation_id", "effect_id", "attempt", "attempt_id")


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def effect_identity(contract_id: str, logical_operation_id: str, actor: str) -> str:
    value = {"contract_id": _text(contract_id, "contract_id"),
             "logical_operation_id": _text(logical_operation_id, "logical_operation_id"),
             "actor": _text(actor, "actor")}
    return "EF-" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def attempt_identity(effect_id: str, attempt: int) -> str:
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise ValueError("attempt must be a positive integer")
    return f"{_text(effect_id, 'effect_id')}:attempt:{attempt}"


def operation_identity(contract_id: str, logical_operation_id: str, actor: str, attempt: int = 1) -> dict:
    effect_id = effect_identity(contract_id, logical_operation_id, actor)
    return {"identity_version": IDENTITY_VERSION, "contract_id": contract_id, "actor": actor,
            "logical_operation_id": logical_operation_id, "effect_id": effect_id,
            "attempt": attempt, "attempt_id": attempt_identity(effect_id, attempt)}


def verify_operation_identity(record: Mapping[str, Any]) -> dict:
    """Recompute and compare every derived field; raise ValueError on any tamper."""
    if not isinstance(record, Mapping) or record.get("identity_version") != IDENTITY_VERSION:
        raise ValueError("operation identity version is missing or unsupported")
    expected = operation_identity(record.get("contract_id"), record.get("logical_operation_id"),
                                  record.get("actor"), record.get("attempt"))
    actual = {k: record.get(k) for k in _FIELDS}
    if actual != expected:
        raise ValueError("operation identity does not match its canonical derivation")
    return expected


__all__ = ["IDENTITY_VERSION", "attempt_identity", "effect_identity", "operation_identity",
           "verify_operation_identity"]
