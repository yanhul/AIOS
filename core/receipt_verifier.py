"""Independent verification of immutable terminal provider receipts.

This module deliberately re-verifies persisted receipts from disk instead of
trusting the in-memory result returned by observe(). It is suitable for
restart-time audit and downstream promotion gates.
"""
from __future__ import annotations

import json
import os

from .effect_authority import (
    EVIDENCE_AUTHORITY,
    ProviderAuthenticationError,
    _load_owned_effect,
    _verify_provider_receipt,
    mint_observation_evidence,
    observation_digest,
)


class PersistedReceiptError(ValueError):
    """A persisted terminal receipt is missing, malformed, tampered or untrusted."""


def verify_persisted_receipt(
    aios_dir: str,
    receipt_id: str,
    actor: str,
    *,
    provider_keyring=None,
    provider_public_keyring=None,
    now=None,
) -> dict:
    """Re-verify a persisted terminal receipt against current authoritative state.

    The provider trust anchor is supplied by deployment configuration, never
    loaded from the receipt itself. The effect/contract/permit are reloaded
    from the authority store and all receipt bindings and AIOS evidence are
    independently reconstructed.
    """
    if not isinstance(receipt_id, str) or not receipt_id.startswith("PR-") or len(receipt_id) != 35:
        raise PersistedReceiptError("invalid provider receipt id")
    rel = os.path.join("provider_receipts", receipt_id + ".json")
    path = os.path.join(aios_dir, rel)
    if os.path.islink(path) or not os.path.isfile(path):
        raise PersistedReceiptError("persisted provider receipt is missing or is a symlink")
    try:
        with open(path, "r", encoding="utf-8") as stream:
            receipt = json.load(stream)
    except (OSError, ValueError) as exc:
        raise PersistedReceiptError(f"persisted provider receipt is unreadable: {exc}") from exc
    expected_keys = {
        "record_type", "receipt_id", "effect_id", "contract_id", "permit_id",
        "attempt_id", "provider", "provider_operation_id", "outcome",
        "observation", "observation_digest", "authentication", "evidence",
        "evidence_authority",
    }
    if not isinstance(receipt, dict) or set(receipt) != expected_keys:
        raise PersistedReceiptError("persisted provider receipt schema mismatch")
    if receipt["record_type"] != "AIOS_TERMINAL_PROVIDER_RECEIPT" or receipt["receipt_id"] != receipt_id:
        raise PersistedReceiptError("persisted provider receipt identity mismatch")
    try:
        effect, _contract = _load_owned_effect(aios_dir, receipt["effect_id"], actor, "receipt verification")
        if effect.get("state") != receipt["outcome"]:
            raise PersistedReceiptError("receipt outcome differs from authoritative terminal effect")
        for key in ("effect_id", "contract_id", "permit_id", "attempt_id", "provider"):
            expected = effect.get(key) if key != "provider" else effect.get("provider")
            if receipt.get(key) != expected:
                raise PersistedReceiptError(f"receipt {key} binding mismatch")
        if receipt["outcome"] not in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
            raise PersistedReceiptError("receipt outcome is not terminal")
        raw = receipt["observation"]
        if not isinstance(raw, dict) or not raw or observation_digest(raw) != receipt["observation_digest"]:
            raise PersistedReceiptError("persisted provider observation digest mismatch")
        if receipt["evidence_authority"] != EVIDENCE_AUTHORITY:
            raise PersistedReceiptError("persisted evidence authority marker mismatch")
        rebuilt = mint_observation_evidence(
            receipt["effect_id"], receipt["attempt_id"], receipt["provider"],
            receipt["provider_operation_id"], raw,
        )
        if receipt["evidence"] != rebuilt:
            raise PersistedReceiptError("persisted AIOS evidence does not match reconstructed observation")
        terminal = effect.get("provider_observation")
        if not isinstance(terminal, dict):
            raise PersistedReceiptError("terminal effect has no provider observation")
        for key, value in (
            ("provider", receipt["provider"]),
            ("provider_operation_id", receipt["provider_operation_id"]),
            ("effect_id", receipt["effect_id"]),
            ("attempt_id", receipt["attempt_id"]),
            ("evidence", rebuilt),
            ("evidence_authority", EVIDENCE_AUTHORITY),
        ):
            if terminal.get(key) != value:
                raise PersistedReceiptError(f"terminal effect {key} differs from persisted receipt")
        provider_record = {
            "provider": receipt["provider"],
            "provider_operation_id": receipt["provider_operation_id"],
            "effect_id": receipt["effect_id"],
            "attempt_id": receipt["attempt_id"],
            "observation": raw,
            "authentication": receipt["authentication"],
        }
        verified_auth = _verify_provider_receipt(
            effect, receipt["outcome"], provider_record,
            provider_keyring, now, provider_public_keyring,
        )
        if verified_auth != receipt["authentication"]:
            raise PersistedReceiptError("provider authentication differs from verified receipt")
    except PersistedReceiptError:
        raise
    except (ProviderAuthenticationError, KeyError, OSError, ValueError) as exc:
        raise PersistedReceiptError(f"persisted provider receipt verification failed: {exc}") from exc
    return {
        "verified": True,
        "receipt_id": receipt_id,
        "effect_id": receipt["effect_id"],
        "attempt_id": receipt["attempt_id"],
        "provider": receipt["provider"],
        "outcome": receipt["outcome"],
        "observation_digest": receipt["observation_digest"],
        "evidence": rebuilt,
    }


__all__ = ["PersistedReceiptError", "verify_persisted_receipt"]
