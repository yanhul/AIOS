"""Firestore-first external effect orchestration.

Unlike core.runtime.execute(), this entrypoint never reads or writes the
filesystem effect journal. Contract and permit authorization remain in the
existing AIOS authority store; effect/attempt/receipt state lives in the
FirestoreEffectStore. The provider is called only after dispatch intent has
been transactionally committed.
"""
from __future__ import annotations

import os
from typing import Any

from .authority import authorize, load_contract, load_permit
from .execution_lineage import bind_lineage_to_effect, verify_effect_lineage
from .effect_authority import (
    ProviderAuthenticationError,
    _id as effect_id_for,
    _verify_provider_receipt,
    mint_observation_evidence,
    observation_digest,
)
from .runtime import ProviderReceipt, _provider_authorized, _text, validate_receipt


def _authorized_context(aios_dir, contract_id, permit_id, actor, adapter, *,
                        authority_resolver=None, authority_digests=None):
    if authority_resolver is not None:
        if not isinstance(authority_digests, dict) or set(authority_digests) != {
            "contract_digest", "permit_digest", "attestation_digest",
            "policy_digest", "capability_digests",
        }:
            raise PermissionError("complete Firestore authority digest bundle required; DENY")
        bundle = authority_resolver.resolve(**authority_digests)
        contract, permit = bundle["contract"], bundle["permit"]
        from .contract import contract_identity
        if contract_identity(contract) != contract_id:
            raise PermissionError("Firestore contract identity differs from requested contract; DENY")
        if permit.get("permit_id") != permit_id:
            raise PermissionError("Firestore permit identity differs from requested permit; DENY")
        if bundle.get("authority_backend") != "firestore-ed25519":
            raise PermissionError("unverified authority backend; DENY")
    else:
        authorize(aios_dir, contract_id, permit_id)
        contract = load_contract(aios_dir, contract_id)
        permit = load_permit(aios_dir, permit_id)
    if contract.get("actor") != actor or permit.get("actor") != actor:
        raise PermissionError("actor does not match authorized contract/permit")
    provider = _text(getattr(adapter, "name", None), "adapter.name")
    if not _provider_authorized(contract, provider):
        raise PermissionError("provider capability is not authorized by contract")
    if "external_effect" not in contract.get("allowed_effects", []):
        raise PermissionError("external effect is not authorized by contract")
    return contract, provider


def _provider_record(receipt: ProviderReceipt) -> dict[str, Any]:
    record = {
        "provider": receipt.provider,
        "provider_operation_id": receipt.provider_operation_id,
        "effect_id": receipt.effect_id,
        "attempt_id": receipt.attempt_id,
        "observation": receipt.observation,
    }
    if receipt.authentication is not None:
        record["authentication"] = receipt.authentication
    return record


def _verified_receipt(effect, receipt, outcome, *, provider_keyring, provider_public_keyring, now):
    record = _provider_record(receipt)
    auth = _verify_provider_receipt(
        effect, outcome, record, provider_keyring, now, provider_public_keyring
    )
    evidence = mint_observation_evidence(
        effect["effect_id"], receipt.attempt_id, receipt.provider,
        receipt.provider_operation_id, receipt.observation
    )
    return {
        "receipt_id": auth["receipt_id"],
        "provider": receipt.provider,
        "provider_operation_id": receipt.provider_operation_id,
        "outcome": outcome,
        "observation": receipt.observation,
        "observation_digest": observation_digest(receipt.observation),
        "evidence": evidence,
    }, auth


def execute_firestore_effect(
    aios_dir, store, contract_id, permit_id, logical_operation_id, actor, adapter,
    *, provider_keyring=None, provider_public_keyring=None, now=None, lineage=None,
    authority_resolver=None, authority_digests=None
):
    """Create, dispatch, execute once, verify receipt, and commit terminal state."""
    _text(logical_operation_id, "logical_operation_id")
    _text(actor, "actor")
    contract, provider = _authorized_context(
        aios_dir, contract_id, permit_id, actor, adapter,
        authority_resolver=authority_resolver, authority_digests=authority_digests
    )
    if os.environ.get("AIOS_REQUIRE_EXECUTION_LINEAGE", "").lower() == "true" and lineage is None:
        raise PermissionError("production Firestore execution requires verified execution lineage; DENY")
    effect_id = effect_id_for(contract_id, logical_operation_id, actor)
    effect = store.create_effect({
        "effect_id": effect_id,
        "logical_operation_id": logical_operation_id,
        "contract_id": contract_id,
        "permit_id": permit_id,
        "actor": actor,
        "effect_type": "external_effect",
        "policy_digest": contract["policy_digest"],
        "max_attempts": contract["max_attempts"],
        "state": "PLANNED",
        **({"authority_digests": dict(authority_digests)} if authority_resolver is not None else {}),
    })
    if effect.get("state") != "PLANNED":
        raise RuntimeError(
            "effect already exists outside PLANNED; use resume_firestore_effect, never execute again"
        )
    attempt_id = f"{effect_id}:attempt:1"
    lineage_binding = None
    if lineage is not None:
        lineage_binding = bind_lineage_to_effect(
            lineage, contract, contract_id, permit_id, provider
        )
        verify_effect_lineage(
            lineage_binding, contract, contract_id, permit_id, provider, attempt_id
        )
    dispatched = store.dispatch(
        effect_id=effect_id, attempt_id=attempt_id, provider=provider,
        expected_revision=effect["revision"], lineage=lineage_binding
    )

    try:
        receipt = adapter.execute(
            contract=dict(contract), effect=dict(dispatched), attempt_id=attempt_id
        )
        validate_receipt(receipt, dispatched, attempt_id, provider)
        receipt_record, auth = _verified_receipt(
            dispatched, receipt, receipt.outcome,
            provider_keyring=provider_keyring,
            provider_public_keyring=provider_public_keyring, now=now
        )
    except Exception as exc:
        return store.mark_unknown(
            effect_id=effect_id, attempt_id=attempt_id,
            reason=f"provider execution/receipt ambiguous: {type(exc).__name__}: {exc}",
            expected_revision=dispatched["revision"]
        )

    return store.record_verified_receipt(
        effect_id=effect_id, attempt_id=attempt_id, receipt=receipt_record,
        verified_authentication=auth, expected_revision=dispatched["revision"]
    )


def resume_firestore_effect(
    aios_dir, store, effect_id, attempt_id, actor, adapter,
    *, provider_keyring=None, provider_public_keyring=None, now=None,
    authority_resolver=None, authority_digests=None
):
    """Recover one exact attempt via provider reconciliation; never re-execute."""
    _text(actor, "actor")
    recovered = store.resume_same_attempt(effect_id=effect_id, attempt_id=attempt_id)
    effect = recovered["effect"]
    if effect.get("state") in ("OBSERVED_SUCCESS", "OBSERVED_FAILURE"):
        # A worker may die after terminal commit but before acknowledgement.
        # The durable receipt/state is authoritative; never call provider again.
        return effect
    if effect.get("actor") != actor:
        raise PermissionError("resume actor does not own durable effect")
    if authority_resolver is not None and authority_digests is None:
        authority_digests = effect.get("authority_digests")
    contract, provider = _authorized_context(
        aios_dir, effect["contract_id"], effect["permit_id"], actor, adapter,
        authority_resolver=authority_resolver, authority_digests=authority_digests
    )
    if effect.get("provider") != provider:
        raise PermissionError("resume provider does not match durable dispatched provider")
    reconcile = getattr(adapter, "reconcile", None)
    if not callable(reconcile):
        raise RuntimeError("safe recovery requires provider reconcile(); refusing to execute again")

    try:
        receipt = reconcile(contract=dict(contract), effect=dict(effect), attempt_id=attempt_id)
        validate_receipt(receipt, effect, attempt_id, provider)
        receipt_record, auth = _verified_receipt(
            effect, receipt, receipt.outcome,
            provider_keyring=provider_keyring,
            provider_public_keyring=provider_public_keyring, now=now
        )
    except Exception as exc:
        if effect["state"] == "DISPATCHED":
            return store.mark_unknown(
                effect_id=effect_id, attempt_id=attempt_id,
                reason=f"provider reconciliation inconclusive: {type(exc).__name__}: {exc}",
                expected_revision=effect["revision"]
            )
        return effect

    return store.record_verified_receipt(
        effect_id=effect_id, attempt_id=attempt_id, receipt=receipt_record,
        verified_authentication=auth, expected_revision=effect["revision"]
    )


__all__ = ["execute_firestore_effect", "resume_firestore_effect"]
