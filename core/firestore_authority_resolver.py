"""Firestore-backed, Ed25519-verified authority resolution.

Every artifact is independently signed and immutable. This resolver performs
domain validation and cross-binding; it deliberately does not issue permits,
create trust anchors, or call providers.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .contract import contract_identity, validate_contract, verify_permit
from .firestore_authority import AuthorityStoreError, FirestoreAuthorityStore


class FirestoreAuthorityResolutionError(PermissionError):
    """Authority artifacts are missing, invalid, or inconsistently bound."""


class FirestoreAuthorityResolver:
    """Resolve a complete signed authority bundle from immutable Firestore."""

    def __init__(
        self,
        store: FirestoreAuthorityStore,
        *,
        trust_anchor: Mapping[str, Mapping[str, Any]],
    ) -> None:
        if not isinstance(trust_anchor, Mapping) or not trust_anchor:
            raise FirestoreAuthorityResolutionError("pinned trust anchor required; DENY")
        self._store = store
        self._trust_anchor = trust_anchor

    def _read(self, digest: str, record_type: str) -> dict[str, Any]:
        try:
            record = self._store.get_verified(
                digest, trust_anchor=self._trust_anchor, expected_type=record_type
            )
        except (AuthorityStoreError, ValueError, TypeError) as exc:
            raise FirestoreAuthorityResolutionError(
                f"{record_type} authority lookup failed; DENY"
            ) from exc
        if not isinstance(record, dict):
            raise FirestoreAuthorityResolutionError(f"{record_type} must be an object; DENY")
        return record

    def resolve(
        self,
        *,
        contract_digest: str,
        permit_digest: str,
        attestation_digest: str,
        policy_digest: str,
        capability_digests: Mapping[str, str],
    ) -> dict[str, Any]:
        """Return validated records only when every cross-binding agrees.

        capability_digests maps each exact versioned contract capability key
        (for example `name@1.2.3`) to its immutable signed record digest.
        """
        if not isinstance(capability_digests, Mapping):
            raise FirestoreAuthorityResolutionError("capability digest map required; DENY")

        contract = self._read(contract_digest, "EXECUTION_CONTRACT")
        permit = self._read(permit_digest, "EXECUTION_PERMIT")
        attestation = self._read(attestation_digest, "EXECUTION_PERMIT_ATTESTATION")
        policy = self._read(policy_digest, "POLICY")
        try:
            validate_contract(contract)
            cid = contract_identity(contract)
            if cid != contract.get("contract_id", cid):
                raise ValueError("contract identity mismatch")
            verify_permit(contract, permit)
            if attestation != {
                "attestation_type": "EXECUTION_PERMIT_ATTESTATION",
                "contract_id": cid,
                "permit_id": permit["permit_id"],
                "issuer": permit["issuer"],
                "algorithm": "Ed25519",
            }:
                raise ValueError("signed Ed25519 attestation binding mismatch")
            if contract["policy_digest"] != policy_digest:
                raise ValueError("contract policy digest does not select resolved policy")
            if set(capability_digests) != set(contract["capabilities"]):
                raise ValueError("capability digest map differs from contract")
            capabilities: dict[str, dict[str, Any]] = {}
            for key, digest in capability_digests.items():
                record = self._read(digest, "CAPABILITY")
                actual_key = f"{record.get('capability_id')}@{record.get('version')}"
                if actual_key != key or record.get("status") != "ACTIVE":
                    raise ValueError(f"capability is not the exact ACTIVE contract version: {key}")
                capabilities[key] = record
        except (KeyError, TypeError, ValueError) as exc:
            raise FirestoreAuthorityResolutionError(
                f"authority cross-binding rejected: {exc}; DENY"
            ) from exc

        return {
            "contract": contract,
            "permit": permit,
            "attestation": attestation,
            "policy": policy,
            "capabilities": capabilities,
            "authority_backend": "firestore-ed25519",
        }


__all__ = ["FirestoreAuthorityResolutionError", "FirestoreAuthorityResolver"]
