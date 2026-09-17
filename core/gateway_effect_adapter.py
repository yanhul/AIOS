"""Translate an AIOS workload contract into the external gateway effect contract.

The adapter is deliberately not an authority provider. It validates that an
already-authorized workload contract contains the capability/effect requested
by the caller and requires an AIOS-issued permit plus deployment-bound
attestation before crossing into the external gateway.
"""

from __future__ import annotations

from collections.abc import Mapping

from .attestation import verify_attestation
from .contract import verify_permit

GATEWAY_PROTOCOL_VERSION = 3
REQUIRED_WORKLOAD_FIELDS = (
    "contract_type",
    "task_id",
    "scope",
    "actor",
    "capabilities",
    "input_digest",
    "allowed_effects",
    "evidence_required",
    "max_attempts",
    "terminal_states",
    "policy_digest",
)


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be non-empty")
    return value.strip()


def _validate_workload_contract(contract: Mapping[str, object]) -> None:
    for field in REQUIRED_WORKLOAD_FIELDS:
        if field not in contract:
            raise ValueError(f"missing workload contract field: {field}")

    capabilities = contract["capabilities"]
    if not isinstance(capabilities, (list, tuple)) or not capabilities:
        raise ValueError("capabilities must be a non-empty sequence")
    for ref in capabilities:
        if not isinstance(ref, str) or "@" not in ref or ref.endswith("@"):
            raise ValueError("capabilities must contain versioned refs")

    allowed_effects = contract["allowed_effects"]
    if not isinstance(allowed_effects, (list, tuple, set, frozenset)):
        raise ValueError("allowed_effects must be a sequence")

    max_attempts = contract["max_attempts"]
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts < 1:
        raise ValueError("max_attempts must be a positive integer")


def build_gateway_effect_contract(
    workload_contract: Mapping[str, object],
    *,
    effect_id: str,
    action: str,
    capability_ref: str,
    authority_ref: str,
    authority_permit: Mapping[str, object],
    authority_attestation: Mapping[str, object],
    attestation_secret: str,
    evidence_ref: str,
    lineage_ref: str,
    idempotency_key: str,
) -> dict[str, object]:
    """Build the v3 gateway contract without minting authority.

    The caller must provide the already-issued permit and its deployment-bound
    attestation. The adapter verifies both and only carries the verified
    ``permit_id`` across the boundary; it never creates authority material.
    """
    _validate_workload_contract(workload_contract)

    effect_id = _required_text(effect_id, "effect_id")
    action = _required_text(action, "action")
    capability_ref = _required_text(capability_ref, "capability_ref")
    authority_ref = _required_text(authority_ref, "authority_ref")
    evidence_ref = _required_text(evidence_ref, "evidence_ref")
    lineage_ref = _required_text(lineage_ref, "lineage_ref")
    idempotency_key = _required_text(idempotency_key, "idempotency_key")

    capabilities = workload_contract["capabilities"]
    if capability_ref not in capabilities:
        raise ValueError("capability_ref is not granted by workload contract")

    if action not in workload_contract["allowed_effects"]:
        raise ValueError("action is not allowed by workload contract")

    if not isinstance(authority_permit, Mapping):
        raise ValueError("authority_permit must be a mapping")
    verify_permit(dict(workload_contract), dict(authority_permit))
    permit_id = _required_text(authority_permit.get("permit_id"), "authority_permit.permit_id")
    if authority_ref != permit_id:
        raise ValueError("authority_ref does not match verified permit")

    if not isinstance(authority_attestation, Mapping):
        raise ValueError("authority_attestation must be a mapping")
    verify_attestation(
        dict(workload_contract),
        dict(authority_permit),
        dict(authority_attestation),
        attestation_secret,
    )

    return {
        "protocol_version": GATEWAY_PROTOCOL_VERSION,
        "effect_id": effect_id,
        "action": action,
        "capability_ref": capability_ref,
        "authority_ref": permit_id,
        "evidence_ref": evidence_ref,
        "lineage_ref": lineage_ref,
        "idempotency_key": idempotency_key,
    }
