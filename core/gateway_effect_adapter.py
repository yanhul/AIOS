"""Translate an AIOS workload contract into the external gateway effect contract.

The adapter is deliberately not an authority provider. It validates that an
already-authorized workload contract contains the capability/effect requested
by the caller and requires an AIOS-issued permit plus deployment-bound
attestation before crossing into the external gateway.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping

from .attestation import verify_attestation
from .authority import authorize, load_attestation, load_contract, load_permit
from .contract import verify_permit

GATEWAY_PROTOCOL_VERSION = 3
REQUIRED_WORKLOAD_FIELDS = (
    "contract_type", "task_id", "scope", "actor", "capabilities",
    "input_digest", "allowed_effects", "evidence_required", "max_attempts",
    "terminal_states", "policy_digest",
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


def _load_persisted_effect(aios_dir: str, effect_id: str) -> dict[str, object]:
    path = os.path.join(aios_dir, "effects", effect_id + ".json")
    if not os.path.exists(path):
        raise KeyError(f"unknown effect: {effect_id}")
    with open(path, "r", encoding="utf-8") as fh:
        effect = json.load(fh)
    if not isinstance(effect, dict):
        raise ValueError("persisted effect record must be an object")
    if effect.get("effect_id") != effect_id:
        raise ValueError("persisted effect identity does not match requested effect")
    return effect


def build_gateway_effect_contract(
    workload_contract: Mapping[str, object],
    *,
    aios_dir: str,
    persisted_effect: Mapping[str, object],
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
    """Build a v3 gateway contract from the current persisted authority/effect state.

    Caller-supplied contract/permit/effect data is treated as an assertion,
    never as the source of truth. The adapter reloads the persisted effect,
    contract, permit and attestation and re-runs current authorization before
    crossing into the external gateway.
    """
    if not isinstance(persisted_effect, Mapping):
        raise ValueError("persisted_effect must be a mapping")
    _validate_workload_contract(workload_contract)
    effect_id = _required_text(effect_id, "effect_id")
    action = _required_text(action, "action")
    capability_ref = _required_text(capability_ref, "capability_ref")
    authority_ref = _required_text(authority_ref, "authority_ref")
    evidence_ref = _required_text(evidence_ref, "evidence_ref")
    lineage_ref = _required_text(lineage_ref, "lineage_ref")
    idempotency_key = _required_text(idempotency_key, "idempotency_key")

    current_effect = _load_persisted_effect(aios_dir, effect_id)
    supplied_effect = dict(persisted_effect)
    if supplied_effect != current_effect:
        raise ValueError("persisted effect assertion does not match authoritative effect")

    stored_effect_id = _required_text(current_effect.get("effect_id"), "persisted effect.effect_id")
    stored_contract_id = _required_text(current_effect.get("contract_id"), "persisted effect.contract_id")
    stored_permit_id = _required_text(current_effect.get("permit_id"), "persisted effect.permit_id")
    stored_actor = _required_text(current_effect.get("actor"), "persisted effect.actor")
    stored_action = _required_text(current_effect.get("effect_type"), "persisted effect.effect_type")
    if effect_id != stored_effect_id:
        raise ValueError("effect_id does not match persisted effect")
    if action != stored_action:
        raise ValueError("action does not match persisted effect")
    if authority_ref != stored_permit_id:
        raise ValueError("authority_ref does not match persisted effect permit")

    authorize(aios_dir, stored_contract_id, stored_permit_id)
    current_contract = load_contract(aios_dir, stored_contract_id)
    current_permit = load_permit(aios_dir, stored_permit_id)
    current_attestation = load_attestation(aios_dir, stored_permit_id)
    verify_permit(current_contract, current_permit)
    verify_attestation(current_contract, current_permit, current_attestation, attestation_secret)

    if dict(current_contract) != dict(workload_contract):
        raise ValueError("workload contract does not match persisted authority contract")
    if not isinstance(authority_permit, Mapping) or dict(authority_permit) != dict(current_permit):
        raise ValueError("authority permit does not match current persisted permit")
    if not isinstance(authority_attestation, Mapping) or dict(authority_attestation) != dict(current_attestation):
        raise ValueError("authority attestation does not match current persisted attestation")
    if stored_actor != current_contract["actor"]:
        raise ValueError("persisted effect actor does not match current contract actor")
    if capability_ref not in current_contract["capabilities"]:
        raise ValueError("capability_ref is not granted by workload contract")
    if action not in current_contract["allowed_effects"]:
        raise ValueError("action is not allowed by workload contract")
    if current_effect.get("policy_digest") != current_contract["policy_digest"]:
        raise ValueError("persisted effect policy digest differs from current authority")

    return {
        "protocol_version": GATEWAY_PROTOCOL_VERSION,
        "effect_id": effect_id,
        "action": action,
        "capability_ref": capability_ref,
        "authority_ref": stored_permit_id,
        "evidence_ref": evidence_ref,
        "lineage_ref": lineage_ref,
        "idempotency_key": idempotency_key,
    }
