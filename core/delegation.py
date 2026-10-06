"""Governed, durable delegation between AIOS workload roles.

This is an AIOS control-plane primitive, not a multi-agent runtime. A
delegation is a proposal/handoff bound to an existing execution contract and
permit, a registered capability, and an immutable execution lineage. It never
issues authority and never executes the delegated work.

The intended flow is:
    source contract/permit -> delegation proposal -> target worker
    -> child execution under its own governed permit -> receipt/evidence

This absorbs the useful Team-Bot pattern (role-oriented handoff) while keeping
AIOS authority, lineage, and evidence boundaries authoritative.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from .capabilities import Capability, CapabilityRegistry
from .contract import contract_identity, verify_permit
from .execution_lineage import ExecutionLineage, validate_lineage
from .mutation import canonical_json, commit_batch

DELEGATION_TYPE = "GOVERNED_DELEGATION"
DELEGATION_STATE = "PROPOSED"
AUTHORITY_MODES = frozenset({"caller_bound", "service_bound", "none"})
MEMORY_SCOPES = frozenset({"private", "shared"})


class DelegationError(ValueError):
    """Raised when a delegation is not valid under its governing context."""


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DelegationError(f"{name} must be a non-empty string")
    return value


def _strings(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise DelegationError(f"{name} must be a non-empty list")
    result = tuple(_text(item, name) for item in value)
    if len(set(result)) != len(result):
        raise DelegationError(f"{name} must not contain duplicates")
    return result


@dataclass(frozen=True)
class DelegationRequest:
    delegation_id: str
    source_contract_id: str
    source_permit_id: str
    source_actor: str
    target_role: str
    authority_mode: str
    credential_ref: str | None
    memory_scope: str
    target_capability: str
    operation_id: str
    input_digest: str
    evidence_required: tuple[str, ...]
    lineage: ExecutionLineage
    state: str = DELEGATION_STATE

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_type": DELEGATION_TYPE,
            "delegation_id": self.delegation_id,
            "source_contract_id": self.source_contract_id,
            "source_permit_id": self.source_permit_id,
            "source_actor": self.source_actor,
            "target_role": self.target_role,
            "authority_mode": self.authority_mode,
            "credential_ref": self.credential_ref,
            "memory_scope": self.memory_scope,
            "target_capability": self.target_capability,
            "operation_id": self.operation_id,
            "input_digest": self.input_digest,
            "evidence_required": list(self.evidence_required),
            "lineage": self.lineage.as_record(),
            "state": self.state,
        }


def _delegation_id(payload: Mapping[str, Any]) -> str:
    identity = {
        "source_contract_id": payload["source_contract_id"],
        "source_permit_id": payload["source_permit_id"],
        "source_actor": payload["source_actor"],
        "target_role": payload["target_role"],
        "authority_mode": payload["authority_mode"],
        "credential_ref": payload["credential_ref"],
        "memory_scope": payload["memory_scope"],
        "target_capability": payload["target_capability"],
        "operation_id": payload["operation_id"],
        "input_digest": payload["input_digest"],
        "lineage_digest": payload["lineage"]["lineage_digest"],
    }
    return "DG-" + hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()


def build_delegation(
    *,
    contract: Mapping[str, Any],
    permit: Mapping[str, Any],
    source_actor: str,
    target_role: str,
    authority_mode: str,
    credential_ref: str | None,
    memory_scope: str,
    target_capability: str,
    operation_id: str,
    input_digest: str,
    evidence_required: list[str] | tuple[str, ...],
    lineage: Mapping[str, Any] | ExecutionLineage,
    registry: CapabilityRegistry,
) -> DelegationRequest:
    """Build a non-authorizing handoff bound to existing AIOS authority.

    The source permit must already authorize the actor. The target capability
    must already be registered. This function cannot mint or broaden a permit.
    """
    try:
        verify_permit(dict(contract), dict(permit))
    except (TypeError, ValueError) as exc:
        raise DelegationError(f"source authority is invalid: {exc}") from exc

    if source_actor != contract.get("actor") or source_actor != permit.get("actor"):
        raise DelegationError("source actor does not match governing contract/permit")

    _text(target_role, "target_role")
    if authority_mode not in AUTHORITY_MODES:
        raise DelegationError(f"unsupported authority_mode: {authority_mode}")
    if memory_scope not in MEMORY_SCOPES:
        raise DelegationError(f"unsupported memory_scope: {memory_scope}")
    if credential_ref is not None:
        credential_ref = _text(credential_ref, "credential_ref")
    if authority_mode == "caller_bound" and credential_ref is None:
        raise DelegationError("caller_bound authority requires credential_ref")
    if authority_mode == "service_bound" and credential_ref is None:
        raise DelegationError("service_bound authority requires credential_ref")
    if authority_mode == "caller_bound" and credential_ref is not None and not credential_ref.startswith("caller:"):
        raise DelegationError("caller_bound authority requires a caller-scoped credential_ref")
    if authority_mode == "service_bound" and credential_ref is not None and not credential_ref.startswith("service:"):
        raise DelegationError("service_bound authority requires a service-scoped credential_ref")
    if authority_mode == "none" and credential_ref is not None:
        raise DelegationError("none authority cannot carry credentials")
    if memory_scope == "shared" and "memory_write" not in permit.get("allowed_effects", []):
        raise DelegationError("shared memory requires explicit memory_write permit")
    target_capability = _text(target_capability, "target_capability")
    operation_id = _text(operation_id, "operation_id")
    _text(input_digest, "input_digest")
    required = _strings(evidence_required, "evidence_required")

    try:
        capability = registry.require(target_capability)
    except (TypeError, ValueError) as exc:
        raise DelegationError(f"target capability is unavailable: {exc}") from exc

    if capability.status != "ACTIVE":
        raise DelegationError("target capability must be ACTIVE")

    if isinstance(lineage, ExecutionLineage):
        lineage_obj = lineage
    else:
        try:
            lineage_obj = validate_lineage(lineage)
        except (TypeError, ValueError) as exc:
            raise DelegationError(f"delegation lineage is invalid: {exc}") from exc

    payload = {
        "source_contract_id": contract_identity(contract),
        "source_permit_id": _text(permit.get("permit_id"), "permit_id"),
        "source_actor": _text(source_actor, "source_actor"),
        "target_role": target_role,
        "authority_mode": authority_mode,
        "credential_ref": credential_ref,
        "memory_scope": memory_scope,
        "target_capability": target_capability,
        "operation_id": operation_id,
        "input_digest": input_digest,
        "evidence_required": list(required),
        "lineage": lineage_obj.as_record(),
    }
    return DelegationRequest(
        delegation_id=_delegation_id(payload),
        source_contract_id=payload["source_contract_id"],
        source_permit_id=payload["source_permit_id"],
        source_actor=payload["source_actor"],
        target_role=target_role,
        authority_mode=authority_mode,
        credential_ref=credential_ref,
        memory_scope=memory_scope,
        target_capability=target_capability,
        operation_id=operation_id,
        input_digest=input_digest,
        evidence_required=required,
        lineage=lineage_obj,
    )


def validate_delegation(
    request: DelegationRequest,
    *,
    contract: Mapping[str, Any],
    permit: Mapping[str, Any],
    registry: CapabilityRegistry,
) -> None:
    """Fail closed when a persisted handoff no longer matches its authority."""
    if request.state != DELEGATION_STATE:
        raise DelegationError("delegation is not in PROPOSED state")
    if request.source_contract_id != contract_identity(contract):
        raise DelegationError("delegation contract binding mismatch")
    if request.source_permit_id != permit.get("permit_id"):
        raise DelegationError("delegation permit binding mismatch")
    if request.source_actor != contract.get("actor"):
        raise DelegationError("delegation actor mismatch")
    if request.authority_mode not in AUTHORITY_MODES:
        raise DelegationError("unsupported authority_mode")
    if request.memory_scope not in MEMORY_SCOPES:
        raise DelegationError("unsupported memory_scope")
    if request.authority_mode == "caller_bound" and not request.credential_ref:
        raise DelegationError("caller_bound authority requires credential_ref")
    if request.authority_mode == "service_bound" and not request.credential_ref:
        raise DelegationError("service_bound authority requires credential_ref")
    if request.authority_mode == "caller_bound" and request.credential_ref and not request.credential_ref.startswith("caller:"):
        raise DelegationError("caller_bound authority requires a caller-scoped credential_ref")
    if request.authority_mode == "service_bound" and request.credential_ref and not request.credential_ref.startswith("service:"):
        raise DelegationError("service_bound authority requires a service-scoped credential_ref")
    if request.authority_mode == "none" and request.credential_ref is not None:
        raise DelegationError("none authority cannot carry credential_ref")
    verify_permit(dict(contract), dict(permit))
    if request.memory_scope == "shared" and "memory_write" not in permit.get("allowed_effects", []):
        raise DelegationError("shared memory requires explicit memory_write permit")
    capability = registry.require(request.target_capability)
    if capability.status != "ACTIVE":
        raise DelegationError("target capability must be ACTIVE")
    if request.lineage.attempt_id == "":
        raise DelegationError("delegation lineage attempt is empty")


def persist_delegation(aios_dir: str, request: DelegationRequest) -> str:
    """Persist the proposal atomically; persistence is not authorization."""
    record = request.as_dict()
    path = f"delegations/{request.delegation_id}.json"
    event = {
        "kind": "governed_delegation",
        "action": "propose",
        "delegation_id": request.delegation_id,
        "source_contract_id": request.source_contract_id,
        "source_permit_id": request.source_permit_id,
        "target_role": request.target_role,
        "authority_mode": request.authority_mode,
        "memory_scope": request.memory_scope,
        "target_capability": request.target_capability,
        "operation_id": request.operation_id,
    }
    commit_batch(
        aios_dir,
        [(path, record),
         (f"events/delegation-propose-{request.delegation_id}.json", event)],
    )
    return request.delegation_id


def load_delegation(record: Mapping[str, Any]) -> DelegationRequest:
    """Rehydrate and integrity-check a delegation record."""
    if record.get("record_type") != DELEGATION_TYPE:
        raise DelegationError("delegation record_type mismatch")
    lineage = validate_lineage(record.get("lineage", {}))
    required = _strings(record.get("evidence_required"), "evidence_required")
    values = {
        "delegation_id": _text(record.get("delegation_id"), "delegation_id"),
        "source_contract_id": _text(record.get("source_contract_id"), "source_contract_id"),
        "source_permit_id": _text(record.get("source_permit_id"), "source_permit_id"),
        "source_actor": _text(record.get("source_actor"), "source_actor"),
        "target_role": _text(record.get("target_role"), "target_role"),
        "authority_mode": _text(record.get("authority_mode"), "authority_mode"),
        "credential_ref": record.get("credential_ref"),
        "memory_scope": _text(record.get("memory_scope"), "memory_scope"),
        "target_capability": _text(record.get("target_capability"), "target_capability"),
        "operation_id": _text(record.get("operation_id"), "operation_id"),
        "input_digest": _text(record.get("input_digest"), "input_digest"),
    }
    request = DelegationRequest(
        **values, evidence_required=required, lineage=lineage,
        state=record.get("state", DELEGATION_STATE),
    )
    # Recompute identity without requiring a registry, so persisted tampering is caught.
    identity_payload = {
        "source_contract_id": request.source_contract_id,
        "source_permit_id": request.source_permit_id,
        "source_actor": request.source_actor,
        "target_role": request.target_role,
        "authority_mode": request.authority_mode,
        "credential_ref": request.credential_ref,
        "memory_scope": request.memory_scope,
        "target_capability": request.target_capability,
        "operation_id": request.operation_id,
        "input_digest": request.input_digest,
        "lineage_digest": request.lineage.as_record()["lineage_digest"],
    }
    if request.delegation_id != _delegation_id({
        **identity_payload,
        "lineage": request.lineage.as_record(),
    }):
        raise DelegationError("delegation identity mismatch")
    return request


__all__ = [
    "DELEGATION_TYPE",
    "DELEGATION_STATE",
    "DelegationError",
    "DelegationRequest",
    "AUTHORITY_MODES",
    "MEMORY_SCOPES",
    "build_delegation",
    "validate_delegation",
    "persist_delegation",
    "load_delegation",
]
