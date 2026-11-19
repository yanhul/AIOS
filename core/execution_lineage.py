"""Strict execution lineage primitives absorbed from agentic-RL execution patterns.

This module is AIOS-native. It records the immutable execution context that must
survive the full contract -> permit -> effect -> attempt -> trajectory -> receipt
-> evidence -> evaluation -> decision chain.

The fields are descriptive provenance, never authority. Missing or mismatched
context fails closed when strict validation is requested.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Mapping


_REQUIRED = (
    "policy_revision",
    "environment_revision",
    "capability_snapshot",
    "provider_revision",
    "attempt_id",
    "trajectory_id",
)


def _s(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError(f"{name} must be a non-empty mapping")
    return dict(value)


@dataclass(frozen=True)
class ExecutionLineage:
    policy_revision: str
    environment_revision: str
    capability_snapshot: Mapping[str, Any]
    provider_revision: str
    attempt_id: str
    trajectory_id: str
    raw_output_digest: str | None = None

    def __post_init__(self) -> None:
        for value, name in (
            (self.policy_revision, "policy_revision"),
            (self.environment_revision, "environment_revision"),
            (self.provider_revision, "provider_revision"),
            (self.attempt_id, "attempt_id"),
            (self.trajectory_id, "trajectory_id"),
        ):
            _s(value, name)
        object.__setattr__(
            self, "capability_snapshot",
            _mapping(self.capability_snapshot, "capability_snapshot"),
        )
        if self.raw_output_digest is not None:
            _s(self.raw_output_digest, "raw_output_digest")

    @property
    def digest(self) -> str:
        payload = self.as_record(include_digest=False)
        return sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()

    def as_record(self, *, include_digest: bool = True) -> dict[str, Any]:
        record = {
            "policy_revision": self.policy_revision,
            "environment_revision": self.environment_revision,
            "capability_snapshot": dict(self.capability_snapshot),
            "provider_revision": self.provider_revision,
            "attempt_id": self.attempt_id,
            "trajectory_id": self.trajectory_id,
            "raw_output_digest": self.raw_output_digest,
        }
        if include_digest:
            record["lineage_digest"] = self.digest
        return record


def validate_lineage(record: Mapping[str, Any]) -> ExecutionLineage:
    if not isinstance(record, Mapping):
        raise ValueError("execution lineage must be a mapping")
    if any(key not in record for key in _REQUIRED):
        raise ValueError("execution lineage is incomplete")
    obj = ExecutionLineage(
        policy_revision=record["policy_revision"],
        environment_revision=record["environment_revision"],
        capability_snapshot=record["capability_snapshot"],
        provider_revision=record["provider_revision"],
        attempt_id=record["attempt_id"],
        trajectory_id=record["trajectory_id"],
        raw_output_digest=record.get("raw_output_digest"),
    )
    if record.get("lineage_digest") != obj.digest:
        raise ValueError("execution lineage digest mismatch")
    return obj


def require_lineage_fields(record: Mapping[str, Any]) -> None:
    validate_lineage(record)


__all__ = ["ExecutionLineage", "validate_lineage", "require_lineage_fields"]


def bind_lineage_to_effect(record: Mapping[str, Any], contract: Mapping[str, Any],
                           contract_id: str, permit_id: str, provider: str) -> dict[str, Any]:
    """Bind substrate-supplied lineage to the exact authorized effect context.

    Policy revision and capability snapshot are checked against the immutable
    AIOS contract; provider revision must match the version authorized for the
    selected provider. Environment and trajectory identifiers remain sourced
    from the execution substrate and are never fabricated by AIOS.
    """
    obj = validate_lineage(record)
    capabilities = contract.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        raise ValueError("authorized contract capabilities are missing")
    expected_snapshot = {
        "capabilities": capabilities,
        "policy_digest": contract.get("policy_digest"),
    }
    if obj.policy_revision != contract.get("policy_digest"):
        raise ValueError("lineage policy_revision differs from authorized contract policy_digest")
    if dict(obj.capability_snapshot) != expected_snapshot:
        raise ValueError("lineage capability_snapshot differs from authorized contract")
    provider_refs = [ref for ref in capabilities if isinstance(ref, str)
                     and ref.split("@", 1)[0] == provider]
    if not provider_refs or not any(ref.split("@", 1)[1] == obj.provider_revision
                                     for ref in provider_refs if "@" in ref):
        raise ValueError("lineage provider_revision is not authorized for selected provider")
    binding = {
        "contract_id": contract_id,
        "permit_id": permit_id,
        "lineage": obj.as_record(),
    }
    digest_payload = json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    binding["binding_digest"] = sha256(digest_payload.encode("utf-8")).hexdigest()
    return binding


def verify_effect_lineage(binding: Mapping[str, Any], contract: Mapping[str, Any],
                          contract_id: str, permit_id: str, provider: str, attempt_id: str) -> dict[str, Any]:
    if not isinstance(binding, Mapping) or set(binding) != {"contract_id", "permit_id", "lineage", "binding_digest"}:
        raise ValueError("effect lineage binding schema mismatch")
    body = {key: binding[key] for key in ("contract_id", "permit_id", "lineage")}
    digest = sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    if binding.get("binding_digest") != digest:
        raise ValueError("effect lineage binding digest mismatch")
    if binding["contract_id"] != contract_id or binding["permit_id"] != permit_id:
        raise ValueError("effect lineage contract/permit binding mismatch")
    obj = validate_lineage(binding["lineage"])
    if obj.attempt_id != attempt_id:
        raise ValueError("effect lineage attempt_id mismatch")
    # Re-run contract and provider authorization checks, not just digest checks.
    rebuilt = bind_lineage_to_effect(binding["lineage"], contract, contract_id, permit_id, provider)
    if rebuilt != dict(binding):
        raise ValueError("effect lineage does not match authoritative execution context")
    return obj.as_record()


__all__ = ["ExecutionLineage", "validate_lineage", "require_lineage_fields",
           "bind_lineage_to_effect", "verify_effect_lineage"]
