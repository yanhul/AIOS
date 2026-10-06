"""Durable model-facing CONTINUE CONTRACT.

The contract is a persisted projection of authoritative durable state. It is
not conversation memory and it never grants authority: it only constrains the
next model-visible choices to actions already authorized by the control plane.
"""
from __future__ import annotations

import hashlib
from typing import Any, Mapping

from .mutation import canonical_json

CONTRACT_TYPE = "CONTINUE_CONTRACT"
CONTRACT_VERSION = 1

_REQUIRED = {
    "contract_type",
    "contract_version",
    "authority",
    "project",
    "design",
    "pipeline",
    "active_phase",
    "active_commit",
    "latest_run",
    "latest_receipt",
    "active_blockers",
    "next_legal_actions",
    "forbidden_actions",
    "state_digest",
}

def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()

def _nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value

def _string_list(value: Any, field: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(x, str) and x.strip() for x in value):
        raise ValueError(f"{field} must be a list of non-empty strings")
    if not allow_empty and not value:
        raise ValueError(f"{field} must not be empty")
    return list(value)

def build_continue_contract(state: Mapping[str, Any]) -> dict[str, Any]:
    """Project durable state into a deterministic model-facing continuation contract.

    The caller must persist the returned object alongside the durable state.
    No pipeline phase, blocker, legal action, or permission is inferred here.
    """
    if not isinstance(state, Mapping):
        raise ValueError("state must be a mapping")
    project = _nonempty_string(state.get("project"), "project")
    design = _nonempty_string(state.get("design"), "design")
    active_phase = _nonempty_string(state.get("active_phase"), "active_phase")
    active_commit = _nonempty_string(state.get("active_commit"), "active_commit")
    latest_run = _nonempty_string(state.get("latest_run"), "latest_run")
    latest_receipt = _nonempty_string(state.get("latest_receipt"), "latest_receipt")
    authority = state.get("authority", "AIOS_CONTROL_PLANE")
    if authority != "AIOS_CONTROL_PLANE":
        raise ValueError("continue contract authority must be AIOS_CONTROL_PLANE")
    pipeline = state.get("pipeline")
    if not isinstance(pipeline, Mapping) or not pipeline:
        raise ValueError("pipeline must be a non-empty mapping")
    active_blockers = state.get("active_blockers", [])
    if not isinstance(active_blockers, list):
        raise ValueError("active_blockers must be a list")
    next_legal = _string_list(state.get("next_legal_actions"), "next_legal_actions")
    forbidden = _string_list(state.get("forbidden_actions"), "forbidden_actions")
    overlap = sorted(set(next_legal) & set(forbidden))
    if overlap:
        raise ValueError(f"action cannot be both legal and forbidden: {overlap}")

    projection = {
        "contract_type": CONTRACT_TYPE,
        "contract_version": CONTRACT_VERSION,
        "authority": authority,
        "project": project,
        "design": design,
        "pipeline": dict(pipeline),
        "active_phase": active_phase,
        "active_commit": active_commit,
        "latest_run": latest_run,
        "latest_receipt": latest_receipt,
        "active_blockers": [dict(x) if isinstance(x, Mapping) else x for x in active_blockers],
        "next_legal_actions": next_legal,
        "forbidden_actions": forbidden,
        "state_digest": _digest(dict(state)),
    }
    projection["contract_id"] = "CC-" + _digest(projection)
    return projection

def validate_continue_contract(contract: Mapping[str, Any]) -> bool:
    """Fail closed unless a continuation contract is complete and self-bound."""
    if not isinstance(contract, Mapping):
        raise ValueError("continue contract must be a mapping")
    missing = _REQUIRED - set(contract)
    if missing:
        raise ValueError(f"continue contract missing fields: {sorted(missing)}")
    if contract["contract_type"] != CONTRACT_TYPE:
        raise ValueError("contract_type mismatch")
    if contract["contract_version"] != CONTRACT_VERSION:
        raise ValueError("unsupported contract_version")
    if contract["authority"] != "AIOS_CONTROL_PLANE":
        raise ValueError("unauthorized continue contract authority")
    _nonempty_string(contract["project"], "project")
    _nonempty_string(contract["design"], "design")
    _nonempty_string(contract["active_phase"], "active_phase")
    _nonempty_string(contract["active_commit"], "active_commit")
    _nonempty_string(contract["latest_run"], "latest_run")
    _nonempty_string(contract["latest_receipt"], "latest_receipt")
    if not isinstance(contract["pipeline"], Mapping) or not contract["pipeline"]:
        raise ValueError("pipeline must be a non-empty mapping")
    if not isinstance(contract["active_blockers"], list):
        raise ValueError("active_blockers must be a list")
    legal = _string_list(contract["next_legal_actions"], "next_legal_actions")
    forbidden = _string_list(contract["forbidden_actions"], "forbidden_actions")
    if set(legal) & set(forbidden):
        raise ValueError("legal and forbidden actions overlap")
    _nonempty_string(contract["state_digest"], "state_digest")
    contract_id = contract.get("contract_id")
    _nonempty_string(contract_id, "contract_id")
    expected = dict(contract)
    del expected["contract_id"]
    if contract_id != "CC-" + _digest(expected):
        raise ValueError("continue contract identity mismatch")
    return True

def validate_continue_action(contract: Mapping[str, Any], action: str) -> bool:
    """Reject any model continuation not explicitly authorized by the contract."""
    validate_continue_contract(contract)
    _nonempty_string(action, "action")
    if action in set(contract["forbidden_actions"]):
        raise PermissionError(f"forbidden continuation action: {action}")
    if action not in set(contract["next_legal_actions"]):
        raise PermissionError(f"continuation action is not legal: {action}")
    return True

__all__ = [
    "CONTRACT_TYPE",
    "CONTRACT_VERSION",
    "build_continue_contract",
    "validate_continue_contract",
    "validate_continue_action",
]
