"""Durable authority records for M6 contract/permit enforcement.

Contracts and permits are consequential AIOS state. They therefore use the
same atomic commit/recovery kernel as ordinary AIOS mutations. This module
never creates or changes governing policy; it only persists already-issued
contract/permit values and verifies their binding.
"""

import os
import json

from .contract import contract_identity, issue_permit, validate_contract, verify_permit
from .mutation import TransitionError, canonical_json, commit_batch, recover_pending

AUTHORITY_DIR = "authority"
CONTRACTS_DIR = "contracts"
PERMITS_DIR = "permits"


def _require_id(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _path(aios_dir, kind, ident):
    return os.path.join(aios_dir, AUTHORITY_DIR, kind, ident + ".json")


def _load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def persist_contract(aios_dir, contract):
    """Atomically persist an immutable contract; replay is allowed."""
    validate_contract(contract)
    cid = contract_identity(contract)
    record = dict(contract)
    record["record_type"] = "EXECUTION_CONTRACT"
    record["contract_id"] = cid
    recover_pending(aios_dir)
    path = _path(aios_dir, CONTRACTS_DIR, cid)
    if os.path.exists(path):
        existing = _load(path)
        if canonical_json(existing) != canonical_json(record):
            raise TransitionError("existing contract identity has different content")
        return existing
    commit_batch(aios_dir, [(os.path.join(AUTHORITY_DIR, CONTRACTS_DIR, cid + ".json"), record)])
    return record


def persist_permit(aios_dir, contract, issuer):
    """Issue and atomically persist a permit bound to the canonical contract."""
    validate_contract(contract)
    stored = persist_contract(aios_dir, contract)
    canonical_contract = {k: stored[k] for k in (
        "contract_type", "task_id", "scope", "actor", "capabilities",
        "input_digest", "allowed_effects", "evidence_required", "max_attempts",
        "terminal_states", "policy_digest")}
    permit = issue_permit(canonical_contract, issuer)
    recover_pending(aios_dir)
    path = _path(aios_dir, PERMITS_DIR, permit["permit_id"])
    if os.path.exists(path):
        existing = _load(path)
        if canonical_json(existing) != canonical_json(permit):
            raise TransitionError("existing permit identity has different content")
        verify_permit(canonical_contract, existing)
        return existing
    commit_batch(aios_dir, [(os.path.join(AUTHORITY_DIR, PERMITS_DIR, permit["permit_id"] + ".json"), permit)])
    return permit


def load_contract(aios_dir, contract_id):
    _require_id(contract_id, "contract_id")
    path = _path(aios_dir, CONTRACTS_DIR, contract_id)
    if not os.path.exists(path):
        raise KeyError(f"unknown contract: {contract_id}")
    record = _load(path)
    contract = {k: record[k] for k in (
        "contract_type", "task_id", "scope", "actor", "capabilities",
        "input_digest", "allowed_effects", "evidence_required", "max_attempts",
        "terminal_states", "policy_digest")}
    if contract_identity(contract) != contract_id:
        raise TransitionError("stored contract identity mismatch")
    validate_contract(contract)
    return contract


def load_permit(aios_dir, permit_id):
    _require_id(permit_id, "permit_id")
    path = _path(aios_dir, PERMITS_DIR, permit_id)
    if not os.path.exists(path):
        raise KeyError(f"unknown permit: {permit_id}")
    return _load(path)


def authorize(aios_dir, contract_id, permit_id):
    """Fail closed unless the durable permit remains exactly bound to contract."""
    contract = load_contract(aios_dir, contract_id)
    permit = load_permit(aios_dir, permit_id)
    verify_permit(contract, permit)
    return True


__all__ = [
    "persist_contract", "persist_permit", "load_contract", "load_permit", "authorize"
]
