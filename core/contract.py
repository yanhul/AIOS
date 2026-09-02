"""AIOS execution-contract boundary (M6 Contract Closure).

This module defines the immutable contract that must exist BEFORE an agent or
runtime is allowed to execute a consequential task.  It deliberately does not
execute tools, call models, or decide policy.

Authority model:
    governing policy/criteria -> contract -> permit -> runtime adapter

The caller supplies the policy digest and governing limits.  AIOS records and
verifies their binding but never lets an agent rewrite them.  A permit is an
integrity/binding object, not a cryptographic signature; authentication of the
issuer remains an adapter/deployment concern.

Stdlib only. No filesystem writes and no network calls.
"""

import hashlib

from .mutation import canonical_json

CONTRACT_TYPE = "EXECUTION_CONTRACT"
PERMIT_TYPE = "EXECUTION_PERMIT"

# These are intentionally fixed here: an agent may choose values only inside
# a contract issued by the governing authority.  The contract itself cannot
# redefine the governing schema.
_REQUIRED_CONTRACT_FIELDS = {
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
}


def _sha256(obj):
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def validate_contract(contract):
    """Validate an execution contract without mutating it."""
    if not isinstance(contract, dict):
        raise ValueError("contract must be a dict")
    missing = _REQUIRED_CONTRACT_FIELDS - set(contract)
    if missing:
        raise ValueError(f"contract missing fields: {sorted(missing)}")
    if set(contract) - _REQUIRED_CONTRACT_FIELDS:
        raise ValueError(
            f"contract contains unsupported fields: "
            f"{sorted(set(contract) - _REQUIRED_CONTRACT_FIELDS)}")
    if contract["contract_type"] != CONTRACT_TYPE:
        raise ValueError("contract_type mismatch")
    for field in ("task_id", "scope", "actor", "input_digest", "policy_digest"):
        if not isinstance(contract[field], str) or not contract[field].strip():
            raise ValueError(f"{field} must be a non-empty string")
    for field in ("capabilities", "allowed_effects", "evidence_required", "terminal_states"):
        if not isinstance(contract[field], list) or not all(
                isinstance(v, str) and v.strip() for v in contract[field]):
            raise ValueError(f"{field} must be a list of non-empty strings")
    if isinstance(contract["max_attempts"], bool) or not isinstance(
            contract["max_attempts"], int) or contract["max_attempts"] < 1:
        raise ValueError("max_attempts must be a positive integer")
    return contract


def contract_identity(contract):
    """Return deterministic identity for an already validated contract."""
    validate_contract(contract)
    return "CT-" + _sha256(contract)


def issue_permit(contract, issuer):
    """Create a permit bound exactly to one immutable contract.

    The issuer is an external authority identity.  This function does not
    consult or modify policy and therefore cannot escalate capabilities.
    """
    if not isinstance(issuer, str) or not issuer.strip():
        raise ValueError("issuer must be a non-empty string")
    validate_contract(contract)
    cid = contract_identity(contract)
    permit = {
        "permit_type": PERMIT_TYPE,
        "contract_id": cid,
        "task_id": contract["task_id"],
        "actor": contract["actor"],
        "capabilities": list(contract["capabilities"]),
        "allowed_effects": list(contract["allowed_effects"]),
        "max_attempts": contract["max_attempts"],
        "policy_digest": contract["policy_digest"],
        "issuer": issuer,
    }
    permit["permit_id"] = "PT-" + _sha256(permit)
    return permit


def verify_permit(contract, permit):
    """Fail closed unless permit and contract are exactly bound."""
    validate_contract(contract)
    if not isinstance(permit, dict):
        raise ValueError("permit must be a dict")
    required = {
        "permit_type", "permit_id", "contract_id", "task_id", "actor",
        "capabilities", "allowed_effects", "max_attempts", "policy_digest",
        "issuer",
    }
    if set(permit) != required:
        raise ValueError("permit schema mismatch")
    if permit["permit_type"] != PERMIT_TYPE:
        raise ValueError("permit_type mismatch")
    if permit["contract_id"] != contract_identity(contract):
        raise ValueError("permit is not bound to this contract")
    expected = dict(permit)
    del expected["permit_id"]
    if permit["permit_id"] != "PT-" + _sha256(expected):
        raise ValueError("permit identity mismatch")
    for field in ("task_id", "actor", "capabilities", "allowed_effects",
                  "max_attempts", "policy_digest"):
        if permit[field] != contract[field]:
            raise ValueError(f"permit/{field} differs from contract")
    return True


__all__ = [
    "CONTRACT_TYPE",
    "PERMIT_TYPE",
    "validate_contract",
    "contract_identity",
    "issue_permit",
    "verify_permit",
]
