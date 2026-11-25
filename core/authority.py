"""Durable authority records for AIOS contract/permit enforcement.

Permit hashes bind fields but do not authenticate the issuer. Every production
authorization therefore requires an Ed25519 attestation issued by the authority
signer (private key) and verified here with public keys only.
"""
import os
import json
from .contract import contract_identity, issue_permit, validate_contract, verify_permit
from .attestation import (ALGORITHM, LEGACY_ALGORITHM, SIGNING_KEY_FILE_ENV, AttestationError, AuthoritySigner,
                          AuthorityVerifier, issue_attestation, signing_material_present)
from .capabilities import CapabilityError, CapabilityRegistry
from .policy_registry import resolve_policy
from .mutation import TransitionError, canonical_json
from .authority_store import commit_authority_batch as commit_batch, recover_authority_store as recover_pending

AUTHORITY_DIR = "authority"
CONTRACTS_DIR = "contracts"
PERMITS_DIR = "permits"
ATTESTATIONS_DIR = "attestations"
AUTHORITY_ATTESTATION_SECRET_ENV = "AIOS_AUTHORITY_ATTESTATION_SECRET"  # legacy; never read
_process_signer = None


def register_process_signer(signer):
    """Install the signer for this *authority-signer* process (or a test harness).

    Execution runtimes never call this: they hold no private key to construct
    an AuthoritySigner from.
    """
    global _process_signer
    if signer is not None and not isinstance(signer, AuthoritySigner):
        raise TypeError("process signer must be an AuthoritySigner")
    _process_signer = signer
_CONTRACT_FIELDS = ("contract_type", "task_id", "scope", "actor", "capabilities", "input_digest",
                    "allowed_effects", "evidence_required", "max_attempts", "terminal_states", "policy_digest")
# Optional fields validated by core.contract and bound into contract/permit identity.
_OPTIONAL_CONTRACT_FIELDS = ("acceptance_predicates",)
_ALL_CONTRACT_FIELDS = _CONTRACT_FIELDS + _OPTIONAL_CONTRACT_FIELDS


def _require_id(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _path(aios_dir, kind, ident):
    return os.path.join(aios_dir, AUTHORITY_DIR, kind, ident + ".json")


def _load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _canonical_contract(contract):
    if not isinstance(contract, dict):
        raise ValueError("contract must be a dict")
    extra = set(contract) - set(_ALL_CONTRACT_FIELDS)
    allowed_record_metadata = {"record_type", "contract_id"}
    if extra - allowed_record_metadata:
        raise ValueError(f"contract contains unsupported fields: {sorted(extra - allowed_record_metadata)}")
    canonical = {k: contract[k] for k in _ALL_CONTRACT_FIELDS if k in contract}
    validate_contract(canonical)
    if "contract_id" in contract and contract["contract_id"] != contract_identity(canonical):
        raise TransitionError("stored contract identity mismatch")
    return canonical


def _resolve_capabilities(aios_dir, contract):
    try:
        CapabilityRegistry.load(aios_dir).resolve_contract(contract)
    except CapabilityError as exc:
        raise TransitionError(f"capability authority rejected contract: {exc}") from exc


def _resolve_policy(aios_dir, contract):
    try:
        resolve_policy(aios_dir, contract["policy_digest"])
    except ValueError as exc:
        raise TransitionError(f"policy authority rejected contract: {exc}") from exc


def persist_contract(aios_dir, contract):
    canonical = _canonical_contract(contract)
    _resolve_capabilities(aios_dir, canonical)
    _resolve_policy(aios_dir, canonical)
    cid = contract_identity(canonical)
    record = dict(canonical)
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


def persist_permit(aios_dir, contract, issuer, signer=None):
    canonical = _canonical_contract(contract)
    stored = persist_contract(aios_dir, canonical)
    canonical = _canonical_contract(stored)
    permit = issue_permit(canonical, issuer)
    recover_pending(aios_dir)
    path = _path(aios_dir, PERMITS_DIR, permit["permit_id"])
    if os.path.exists(path):
        existing = _load(path)
        if canonical_json(existing) != canonical_json(permit):
            raise TransitionError("existing permit identity has different content")
        verify_permit(canonical, existing)
        permit = existing
    else:
        commit_batch(aios_dir, [(os.path.join(AUTHORITY_DIR, PERMITS_DIR, permit["permit_id"] + ".json"), permit)])
    # Attestation is created only by the authority signer. Without one the
    # permit is recorded unattested and authorize() fails closed.
    signer = signer if signer is not None else _process_signer
    if signer is not None:
        persist_attestation(aios_dir, canonical, permit, signer)
    return permit


def persist_attestation(aios_dir, contract, permit, signer, *, reissue=False):
    """Atomically persist an Ed25519 attestation issued by the authority signer.

    An existing legacy HMAC attestation is replaced (explicit migration by the
    signer); an existing Ed25519 attestation is replaced only with an explicit
    ``reissue=True`` (key rotation/revocation), never silently.
    """
    if not isinstance(signer, AuthoritySigner):
        raise TransitionError("attestations can only be issued by an AuthoritySigner")
    canonical = _canonical_contract(contract)
    verify_permit(canonical, permit)
    _resolve_capabilities(aios_dir, canonical)
    _resolve_policy(aios_dir, canonical)
    attestation = issue_attestation(canonical, permit, signer)
    recover_pending(aios_dir)
    path = _path(aios_dir, ATTESTATIONS_DIR, permit["permit_id"])
    if os.path.exists(path):
        existing = _load(path)
        if existing.get("algorithm") == ALGORITHM and not reissue:
            if canonical_json(existing) != canonical_json(attestation):
                raise TransitionError("existing Ed25519 attestation has different content; revoke and re-issue explicitly")
            return existing
        if existing.get("algorithm") not in (ALGORITHM, LEGACY_ALGORITHM):
            raise TransitionError("existing attestation has an unknown algorithm")
    commit_batch(aios_dir, [(os.path.join(AUTHORITY_DIR, ATTESTATIONS_DIR, permit["permit_id"] + ".json"), attestation)])
    return attestation


def load_contract(aios_dir, contract_id):
    _require_id(contract_id, "contract_id")
    record = _load(_path(aios_dir, CONTRACTS_DIR, contract_id))
    contract = {k: record[k] for k in _CONTRACT_FIELDS}
    contract.update({k: record[k] for k in _OPTIONAL_CONTRACT_FIELDS if k in record})
    if contract_identity(contract) != contract_id:
        raise TransitionError("stored contract identity mismatch")
    validate_contract(contract)
    _resolve_policy(aios_dir, contract)
    return contract


def load_permit(aios_dir, permit_id):
    _require_id(permit_id, "permit_id")
    return _load(_path(aios_dir, PERMITS_DIR, permit_id))


def load_attestation(aios_dir, permit_id):
    _require_id(permit_id, "permit_id")
    return _load(_path(aios_dir, ATTESTATIONS_DIR, permit_id))


def authorize(aios_dir, contract_id, permit_id, verifier=None):
    # Separation of duties: a verifying (execution) process must not be
    # configured with authority signing material.
    if signing_material_present():
        raise TransitionError(f"{SIGNING_KEY_FILE_ENV} must not be configured in a verifying process")
    try:
        verifier = verifier if verifier is not None else AuthorityVerifier.from_env()
    except AttestationError as exc:
        raise TransitionError(f"authority verifier unavailable: {exc}") from exc
    contract = load_contract(aios_dir, contract_id)
    _resolve_capabilities(aios_dir, contract)
    _resolve_policy(aios_dir, contract)
    permit = load_permit(aios_dir, permit_id)
    verify_permit(contract, permit)
    try:
        attestation = load_attestation(aios_dir, permit_id)
    except FileNotFoundError as exc:
        raise TransitionError("permit issuer attestation is missing") from exc
    try:
        verifier.verify(contract, permit, attestation)
    except ValueError as exc:
        raise TransitionError(f"permit issuer attestation rejected: {exc}") from exc
    return True


__all__ = ["AUTHORITY_ATTESTATION_SECRET_ENV", "register_process_signer", "persist_contract", "persist_permit",
           "persist_attestation", "load_contract", "load_permit", "load_attestation", "authorize"]
