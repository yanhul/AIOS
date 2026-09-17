"""Durable authority records for AIOS contract/permit enforcement."""
import datetime
import os
import json
from .contract import contract_identity, issue_permit, validate_contract, verify_permit
from .attestation import issue_attestation
from .capabilities import CapabilityError, CapabilityRegistry
from .policy_registry import resolve_policy
from .mutation import TransitionError, canonical_json, commit_batch, recover_pending

AUTHORITY_DIR="authority"; CONTRACTS_DIR="contracts"; PERMITS_DIR="permits"; ATTESTATIONS_DIR="attestations"; LIFECYCLE_DIR="permit_lifecycle"
_CONTRACT_FIELDS=("contract_type","task_id","scope","actor","capabilities","input_digest","allowed_effects","evidence_required","max_attempts","terminal_states","policy_digest")
_PERMIT_FIELDS=("permit_type","permit_id","contract_id","task_id","actor","capabilities","allowed_effects","max_attempts","policy_digest","issuer")
_LIFECYCLE_FIELDS=("permit_id","status","lifecycle_sequence","updated_at","updated_by","reason_code")

def _require_id(value,name):
    if not isinstance(value,str) or not value.strip(): raise ValueError(f"{name} must be a non-empty string")

def _path(aios_dir,kind,ident): return os.path.join(aios_dir,AUTHORITY_DIR,kind,ident+".json")
def _load(path):
    with open(path,"r",encoding="utf-8") as fh:return json.load(fh)
def _utc_iso(): return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _canonical_contract(contract):
    if not isinstance(contract,dict): raise ValueError("contract must be a dict")
    extra=set(contract)-set(_CONTRACT_FIELDS); allowed_record_metadata={"record_type","contract_id"}
    if extra-allowed_record_metadata: raise ValueError(f"contract contains unsupported fields: {sorted(extra-allowed_record_metadata)}")
    canonical={k:contract[k] for k in _CONTRACT_FIELDS if k in contract}; validate_contract(canonical)
    if "contract_id" in contract and contract["contract_id"]!=contract_identity(canonical): raise TransitionError("stored contract identity mismatch")
    return canonical

def _resolve_capabilities(aios_dir,contract):
    try: CapabilityRegistry.load(aios_dir).resolve_contract(contract)
    except CapabilityError as exc: raise TransitionError(f"capability authority rejected contract: {exc}") from exc

def _resolve_policy(aios_dir,contract):
    try: resolve_policy(aios_dir,contract["policy_digest"])
    except ValueError as exc: raise TransitionError(f"policy authority rejected contract: {exc}") from exc

def persist_contract(aios_dir,contract):
    canonical=_canonical_contract(contract); _resolve_capabilities(aios_dir,canonical); _resolve_policy(aios_dir,canonical); cid=contract_identity(canonical); record=dict(canonical); record["record_type"]="EXECUTION_CONTRACT"; record["contract_id"]=cid; recover_pending(aios_dir); path=_path(aios_dir,CONTRACTS_DIR,cid)
    if os.path.exists(path):
        existing=_load(path)
        if canonical_json(existing)!=canonical_json(record): raise TransitionError("existing contract identity has different content")
        return existing
    commit_batch(aios_dir,[(os.path.join(AUTHORITY_DIR,CONTRACTS_DIR,cid+".json"),record)]); return record

def _new_lifecycle(permit_id,updated_by="AIOS_AUTHORITY"):
    _require_id(permit_id,"permit_id"); _require_id(updated_by,"updated_by")
    return {"permit_id":permit_id,"status":"ACTIVE","lifecycle_sequence":1,"updated_at":_utc_iso(),"updated_by":updated_by,"reason_code":"ISSUED"}

def _lifecycle_path(aios_dir,permit_id): return _path(aios_dir,LIFECYCLE_DIR,permit_id)

def persist_permit(aios_dir,contract,issuer):
    canonical=_canonical_contract(contract); stored=persist_contract(aios_dir,canonical); canonical=_canonical_contract(stored); permit=issue_permit(canonical,issuer); recover_pending(aios_dir); path=_path(aios_dir,PERMITS_DIR,permit["permit_id"]); lifecycle=_new_lifecycle(permit["permit_id"],issuer)
    if os.path.exists(path):
        existing=_load(path)
        if canonical_json(existing)!=canonical_json(permit): raise TransitionError("existing permit identity has different content")
        verify_permit(canonical,existing); existing_lifecycle=load_permit_lifecycle(aios_dir,permit["permit_id"])
        if existing_lifecycle["status"]!="ACTIVE": raise TransitionError("existing permit is not ACTIVE")
        return existing
    commit_batch(aios_dir,[(os.path.join(AUTHORITY_DIR,PERMITS_DIR,permit["permit_id"]+".json"),permit),(os.path.join(AUTHORITY_DIR,LIFECYCLE_DIR,permit["permit_id"]+".json"),lifecycle)]); return permit

def persist_attestation(aios_dir,contract,permit,secret):
    canonical=_canonical_contract(contract); verify_permit(canonical,permit); _resolve_capabilities(aios_dir,canonical); _resolve_policy(aios_dir,canonical); attestation=issue_attestation(canonical,permit,secret); recover_pending(aios_dir); path=_path(aios_dir,ATTESTATIONS_DIR,permit["permit_id"])
    if os.path.exists(path):
        existing=_load(path)
        if canonical_json(existing)!=canonical_json(attestation): raise TransitionError("existing attestation identity has different content")
        return existing
    commit_batch(aios_dir,[(os.path.join(AUTHORITY_DIR,ATTESTATIONS_DIR,permit["permit_id"]+".json"),attestation)]); return attestation

def load_contract(aios_dir,contract_id):
    _require_id(contract_id,"contract_id")
    try: record=_load(_path(aios_dir,CONTRACTS_DIR,contract_id))
    except (OSError,ValueError,TypeError) as exc: raise TransitionError(f"authority contract record unavailable: {contract_id}") from exc
    try: contract={k:record[k] for k in _CONTRACT_FIELDS}
    except (KeyError,TypeError) as exc: raise TransitionError(f"authority contract record malformed: {contract_id}") from exc
    if contract_identity(contract)!=contract_id: raise TransitionError("stored contract identity mismatch")
    validate_contract(contract); _resolve_policy(aios_dir,contract); return contract

def load_permit(aios_dir,permit_id):
    _require_id(permit_id,"permit_id")
    try: permit=_load(_path(aios_dir,PERMITS_DIR,permit_id))
    except (OSError,ValueError,TypeError) as exc: raise TransitionError(f"authority permit record unavailable: {permit_id}") from exc
    if not isinstance(permit,dict) or set(permit)!=set(_PERMIT_FIELDS): raise TransitionError(f"authority permit record malformed: {permit_id}")
    if permit.get("permit_id")!=permit_id: raise TransitionError(f"stored permit identity mismatch: {permit_id}")
    for field in ("contract_id","task_id","actor","issuer","policy_digest"): _require_id(permit.get(field),f"permit.{field}")
    return permit

def load_permit_lifecycle(aios_dir,permit_id):
    _require_id(permit_id,"permit_id")
    try: record=_load(_lifecycle_path(aios_dir,permit_id))
    except (OSError,ValueError,TypeError) as exc: raise TransitionError(f"permit lifecycle record unavailable: {permit_id}") from exc
    if not isinstance(record,dict) or set(record)!=set(_LIFECYCLE_FIELDS): raise TransitionError(f"permit lifecycle record malformed: {permit_id}")
    if record.get("permit_id")!=permit_id: raise TransitionError("stored permit lifecycle identity mismatch")
    if record.get("status") not in ("ACTIVE","REVOKED"): raise TransitionError("unknown permit lifecycle status")
    seq=record.get("lifecycle_sequence")
    if isinstance(seq,bool) or not isinstance(seq,int) or seq<1: raise TransitionError("invalid permit lifecycle sequence")
    for field in ("updated_at","updated_by","reason_code"): _require_id(record.get(field),f"lifecycle.{field}")
    return record

def revoke_permit(aios_dir,permit_id,revoked_by,reason_code="REVOKED",expected_sequence=None):
    _require_id(permit_id,"permit_id"); _require_id(revoked_by,"revoked_by"); _require_id(reason_code,"reason_code")
    recover_pending(aios_dir); permit=load_permit(aios_dir,permit_id); lifecycle=load_permit_lifecycle(aios_dir,permit_id); verify_permit(load_contract(aios_dir,permit["contract_id"]),permit)
    if lifecycle["status"]=="REVOKED": raise TransitionError("permit lifecycle is REVOKED")
    if expected_sequence is not None and lifecycle["lifecycle_sequence"]!=expected_sequence: raise TransitionError("lifecycle sequence conflict")
    updated=dict(lifecycle); updated.update(status="REVOKED",lifecycle_sequence=lifecycle["lifecycle_sequence"]+1,updated_at=_utc_iso(),updated_by=revoked_by,reason_code=reason_code)
    commit_batch(aios_dir,[(os.path.join(AUTHORITY_DIR,LIFECYCLE_DIR,permit_id+".json"),updated)]); return updated

def authorize(aios_dir,contract_id,permit_id):
    contract=load_contract(aios_dir,contract_id); _resolve_capabilities(aios_dir,contract); _resolve_policy(aios_dir,contract); permit=load_permit(aios_dir,permit_id); verify_permit(contract,permit); lifecycle=load_permit_lifecycle(aios_dir,permit_id)
    if lifecycle["status"]!="ACTIVE": raise TransitionError(f"permit lifecycle is {lifecycle['status']}")
    return True

__all__=["persist_contract","persist_permit","persist_attestation","load_contract","load_permit","load_attestation","load_permit_lifecycle","revoke_permit","authorize"]

def load_attestation(aios_dir,permit_id):
    _require_id(permit_id,"permit_id"); return _load(_path(aios_dir,ATTESTATIONS_DIR,permit_id))
