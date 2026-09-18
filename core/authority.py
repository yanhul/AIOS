"""Durable authority records for AIOS contract/permit enforcement."""
import os,json
from .contract import contract_identity,issue_permit,validate_contract,verify_permit
from .attestation import issue_attestation
from .capabilities import CapabilityError,CapabilityRegistry
from .policy_registry import resolve_policy
from .mutation import TransitionError,canonical_json,commit_batch,recover_pending
AUTHORITY_DIR="authority"; CONTRACTS_DIR="contracts"; PERMITS_DIR="permits"; ATTESTATIONS_DIR="attestations"
_CONTRACT_FIELDS=("contract_type","task_id","scope","actor","capabilities","input_digest","allowed_effects","evidence_required","max_attempts","terminal_states","policy_digest")
def _require_id(value,name):
 if not isinstance(value,str) or not value.strip(): raise ValueError(f"{name} must be a non-empty string")
def _path(aios_dir,kind,ident): return os.path.join(aios_dir,AUTHORITY_DIR,kind,ident+".json")
def _load(path):
 with open(path,"r",encoding="utf-8") as fh:return json.load(fh)
def _canonical_contract(contract):
 if not isinstance(contract,dict): raise ValueError("contract must be a dict")
 extra=set(contract)-set(_CONTRACT_FIELDS); allowed_record_metadata={"record_type","contract_id"}
 if extra-allowed_record_metadata: raise ValueError(f"contract contains unsupported fields: {sorted(extra-allowed_record_metadata)}")
 canonical={k:contract[k] for k in _CONTRACT_FIELDS if k in contract}
 validate_contract(canonical)
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
def persist_permit(aios_dir,contract,issuer):
 canonical=_canonical_contract(contract); stored=persist_contract(aios_dir,canonical); canonical=_canonical_contract(stored); permit=issue_permit(canonical,issuer); recover_pending(aios_dir); path=_path(aios_dir,PERMITS_DIR,permit["permit_id"])
 if os.path.exists(path):
  existing=_load(path)
  if canonical_json(existing)!=canonical_json(permit): raise TransitionError("existing permit identity has different content")
  verify_permit(canonical,existing); return existing
 commit_batch(aios_dir,[(os.path.join(AUTHORITY_DIR,PERMITS_DIR,permit["permit_id"]+".json"),permit)]); return permit
def persist_attestation(aios_dir,contract,permit,secret):
 """Atomically persist an authenticity attestation for an issued permit."""
 canonical=_canonical_contract(contract); verify_permit(canonical,permit); _resolve_capabilities(aios_dir,canonical); _resolve_policy(aios_dir,canonical); attestation=issue_attestation(canonical,permit,secret); recover_pending(aios_dir); path=_path(aios_dir,ATTESTATIONS_DIR,permit["permit_id"])
 if os.path.exists(path):
  existing=_load(path)
  if canonical_json(existing)!=canonical_json(attestation): raise TransitionError("existing attestation identity has different content")
  return existing
 commit_batch(aios_dir,[(os.path.join(AUTHORITY_DIR,ATTESTATIONS_DIR,permit["permit_id"]+".json"),attestation)]); return attestation
def load_contract(aios_dir,contract_id):
 _require_id(contract_id,"contract_id")
 try:
  record=_load(_path(aios_dir,CONTRACTS_DIR,contract_id))
 except FileNotFoundError as exc:
  raise TransitionError("authorized contract does not exist") from exc
 contract={k:record[k] for k in _CONTRACT_FIELDS}
 if contract_identity(contract)!=contract_id: raise TransitionError("stored contract identity mismatch")
 validate_contract(contract); _resolve_policy(aios_dir,contract); return contract
def load_permit(aios_dir,permit_id):
 _require_id(permit_id,"permit_id")
 try:
  return _load(_path(aios_dir,PERMITS_DIR,permit_id))
 except FileNotFoundError as exc:
  raise TransitionError("authorized permit does not exist") from exc
def load_attestation(aios_dir,permit_id):
 _require_id(permit_id,"permit_id"); return _load(_path(aios_dir,ATTESTATIONS_DIR,permit_id))
def authorize(aios_dir,contract_id,permit_id):
 contract=load_contract(aios_dir,contract_id); _resolve_capabilities(aios_dir,contract); _resolve_policy(aios_dir,contract); permit=load_permit(aios_dir,permit_id); verify_permit(contract,permit); return True
__all__=["persist_contract","persist_permit","persist_attestation","load_contract","load_permit","load_attestation","authorize"]
