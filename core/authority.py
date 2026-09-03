"""Durable authority records for AIOS contract/permit enforcement."""
import os,json
from .contract import contract_identity,issue_permit,validate_contract,verify_permit
from .attestation import issue_attestation
from .mutation import TransitionError,canonical_json,commit_batch,recover_pending
AUTHORITY_DIR="authority"; CONTRACTS_DIR="contracts"; PERMITS_DIR="permits"; ATTESTATIONS_DIR="attestations"
def _require_id(value,name):
 if not isinstance(value,str) or not value.strip(): raise ValueError(f"{name} must be a non-empty string")
def _path(aios_dir,kind,ident): return os.path.join(aios_dir,AUTHORITY_DIR,kind,ident+".json")
def _load(path):
 with open(path,"r",encoding="utf-8") as fh:return json.load(fh)
def persist_contract(aios_dir,contract):
 validate_contract(contract); cid=contract_identity(contract); record=dict(contract); record["record_type"]="EXECUTION_CONTRACT"; record["contract_id"]=cid; recover_pending(aios_dir); path=_path(aios_dir,CONTRACTS_DIR,cid)
 if os.path.exists(path):
  existing=_load(path)
  if canonical_json(existing)!=canonical_json(record): raise TransitionError("existing contract identity has different content")
  return existing
 commit_batch(aios_dir,[(os.path.join(AUTHORITY_DIR,CONTRACTS_DIR,cid+".json"),record)]); return record
def persist_permit(aios_dir,contract,issuer):
 validate_contract(contract); stored=persist_contract(aios_dir,contract); canonical_contract={k:stored[k] for k in ("contract_type","task_id","scope","actor","capabilities","input_digest","allowed_effects","evidence_required","max_attempts","terminal_states","policy_digest")}; permit=issue_permit(canonical_contract,issuer); recover_pending(aios_dir); path=_path(aios_dir,PERMITS_DIR,permit["permit_id"])
 if os.path.exists(path):
  existing=_load(path)
  if canonical_json(existing)!=canonical_json(permit): raise TransitionError("existing permit identity has different content")
  verify_permit(canonical_contract,existing); return existing
 commit_batch(aios_dir,[(os.path.join(AUTHORITY_DIR,PERMITS_DIR,permit["permit_id"]+".json"),permit)]); return permit
def persist_attestation(aios_dir,contract,permit,secret):
 """Atomically persist an authenticity attestation for an issued permit."""
 validate_contract(contract); verify_permit(contract,permit); attestation=issue_attestation(contract,permit,secret); recover_pending(aios_dir); path=_path(aios_dir,ATTESTATIONS_DIR,permit["permit_id"])
 if os.path.exists(path):
  existing=_load(path)
  if canonical_json(existing)!=canonical_json(attestation): raise TransitionError("existing attestation identity has different content")
  return existing
 commit_batch(aios_dir,[(os.path.join(AUTHORITY_DIR,ATTESTATIONS_DIR,permit["permit_id"]+".json"),attestation)]); return attestation
def load_contract(aios_dir,contract_id):
 _require_id(contract_id,"contract_id"); record=_load(_path(aios_dir,CONTRACTS_DIR,contract_id)); contract={k:record[k] for k in ("contract_type","task_id","scope","actor","capabilities","input_digest","allowed_effects","evidence_required","max_attempts","terminal_states","policy_digest")}
 if contract_identity(contract)!=contract_id: raise TransitionError("stored contract identity mismatch")
 validate_contract(contract); return contract
def load_permit(aios_dir,permit_id):
 _require_id(permit_id,"permit_id"); return _load(_path(aios_dir,PERMITS_DIR,permit_id))
def load_attestation(aios_dir,permit_id):
 _require_id(permit_id,"permit_id"); return _load(_path(aios_dir,ATTESTATIONS_DIR,permit_id))
def authorize(aios_dir,contract_id,permit_id):
 contract=load_contract(aios_dir,contract_id); permit=load_permit(aios_dir,permit_id); verify_permit(contract,permit); return True
__all__=["persist_contract","persist_permit","persist_attestation","load_contract","load_permit","load_attestation","authorize"]
