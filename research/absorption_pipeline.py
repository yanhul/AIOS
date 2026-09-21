"""Governed research -> adaptation -> verification intake."""
from __future__ import annotations
import hashlib,json,os
from pathlib import Path
SCAN=Path(os.environ.get("AIOS_RESEARCH_SCAN","research/artifacts/daily-scan.json"))
OUT=Path(os.environ.get("AIOS_ABSORPTION_OUT","research/artifacts/absorption-candidates.json"))
VERIFY=Path(os.environ.get("AIOS_ABSORPTION_VERIFY","research/artifacts/absorption-verification.json"))
ALLOWED=("harness","research","memory","provenance","governance","execution","agent")
def _digest(v): return hashlib.sha256(json.dumps(v,sort_keys=True).encode()).hexdigest()
def _primitive(text):
 t=text.lower()
 if "provenance" in t or "evidence" in t:return "evidence_provenance"
 if "research" in t or "experiment" in t:return "research_harness"
 if "memory" in t:return "memory"
 if "execution" in t or "durable" in t or "retry" in t:return "durable_execution"
 return "agent_harness"
def build(scan):
 cs=[]
 for r in scan.get("records",[]):
  text=" ".join(str(r.get(k,"")) for k in ("repo","description","query"))
  if any(k in text.lower() for k in ALLOWED):
   cs.append({"candidate_id":"cand-"+_digest({"source_ref":r["source_ref"],"digest":r["source_digest"]})[:16],"source_ref":r["source_ref"],"source_digest":r["source_digest"],"ref":r.get("ref","HEAD"),"primitive":_primitive(text),"status":"UNTRUSTED_EVIDENCE","mutation_authority":"AIOS","external_code_copy":False,"next_action":"RESEARCH_AND_VERIFY","bounded_surface":["new AIOS adapter/task only"],"promotion_required":True})
 result={"schema_version":2,"kind":"AIOS_ABSORPTION_CANDIDATES","candidates":cs}
 OUT.parent.mkdir(parents=True,exist_ok=True); OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); return result
def verify(candidates, *, run_id=None):
 rs=[{"candidate_id":c["candidate_id"],"source_ref":c["source_ref"],"source_digest":c["source_digest"],"primitive":c["primitive"],"verification":"STATIC_INTAKE","evidence_refs":[c["source_ref"],c["source_digest"]],"level":"ADVISORY","status":"UNTRUSTED_EVIDENCE","promotion":"REQUIRES_INDEPENDENT_RESEARCH_AND_EVIDENCE_GATE","authority":"AIOS_CONTROL_PLANE","run_id":run_id} for c in candidates]
 result={"schema_version":2,"kind":"AIOS_ABSORPTION_VERIFICATION","records":rs}
 VERIFY.parent.mkdir(parents=True,exist_ok=True); VERIFY.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); return result
if __name__=="__main__": verify(build(json.loads(SCAN.read_text(encoding="utf-8")))["candidates"])
