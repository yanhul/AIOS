"""Bounded, fail-closed research -> adaptation executor for AIOS absorption.

External repositories are evidence sources only. This module never copies or executes external code and never mutates AIOS source/policy/promotion state.
"""
from __future__ import annotations
import hashlib,json,os,urllib.parse,urllib.request
from pathlib import Path

DEFAULT_CANDIDATES=Path("research/artifacts/absorption-candidates.json")
DEFAULT_OUT=Path("research/artifacts/absorption-executor.json")
MAX_CANDIDATES=50  # bounded, but never silently truncates the daily candidate set
MAX_README=12000
TIMEOUT=15

def _path(env_name, default): return Path(os.environ.get(env_name, str(default)))
def _digest(text): return hashlib.sha256(text.encode("utf-8")).hexdigest()
def _get(url):
    req=urllib.request.Request(url,headers={"Accept":"application/vnd.github+json","User-Agent":"AIOS-absorption-executor"})
    token=os.environ.get("GITHUB_TOKEN")
    if token: req.add_header("Authorization",f"Bearer {token}")
    with urllib.request.urlopen(req,timeout=TIMEOUT) as r: return r.read().decode("utf-8","replace")
def _readme_url(source_ref,ref=None):
    p=urllib.parse.urlparse(source_ref); parts=p.path.strip("/").split("/")
    if len(parts)<2: return None
    owner,repo=parts[:2]; branch=ref or "HEAD"
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{urllib.parse.quote(branch,safe='')}/README.md"
def _adapt(candidate,readme):
    text=readme.lower()
    signals=[s for s in ("provenance","evidence","durable","retry","research","memory","harness","governance") if s in text]
    return {"adaptation":"AIOS_NATIVE_PROPOSAL_ONLY","primitive":candidate["primitive"],"signals":signals[:8],"target_surface":"new AIOS adapter/task only","external_code_copy":False,"external_code_execution":False,"proposal":"derive an AIOS-native interface from independently verified behavior; do not import source code","required_checks":["source_evidence_digest","AIOS_conformance","independent_tests","evidence_promotion_gate"]}
def execute(candidates,*,run_id):
    records=[]
    for c in candidates[:MAX_CANDIDATES]:
        source=c.get("source_ref",""); url=_readme_url(source,c.get("ref"))
        base={"candidate_id":c["candidate_id"],"source_ref":source,"source_digest":c["source_digest"],"run_id":run_id,"authority":"AIOS_CONTROL_PLANE","status":"HOLD","promotion":"REQUIRES_INDEPENDENT_RESEARCH_AND_EVIDENCE_GATE"}
        try:
            readme=_get(url) if url else ""; readme=readme[:MAX_README]
            base.update({"evidence_url":url,"evidence_digest":_digest(readme),"evidence_status":"COLLECTED","adaptation":_adapt(c,readme),"status":"RESEARCHED_ADAPTATION_PROPOSED"})
        except Exception as exc:
            base.update({"evidence_status":"ERROR","error_type":type(exc).__name__,"error_digest":_digest(str(exc))})
        records.append(base)
    result={"schema_version":1,"kind":"AIOS_ABSORPTION_EXECUTOR","run_id":run_id,"candidate_count":len(candidates),"processed_count":len(records),"truncated":len(records) < len(candidates),"records":records,"promotion":"BLOCKED_UNTIL_EVIDENCE_GATE"}
    out=_path("AIOS_ABSORPTION_EXECUTOR_OUT",DEFAULT_OUT)
    out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    return result

if __name__=="__main__":
    candidates=_path("AIOS_ABSORPTION_OUT",DEFAULT_CANDIDATES)
    data=json.loads(candidates.read_text(encoding="utf-8")); execute(data.get("candidates",[]),run_id=os.environ.get("GITHUB_RUN_ID","local"))
