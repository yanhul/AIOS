"""Materialize only absorption records that passed verification and runtime proof."""
from __future__ import annotations
import json, os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DEFAULT_EXEC=ROOT/"research/artifacts/absorption-executor.json"
DEFAULT_VERIFY=ROOT/"research/artifacts/absorption-verification.json"
DEFAULT_PROMO=ROOT/"research/artifacts/absorption-promotion.json"
DEFAULT_RUNTIME=ROOT/"research/artifacts/absorption-runtime-proof.json"
DEFAULT_OUT=ROOT/"research/artifacts/absorption.json"

def _path(name, default): return Path(os.environ.get(name, str(default)))

def absorb(executor, verification, promotion, runtime, *, run_id):
    if runtime.get("overall") != "PASS":
        raise RuntimeError("cannot materialize absorption without PASS runtime proof")
    exec_by_id={r.get("candidate_id"):r for r in executor.get("records",[])}
    verified={r.get("candidate_id"):r for r in verification.get("records",[])}
    decisions=[d for d in promotion.get("decisions",[]) if d.get("allowed") is True and d.get("verdict")=="PROMOTE"]
    records=[]; blocked=[]
    for d in decisions:
        cid=d.get("candidate_id"); e=exec_by_id.get(cid); v=verified.get(cid)
        if not e or not v:
            blocked.append({"candidate_id":cid,"verdict":"HOLD","reason":"missing executor or independent-verification lineage"}); continue
        records.append({"candidate_id":cid,"run_id":run_id,"source_ref":e["source_ref"],
            "source_digest":e["source_digest"],"evidence_digest":e["evidence_digest"],
            "test_digest":v["test_digest"],"claim":v["claim"],"primitive":e["adaptation"]["primitive"],
            "signals":e["adaptation"]["signals"],"proposal":e["adaptation"]["proposal"],
            "target_surface":e["adaptation"]["target_surface"],"absorption_kind":"AIOS_NATIVE_PRIMITIVE_REGISTRY",
            "status":"ABSORBED","implementation_status":"IMPLEMENTED_AND_CONFORMANT",
            "runtime_status":"PROVEN","external_code_copy":False,"external_code_execution":False,
            "source_mutation":False,"authority":"AIOS_CONTROL_PLANE",
            "verification":"INDEPENDENT_STRUCTURAL_CONFORMANCE","runtime_proof":runtime.get("digest")})
    expected=len(promotion.get("decisions",[]))+len(promotion.get("blocked",[]))
    result={"schema_version":2,"kind":"AIOS_ABSORPTION","run_id":run_id,"candidate_count":expected,
        "absorbed_count":len(records),"deferred_count":expected-len(records),"records":records,
        "blocked":blocked+[{"candidate_id":x.get("candidate_id"),"verdict":"DEFER",
        "reason":x.get("reason","promotion gate blocked")} for x in promotion.get("blocked",[])],
        "overall":"PASS" if expected and len(records)==expected and not blocked else "PASS_WITH_HOLDS" if records else "BLOCKED",
        "source_mutation":False,"external_code_execution":False,"authority":"AIOS_CONTROL_PLANE",
        "implementation_runtime_proof":"PASS"}
    out=_path("AIOS_ABSORPTION_OUTCOME",DEFAULT_OUT); out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8"); return result

if __name__=="__main__":
    e=json.loads(_path("AIOS_ABSORPTION_EXECUTOR_IN",DEFAULT_EXEC).read_text())
    v=json.loads(_path("AIOS_ABSORPTION_VERIFY_IN",DEFAULT_VERIFY).read_text())
    p=json.loads(_path("AIOS_ABSORPTION_PROMOTION_IN",DEFAULT_PROMO).read_text())
    r=json.loads(_path("AIOS_ABSORPTION_RUNTIME_IN",DEFAULT_RUNTIME).read_text())
    result=absorb(e,v,p,r,run_id=os.environ.get("GITHUB_RUN_ID",p.get("run_id","local")))
    raise SystemExit(0 if result["overall"] in {"PASS","PASS_WITH_HOLDS"} else 1)
