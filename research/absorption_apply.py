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
    # Materialization has no independent issuer/verifier to authenticate a
    # candidate proof. A matching dictionary and digest are caller assertions,
    # so this boundary must never stamp runtime_status=PROVEN yet.
    blocked=[]
    decisions=[d for d in promotion.get("decisions",[]) if d.get("allowed") is True and d.get("verdict")=="PROMOTE"]
    records=[]
    for d in decisions:
        cid=d.get("candidate_id")
        blocked.append({"candidate_id":cid,"verdict":"HOLD","reason":"independent candidate runtime proof verifier is not configured"})
    expected=len(promotion.get("decisions",[]))+len(promotion.get("blocked",[]))
    result={"schema_version":2,"kind":"AIOS_ABSORPTION","run_id":run_id,"candidate_count":expected,
        "absorbed_count":0,"deferred_count":expected,"records":[],
        "blocked":blocked+[{ "candidate_id":x.get("candidate_id"),"verdict":"DEFER",
        "reason":x.get("reason","promotion gate blocked")} for x in promotion.get("blocked",[])],
        "overall":"BLOCKED",
        "source_mutation":False,"external_code_execution":False,"authority":"AIOS_CONTROL_PLANE",
        "implementation_runtime_proof":"INCOMPLETE"}
    out=_path("AIOS_ABSORPTION_OUTCOME",DEFAULT_OUT); out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8"); return result


if __name__=="__main__":
    e=json.loads(_path("AIOS_ABSORPTION_EXECUTOR_IN",DEFAULT_EXEC).read_text())
    v=json.loads(_path("AIOS_ABSORPTION_VERIFY_IN",DEFAULT_VERIFY).read_text())
    p=json.loads(_path("AIOS_ABSORPTION_PROMOTION_IN",DEFAULT_PROMO).read_text())
    r=json.loads(_path("AIOS_ABSORPTION_RUNTIME_IN",DEFAULT_RUNTIME).read_text())
    result=absorb(e,v,p,r,run_id=os.environ.get("GITHUB_RUN_ID",p.get("run_id","local")))
    raise SystemExit(0 if result["overall"] in {"PASS","PASS_WITH_HOLDS"} else 1)
