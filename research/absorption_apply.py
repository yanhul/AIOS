"""Materialize absorption only with candidate-specific verification and runtime proof.

A generic AIOS runtime probe is not evidence that a particular candidate was
implemented. Every promoted record must have matching source review, test, receipt,
lineage, and candidate-specific runtime proof.
"""
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
    if verification.get("overall") != "PASS":
        raise RuntimeError("cannot materialize absorption without candidate-specific verification PASS")
    if runtime.get("overall") != "PASS":
        raise RuntimeError("cannot materialize absorption without PASS runtime proof")
    exec_by_id={r.get("candidate_id"):r for r in executor.get("records",[])}
    verified={r.get("candidate_id"):r for r in verification.get("records",[])}
    runtime_records=runtime.get("candidate_proofs")
    if not isinstance(runtime_records, list) or not runtime_records:
        raise RuntimeError("generic runtime probes are insufficient; candidate_proofs is required")
    runtime_by_id={r.get("candidate_id"):r for r in runtime_records}
    decisions=[d for d in promotion.get("decisions",[]) if d.get("allowed") is True and d.get("verdict")=="PROMOTE"]
    records=[]; blocked=[]
    for d in decisions:
        cid=d.get("candidate_id"); e=exec_by_id.get(cid); v=verified.get(cid); rp=runtime_by_id.get(cid)
        if not e or not v or not rp:
            blocked.append({"candidate_id":cid,"verdict":"HOLD","reason":"missing candidate-specific executor, verification, or runtime proof"}); continue
        if (rp.get("status") != "PASS" or rp.get("source_commit") != v.get("source_commit")
                or rp.get("test_digest") != v.get("test_digest")
                or rp.get("candidate_test_digest") != v.get("candidate_test_digest")):
            blocked.append({"candidate_id":cid,"verdict":"HOLD","reason":"candidate runtime proof failed or does not match verified source/test lineage"}); continue
        lineage=v.get("authority_receipt_lineage") or {}
        if rp.get("effect_id") != lineage.get("effect_id") or rp.get("attempt_id") != lineage.get("attempt_id") or rp.get("receipt_id") != lineage.get("receipt_id"):
            blocked.append({"candidate_id":cid,"verdict":"HOLD","reason":"runtime proof receipt/attempt/effect lineage mismatch"}); continue
        records.append({"candidate_id":cid,"run_id":run_id,"source_ref":e["source_ref"],
            "source_commit":v["source_commit"],"reviewed_files":v["reviewed_files"],
            "source_code_digest":v["source_code_digest"],"source_digest":e["source_digest"],
            "evidence_digest":e["evidence_digest"],"test_digest":v["test_digest"],
            "claim":v["claim"],"primitive":e["adaptation"]["primitive"],
            "implementation_refs":v["implementation_refs"],"candidate_test_refs":v["candidate_test_refs"],
            "conformance_run_id":v["conformance_run_id"],"log_digest":v["log_digest"],
            "authority_receipt_lineage":lineage,"signals":e["adaptation"].get("signals",[]),
            "proposal":e["adaptation"].get("proposal"),"target_surface":e["adaptation"].get("target_surface"),
            "absorption_kind":"AIOS_NATIVE_PRIMITIVE_REGISTRY","status":"ABSORBED",
            "implementation_status":"IMPLEMENTED_AND_CONFORMANT","runtime_status":"PROVEN",
            "external_code_copy":False,"external_code_execution":False,"source_mutation":False,
            "authority":"AIOS_CONTROL_PLANE","verification":"CANDIDATE_SPECIFIC_CONFORMANCE",
            "runtime_proof":rp.get("proof_digest")})
    expected=len(promotion.get("decisions",[]))+len(promotion.get("blocked",[]))
    result={"schema_version":3,"kind":"AIOS_ABSORPTION","run_id":run_id,"candidate_count":expected,
        "absorbed_count":len(records),"deferred_count":expected-len(records),"records":records,
        "blocked":blocked+[{"candidate_id":x.get("candidate_id"),"verdict":"DEFER",
        "reason":x.get("reason","promotion gate blocked")} for x in promotion.get("blocked",[])],
        "overall":"PASS" if expected and len(records)==expected and not blocked else "PASS_WITH_HOLDS" if records else "BLOCKED",
        "source_mutation":False,"external_code_execution":False,"authority":"AIOS_CONTROL_PLANE",
        "implementation_runtime_proof":"CANDIDATE_SPECIFIC"}
    out=_path("AIOS_ABSORPTION_OUTCOME",DEFAULT_OUT); out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8"); return result

if __name__=="__main__":
    e=json.loads(_path("AIOS_ABSORPTION_EXECUTOR_IN",DEFAULT_EXEC).read_text())
    v=json.loads(_path("AIOS_ABSORPTION_VERIFY_IN",DEFAULT_VERIFY).read_text())
    p=json.loads(_path("AIOS_ABSORPTION_PROMOTION_IN",DEFAULT_PROMO).read_text())
    r=json.loads(_path("AIOS_ABSORPTION_RUNTIME_IN",DEFAULT_RUNTIME).read_text())
    result=absorb(e,v,p,r,run_id=os.environ.get("GITHUB_RUN_ID",p.get("run_id","local")))
    raise SystemExit(0 if result["overall"] in {"PASS","PASS_WITH_HOLDS"} else 1)
