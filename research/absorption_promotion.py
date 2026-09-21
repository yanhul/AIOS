"""Fail-closed promotion for verified AIOS-native absorption.

Promotion requires structural verification AND current implementation/runtime proof.
"""
from __future__ import annotations
import json, os, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from core.evidence_gate import gate_promotion

def _path(env_name, default): return Path(os.environ.get(env_name, str(default)))
DEFAULT_INPUT=Path("research/artifacts/absorption-verification.json")
DEFAULT_RUNTIME=Path("research/artifacts/absorption-runtime-proof.json")
DEFAULT_OUT=Path("research/artifacts/absorption-promotion.json")

def promote(data: dict, runtime: dict | None = None) -> dict:
    runtime = runtime or {}
    runtime_ok = runtime.get("overall") == "PASS"
    decisions=[]; blocked=[]
    for record in data.get("records", []):
        decision=gate_promotion(record, required_level="VERIFIED_DIGITAL")
        allowed=decision.allowed and runtime_ok
        item={"candidate_id":record.get("candidate_id"),"run_id":record.get("run_id"),
              "source_ref":record.get("source_ref"),"claim":record.get("claim"),
              "level":record.get("level"),"allowed":allowed,
              "action":"PROMOTE_TO_ABSORBED_REGISTRY" if allowed else "HOLD",
              "verdict":"PROMOTE" if allowed else "DEFER"}
        if not decision.allowed: item["reason"]=decision.reason
        elif not runtime_ok: item["reason"]="implementation/runtime proof is not PASS"
        (decisions if allowed else blocked).append(item)
    for failure in data.get("failures", []):
        blocked.append({"candidate_id":failure.get("candidate_id"),"run_id":data.get("run_id"),
                        "source_ref":failure.get("source_ref"),"allowed":False,"action":"HOLD",
                        "verdict":"DEFER","level":failure.get("level","UNKNOWN"),
                        "reason":"; ".join(failure.get("errors",[])) or "independent verification did not complete",
                        "errors":failure.get("errors",[])})
    result={"schema_version":2,"kind":"AIOS_ABSORPTION_PROMOTION","run_id":data.get("run_id"),
            "decisions":decisions,"blocked":blocked,
            "candidate_count":len(decisions)+len(blocked),"promoted_count":len(decisions),
            "deferred_count":len(blocked),
            "overall":"PASS" if decisions and not blocked and data.get("overall")=="PASS" and runtime_ok
                     else "PASS_WITH_HOLDS" if decisions or blocked else "BLOCKED",
            "implementation_runtime_proof":runtime_ok,"source_mutation":False,
            "external_code_execution":False,"authority":"AIOS_CONTROL_PLANE"}
    out=_path("AIOS_ABSORPTION_PROMOTION_OUT",DEFAULT_OUT)
    out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return result

if __name__=="__main__":
    verification=json.loads(_path("AIOS_ABSORPTION_VERIFY_OUT",DEFAULT_INPUT).read_text())
    runtime=json.loads(_path("AIOS_ABSORPTION_RUNTIME_IN",DEFAULT_RUNTIME).read_text()) if _path("AIOS_ABSORPTION_RUNTIME_IN",DEFAULT_RUNTIME).exists() else {}
    result=promote(verification,runtime)
    raise SystemExit(0 if result["overall"] in {"PASS","PASS_WITH_HOLDS"} else 1)
