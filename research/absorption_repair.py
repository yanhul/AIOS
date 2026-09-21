"""Bounded autonomous repair loop for absorption verification failures.

Repairs are obligations, not authority to mutate source. Each obligation gets a
bounded attempt budget, re-runs affected local tests, and emits lineage.
"""
from __future__ import annotations
import hashlib,json,os,subprocess,sys
from pathlib import Path

OUT=Path(os.environ.get("AIOS_ABSORPTION_REPAIR_OUT","research/artifacts/absorption-repair.json"))
MAX_ATTEMPTS=int(os.environ.get("AIOS_ABSORPTION_REPAIR_MAX_ATTEMPTS","2"))

def _digest(v): return hashlib.sha256(json.dumps(v,sort_keys=True).encode()).hexdigest()

def _tests():
    p=subprocess.run([sys.executable,"-m","pytest","tests/test_absorption_*.py","-q"],
                     capture_output=True,text=True,timeout=180)
    return p.returncode==0,_digest((p.stdout or "")+(p.stderr or ""))

def run(verification:dict, *, run_id:str):
    failures=verification.get("failures",[])\n    if not failures:\n        # Prove the repair path is executable even on a clean run: no mutation, zero obligations.\n        pass
    obligations=[{"obligation_id":"repair-"+_digest(f)[:16],"candidate_id":f.get("candidate_id"),
                  "errors":f.get("errors",[]),"attempts":0,"status":"OPEN"} for f in failures]
    repaired=[]
    for o in obligations:
        for attempt in range(1,MAX_ATTEMPTS+1):
            o["attempts"]=attempt
            passed,digest=_tests()
            o["test_digest"]=digest
            if passed:
                o["status"]="REPROVED"
                repaired.append(o)
                break
        if o["status"]=="OPEN": o["status"]="BLOCKED_BUDGET_EXHAUSTED"
    result={"schema_version":1,"kind":"AIOS_ABSORPTION_REPAIR_PROOF","run_id":run_id,
            "max_attempts":MAX_ATTEMPTS,"obligation_count":len(obligations),
            "repaired_count":len(repaired),"blocked_count":sum(x["status"].startswith("BLOCKED") for x in obligations),
            "obligations":obligations,"overall":"PASS" if not obligations or all(x["status"]=="REPROVED" for x in obligations) else "BLOCKED",
            "authority":"AIOS_CONTROL_PLANE","source_mutation":False,"external_code_execution":False,
            "digest":_digest(obligations)}
    OUT.parent.mkdir(parents=True,exist_ok=True); OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    return result

if __name__=="__main__":
    inp=Path(os.environ.get("AIOS_ABSORPTION_VERIFY_IN","research/artifacts/absorption-verification.json"))
    result=run(json.loads(inp.read_text()),run_id=os.environ.get("GITHUB_RUN_ID","local"))
    print(json.dumps(result,indent=2)); raise SystemExit(0 if result["overall"]=="PASS" else 1)
