#!/usr/bin/env python3
"""AIOS durable schematic-first runner for QI9-2605."""
from __future__ import annotations
import argparse,json,hashlib,subprocess,sys
from pathlib import Path
from typing import Mapping
from core.continue_contract import build_continue_contract
from core.durable_loop import LoopPolicy,run_durable_loop

class Store:
    def __init__(self,p): self.p=p
    def load(self): return json.loads(self.p.read_text()) if self.p.exists() else None
    def save(self,s):
        t=self.p.with_suffix(".tmp"); t.write_text(json.dumps(s,indent=2,ensure_ascii=False)); t.replace(self.p)

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def seed(a):
    return {"project":"yanhul/temp","design":a.design,"authority":"AIOS_CONTROL_PLANE",
      "pipeline":{"schematic":"RUNNING","placement":"BLOCKED_BY_SCHEMATIC","routing":"BLOCKED_BY_SCHEMATIC"},
      "active_phase":"SCHEMATIC","active_commit":a.source_commit,"latest_run":"NOT_YET_RUN","latest_receipt":"NOT_YET_RECEIPT",
      "active_blockers":[],"next_legal_actions":["run_schematic","inspect_receipt","inspect_source","patch","commit","wait_ci"],
      "forbidden_actions":["placement","routing","claim_pass"],"verified_evidence_refs":[],"blocked_requirements":[]}

class Executor:
    def __init__(self,a): self.a=a
    def observe(self,s): return {"capability":"pcb.eda@1","phase":"SCHEMATIC","step":s.get("step",0)}
    def decide(self,o,s): return {"logical_operation_id":"pcb.eda.schematic","authority":"AIOS_CONTROL_PLANE"}
    def act(self,d,s):
        if d["logical_operation_id"]!="pcb.eda.schematic": raise PermissionError("only schematic operation is legal")
        n=s.get("step",0)+1; out=self.a.output/f"attempt-{n}"; out.mkdir(parents=True,exist_ok=True)
        p=subprocess.run([sys.executable,str(self.a.kit_root/"tools/altium-audit/e2e_phase.py"),"--phase","schematic","--input",str(self.a.input),"--output",str(out),"--config",str(self.a.config)],text=True,capture_output=True)
        rp=out/"phase_receipt.json"
        if not rp.is_file(): raise RuntimeError("schematic phase emitted no phase_receipt.json")
        r=json.loads(rp.read_text()); r["receipt_sha256"]=sha(rp)
        return {"attempt_dir":str(out.resolve()),"returncode":p.returncode,"receipt":r,"stderr_tail":p.stderr[-4000:]}
    def verify(self,x,s):
        r=x["receipt"]; status=r.get("status")
        if status not in {"PASS","BLOCKED"}: raise ValueError(f"unauthorized schematic status: {status!r}")
        ev=r.get("evidence") if isinstance(r.get("evidence"),Mapping) else {}
        inv=ev.get("finding_inventory") if isinstance(ev.get("finding_inventory"),Mapping) else {}
        blockers=list(inv.get("blocking") or inv.get("errors") or [])
        pipe=dict(s.get("pipeline") or {}); pipe["schematic"]="VERIFIED" if status=="PASS" else "BLOCKED"
        pipe["placement"]="READY" if status=="PASS" else "BLOCKED_BY_SCHEMATIC"; pipe["routing"]="BLOCKED_BY_PLACEMENT" if status=="PASS" else "BLOCKED_BY_SCHEMATIC"
        return {"status":status,"state_patch":{"active_phase":"SCHEMATIC_VERIFIED" if status=="PASS" else "SCHEMATIC","pipeline":pipe,"active_blockers":blockers,
          "latest_attempt_dir":x["attempt_dir"],"latest_receipt":str(Path(x["attempt_dir"])/"phase_receipt.json"),"latest_run":self.a.run_id,
          "next_legal_actions":["placement"] if status=="PASS" else ["inspect_receipt","inspect_source","patch","commit","wait_ci"],
          "forbidden_actions":["routing","claim_pass"] if status=="PASS" else ["placement","routing","claim_pass"],
          "receipt":{"effect_id":f"{self.a.task_id}:effect:{s.get('step',0)+1}","attempt_id":f"{self.a.task_id}:attempt:{s.get('step',0)+1}","status":"OBSERVED",
            "evidence":{"phase_receipt":str(Path(x["attempt_dir"])/"phase_receipt.json"),"phase_receipt_sha256":r["receipt_sha256"],"source_commit":self.a.source_commit}}}}

def main():
    ap=argparse.ArgumentParser()
    for n in ("task_id","source_commit","run_id"): ap.add_argument("--"+n,required=True)
    ap.add_argument("--design",default="QI9-2605-A01"); ap.add_argument("--input",type=Path,required=True); ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--kit-root",type=Path,required=True); ap.add_argument("--config",type=Path,required=True); ap.add_argument("--state",type=Path,required=True); ap.add_argument("--max-steps",type=int,default=1)
    a=ap.parse_args(); a.output.mkdir(parents=True,exist_ok=True); st=Store(a.state)
    if st.load() is None: st.save(seed(a))
    def term(v,s): return v.get("status") if v.get("status") in {"PASS","BLOCKED"} else None
    pol=LoopPolicy(max_steps=a.max_steps,terminal_evaluator=term,action_authorizer=lambda d,s: None if d.get("logical_operation_id")=="pcb.eda.schematic" else (_ for _ in ()).throw(PermissionError("unauthorized phase")),require_execution_receipt=True,continue_contract_builder=build_continue_contract)
    result=run_durable_loop(Executor(a),st,pol); print(json.dumps(result,indent=2,ensure_ascii=False)); return 0 if result["status"]=="PASS" else 2
if __name__=="__main__": raise SystemExit(main())
