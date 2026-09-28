#!/usr/bin/env python3
"""Run pcb.eda@1 as an AIOS durable, bounded, resumable workload."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from typing import Any
from adapters.pcb_eda.adapter import run_kit
from core.pcb_eda import PcbEdaRequest
from core.durable_loop import LoopPolicy, run_durable_loop
from core.blocked_continuation import classify_blockers

class JsonStateStore:
    def __init__(self, path: Path): self.path = path
    def load(self):
        return json.loads(self.path.read_text()) if self.path.exists() else None
    def save(self, state):
        self.path.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")

class PcbExecutor:
    def __init__(self, args): self.args=args
    def observe(self, state):
        return {"capability":"pcb.eda@1", "step":state.get("step",0),
                "continuation":state.get("continuation")}
    def decide(self, observation, state):
        op = (state.get("continuation") or {}).get("next_operation_id", "pcb.eda@1")
        return {"logical_operation_id":op, "authority":"AIOS_CONTROL_PLANE"}
    def act(self, decision, state):
        if decision["logical_operation_id"] != "pcb.eda@1":
            raise RuntimeError("discovery must produce verified evidence before pcb.eda redispatch")
        task = f"{self.args.task_id}-attempt-{state.get('step',0)+1}"
        req=PcbEdaRequest(task_id=task,input_dir=str(self.args.input),
                          output_dir=str(self.args.output),kit_root=str(self.args.kit_root),
                          config=str(self.args.config) if self.args.config else None,
                          repair=True,max_retries=self.args.kit_retries)
        rc, receipt=run_kit(req)
        return {"returncode":rc,"receipt":receipt}
    def verify(self, result, state):
        receipt=result["receipt"]
        return {
            "status": receipt["status"],
            "blockers": receipt.get("blockers") or receipt.get("findings") or [],
            "receipt": {
                "effect_id": f"{self.args.task_id}:effect:{state.get('step',0)+1}",
                "attempt_id": f"{self.args.task_id}:attempt:{state.get('step',0)+1}",
                "status": "OBSERVED",
                "evidence": {
                    "summary": str(self.args.output / "summary.json"),
                    "receipt_schema": receipt.get("schema"),
                    "terminal_reason": receipt.get("terminal_reason"),
                    "gates": receipt.get("gates"),
                },
            },
            "kit_receipt": receipt,
        }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--task-id",required=True); ap.add_argument("--input",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True); ap.add_argument("--kit-root",type=Path,required=True)
    ap.add_argument("--config",type=Path); ap.add_argument("--state",type=Path,required=True)
    ap.add_argument("--max-steps",type=int,default=4); ap.add_argument("--kit-retries",type=int,default=3)
    a=ap.parse_args()
    a.output.mkdir(parents=True,exist_ok=True)
    def continuation(v,s):
        blockers=classify_blockers(v)
        if not blockers: return None
        refs=[str(a.output/"summary.json")]
        # A rerun is authorized only from the observed Kit receipt/evidence.
        return {"authority":"AIOS_CONTROL_PLANE","evidence_refs":refs,
                "next_operation_id":"pcb.eda@1",
                "reason":"observed Kit blocker evidence permits bounded re-dispatch",
                "blockers":blockers}
    def terminal(v,s):
        if v.get("status")=="PASS": return "PASS"
        if v.get("status")=="BLOCKED": return "BLOCKED"
        return "INCONCLUSIVE"
    policy=LoopPolicy(max_steps=a.max_steps,terminal_evaluator=terminal,
                      action_authorizer=lambda d,s: None,require_execution_receipt=True,
                      blocked_continuation=continuation)
    result=run_durable_loop(PcbExecutor(a),JsonStateStore(a.state),policy)
    print(json.dumps(result,indent=2,default=str))
    raise SystemExit(0 if result["status"]=="PASS" else 2)

if __name__=="__main__": main()
