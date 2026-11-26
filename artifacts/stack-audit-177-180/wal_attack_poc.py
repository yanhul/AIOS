import sys; sys.path.insert(0, ".")
from copy import deepcopy
from core.durable_loop import LoopPolicy, MemoryStateStore, run_durable_loop, reconcile_in_flight_attempt, _recovery_binding
acts=[]
class Ex:
    def observe(s,st): return {}
    def decide(s,o,st): return {"op":"x"}
    def act(s,d,st): acts.append(1); return {"ok":1}
    def verify(s,r,st):
        i=st["in_flight_attempt"]
        return {"status":"DONE","state_patch":{"out":"real"},"receipt":{"effect_id":i["effect_id"],"attempt_id":i["attempt_id"],"status":"OBSERVED","evidence":{"p":1}}}
pol=LoopPolicy(max_steps=3,terminal_evaluator=lambda v,s:"PASS",action_authorizer=lambda d,s:None,require_execution_receipt=True,
  execution_receipt_validator=lambda r,s:None,state_patch_validator=lambda p,r,s:None,
  operation_identity=lambda d,s:{"contract_id":"c","actor":"a","logical_operation_id":f"op:{s['step']}"})
# F-03: forge validated patch + recompute unkeyed binding
class CrashStore(MemoryStateStore):
    def save(self, st):
        super().save(st)
        if st.get("in_flight_attempt",{}).get("status")=="RECEIPT_VALIDATED": raise SystemExit
s=CrashStore()
try: run_durable_loop(Ex(),s,pol)
except SystemExit: pass
st=s.state; i=st["in_flight_attempt"]
i["validated_state_patch"]={"out":"FORGED"}; i["validated_verification"]["state_patch"]={"out":"FORGED"}
i["recovery_binding"]=_recovery_binding(i,i["validated_receipt"],i["validated_state_patch"],i["validated_verification"],i["validated_action_result"])
m=MemoryStateStore(deepcopy(st))
r=reconcile_in_flight_attempt(m,pol,deepcopy(i["validated_receipt"]),authorizer=lambda a,b:None)
print("F-03 forged patch accepted:", r.get("out"), r["status"])
# F-04: WAL writer drops in-flight intent -> provider re-invoked
acts.clear(); s2=CrashStore()
try: run_durable_loop(Ex(),s2,pol)
except SystemExit: pass
st=deepcopy(s2.state); st.pop("in_flight_attempt")
m=MemoryStateStore(st); run_durable_loop(Ex(),m,pol)
print("F-04 act() invocations for one logical op:", len(acts))
