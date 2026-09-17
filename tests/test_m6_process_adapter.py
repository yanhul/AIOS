import json
import sys
from adapters.process import SubprocessAdapter
from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.evidence import EvidenceRecord
from core.policy_registry import persist_policy
from core.runtime import execute

BINDING={"target_sha":"sha256:worker-v1","evidence_ref":"EV-process-1","lineage_ref":"LIN-process-1","idempotency_key":"idem-process-1","attempt_fence":1}

def make_contract(policy_digest):
    return {"contract_type":"EXECUTION_CONTRACT","task_id":"task-process","scope":"process-test","actor":"agent:test","capabilities":["process-provider@1"],"input_digest":"input-1","allowed_effects":["external_effect"],"evidence_required":["provider_receipt"],"max_attempts":1,"terminal_states":["SUCCESS","FAILURE"],"policy_digest":policy_digest}

def setup(tmp_path):
    registry=CapabilityRegistry(); registry.register(Capability("process-provider","1","test-fixture","test",status="ACTIVE")); registry.persist(str(tmp_path),"test-fixture")
    policy=persist_policy(str(tmp_path),{"policy_type":"GOVERNING_POLICY","name":"process-fixture"}); contract=make_contract(policy); cid=contract_identity(contract); persist_contract(str(tmp_path),contract); permit=persist_permit(str(tmp_path),contract,"root")
    return cid,permit["permit_id"]

def _execute(tmp_path,cid,pid,adapter):
    return execute(str(tmp_path),cid,pid,"op-1","agent:test",adapter,BINDING["target_sha"],BINDING["evidence_ref"],BINDING["lineage_ref"],BINDING["idempotency_key"],BINDING["attempt_fence"])

def _success_code():
    evidence=EvidenceRecord(evidence_id="EV-process-1",level="OBSERVED",source_ref="process://test",claim="process completed operation",run_id="task-process",provider="process-provider").as_record()
    payload={"provider":"process-provider","effect_id":"EFFECT","attempt_id":"ATTEMPT","provider_operation_id":"proc-1","outcome":"OBSERVED_SUCCESS","observation":{"exit":0,"evidence":evidence},**BINDING}
    return "import json,sys; r=json.load(sys.stdin); p="+repr(payload)+"; p['effect_id']=r['effect']['effect_id']; p['attempt_id']=r['attempt_id']; print(json.dumps(p))"

def test_subprocess_adapter_returns_bound_receipt(tmp_path):
    cid,pid=setup(tmp_path); adapter=SubprocessAdapter("process-provider",[sys.executable,"-c",_success_code()]); result=_execute(tmp_path,cid,pid,adapter)
    assert result["state"]=="OBSERVED_SUCCESS" and result["provider_observation"]["provider_operation_id"]=="proc-1"

def test_subprocess_malformed_output_becomes_unknown(tmp_path):
    cid,pid=setup(tmp_path); result=_execute(tmp_path,cid,pid,SubprocessAdapter("process-provider",[sys.executable,"-c","print('not-json')"])); assert result["state"]=="UNKNOWN" and "JSON" in result["unknown_reason"]

def test_subprocess_timeout_becomes_unknown(tmp_path):
    cid,pid=setup(tmp_path); result=_execute(tmp_path,cid,pid,SubprocessAdapter("process-provider",[sys.executable,"-c","import time; time.sleep(1)"],timeout_seconds=0.05)); assert result["state"]=="UNKNOWN" and "timed out" in result["unknown_reason"]

def test_subprocess_output_limit_becomes_unknown(tmp_path):
    cid,pid=setup(tmp_path); result=_execute(tmp_path,cid,pid,SubprocessAdapter("process-provider",[sys.executable,"-c","print('x' * 10000)"],max_output_bytes=128)); assert result["state"]=="UNKNOWN" and "output limit" in result["unknown_reason"]

def test_subprocess_command_is_not_shell_interpolated(tmp_path):
    cid,pid=setup(tmp_path)
    evidence=EvidenceRecord(evidence_id="EV-process-1",level="OBSERVED",source_ref="process://test",claim="process completed operation",run_id="task-process",provider="process-provider").as_record()
    code="import json,sys; r=json.load(sys.stdin); print(json.dumps({'provider':'process-provider','effect_id':r['effect']['effect_id'],'attempt_id':r['attempt_id'],'provider_operation_id':'proc-safe','outcome':'OBSERVED_SUCCESS','observation':{'safe':True,'evidence':"+repr(evidence)+"},**r['effect']}))"
    adapter=SubprocessAdapter("process-provider",[sys.executable,"-c",code,"literal;not;a;shell;command"]); result=_execute(tmp_path,cid,pid,adapter)
    assert result["state"]=="OBSERVED_SUCCESS"

def test_subprocess_rejects_receipt_missing_gateway_binding(tmp_path):
    cid,pid=setup(tmp_path)
    code="import json; print(json.dumps({'provider':'process-provider','effect_id':'x','attempt_id':'x','provider_operation_id':'proc-1','outcome':'OBSERVED_SUCCESS','observation':{'ok':True}}))"
    with __import__('pytest').raises(ValueError, match="missing mandatory Gateway bindings"):
        SubprocessAdapter("process-provider",[sys.executable,"-c",code]).execute(contract=make_contract("x"),effect={"target_sha":"x","evidence_ref":"x","lineage_ref":"x","idempotency_key":"x","attempt_fence":1},attempt_id="x")
