import pytest

from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.durable_runtime import RuntimeSubmission
from core.effect_authority import create_effect, dispatch, transition
from core.evidence import EvidenceRecord
from core.policy_registry import persist_policy
from core.runtime import ProviderReceipt, execute, execute_retry_attempt

BINDING = {"target_sha":"sha256:worker-v1","evidence_ref":"EV-durable-1","lineage_ref":"LIN-durable-1","idempotency_key":"idem-durable-1","attempt_fence":1}

def evidence(): return EvidenceRecord(evidence_id="EV-durable-1",level="OBSERVED",source_ref="runtime/test",claim="provider completed operation",run_id="run-durable-1",provider="fake-provider").as_record()

def make_contract(policy_digest, max_attempts=1):
    return {"contract_type":"EXECUTION_CONTRACT","task_id":"task-durable-runtime","scope":"runtime-test","actor":"agent:test","capabilities":["fake-provider@1"],"input_digest":"input-1","allowed_effects":["external_effect"],"evidence_required":["provider_receipt"],"max_attempts":max_attempts,"terminal_states":["SUCCESS","FAILURE"],"policy_digest":policy_digest}

class GoodAdapter:
    name="fake-provider"
    def execute(self, *, contract, effect, attempt_id):
        return ProviderReceipt(self.name,effect["effect_id"],attempt_id,"provider-op","OBSERVED_SUCCESS",{"status":"ok","evidence":evidence()},effect["target_sha"],effect["evidence_ref"],effect["lineage_ref"],effect["idempotency_key"],effect["attempt_fence"])

class GoodRuntime:
    name="durable-test"
    def submit(self, *, effect, attempt_id): return RuntimeSubmission(effect["effect_id"],attempt_id,"fake-provider")
    def retry(self, *, effect, attempt_id, attempt): return RuntimeSubmission(effect["effect_id"],attempt_id,"fake-provider")
    def resume(self, *, effect, attempt_id): return RuntimeSubmission(effect["effect_id"],attempt_id,"fake-provider")

def setup(tmp_path,max_attempts=1):
    registry=CapabilityRegistry(); registry.register(Capability("fake-provider","1","test-fixture","test",status="ACTIVE")); registry.persist(str(tmp_path),"test-fixture")
    policy=persist_policy(str(tmp_path),{"policy_type":"GOVERNING_POLICY","name":"durable-runtime-fixture"}); c=make_contract(policy,max_attempts); cid=contract_identity(c); persist_contract(str(tmp_path),c); permit=persist_permit(str(tmp_path),c,"root")
    return cid,permit["permit_id"]

def _execute(tmp_path,cid,pid,adapter,runtime=None,fence=1):
    return execute(str(tmp_path),cid,pid,"op-1","agent:test",adapter,BINDING["target_sha"],BINDING["evidence_ref"],BINDING["lineage_ref"],BINDING["idempotency_key"],fence,runtime)

def test_execute_bridges_authorized_attempt_to_runtime(tmp_path):
    cid,pid=setup(tmp_path); result=_execute(tmp_path,cid,pid,GoodAdapter(),GoodRuntime()); assert result["state"]=="OBSERVED_SUCCESS"

def test_runtime_binding_mismatch_fails_closed_before_provider(tmp_path):
    cid,pid=setup(tmp_path)
    class BadRuntime(GoodRuntime):
        def submit(self, *, effect, attempt_id): return RuntimeSubmission(effect["effect_id"]+"-wrong",attempt_id,"fake-provider")
    class CountingAdapter(GoodAdapter):
        calls=0
        def execute(self, **kwargs): self.calls+=1; return super().execute(**kwargs)
    adapter=CountingAdapter()
    with pytest.raises(ValueError,match="effect mismatch"): _execute(tmp_path,cid,pid,adapter,BadRuntime())
    assert adapter.calls==0

def test_retry_bridges_explicit_bounded_retry(tmp_path):
    cid,pid=setup(tmp_path,max_attempts=2); effect=create_effect(str(tmp_path),cid,"op-1","agent:test",pid,"external_effect")
    effect=dispatch(str(tmp_path),effect["effect_id"],"agent:test",f"{effect['effect_id']}:attempt:1","fake-provider",**BINDING)
    effect=transition(str(tmp_path),effect["effect_id"],"UNKNOWN","agent:test",unknown_reason="timeout")
    result=execute_retry_attempt(str(tmp_path),cid,pid,effect,"agent:test",GoodAdapter(),f"{effect['effect_id']}:attempt:2",2,BINDING["target_sha"],2,GoodRuntime())
    assert result["state"]=="OBSERVED_SUCCESS" and result["attempt"]==2

def test_retry_runtime_cannot_override_contract_bounds(tmp_path):
    cid,pid=setup(tmp_path,max_attempts=1); effect=create_effect(str(tmp_path),cid,"op-1","agent:test",pid,"external_effect")
    effect=dispatch(str(tmp_path),effect["effect_id"],"agent:test",f"{effect['effect_id']}:attempt:1","fake-provider",**BINDING)
    effect=transition(str(tmp_path),effect["effect_id"],"UNKNOWN","agent:test",unknown_reason="timeout")
    with pytest.raises(PermissionError,match="max_attempts"):
        execute_retry_attempt(str(tmp_path),cid,pid,effect,"agent:test",GoodAdapter(),f"{effect['effect_id']}:attempt:2",2,BINDING["target_sha"],2,GoodRuntime())
    assert effect["state"]=="UNKNOWN"
