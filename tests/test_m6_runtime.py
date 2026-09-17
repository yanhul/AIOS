import os
import pytest

from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.effect_authority import create_effect, dispatch, retry_dispatch, transition
from core.evidence import EvidenceRecord
from core.policy_registry import persist_policy
from core.runtime import ProviderReceipt, execute, execute_attempt, execute_retry_attempt

BINDING = {"target_sha": "sha256:worker-v1", "evidence_ref": "EV-runtime-1", "lineage_ref": "LIN-runtime-1", "idempotency_key": "idem-runtime-1", "attempt_fence": 1}


def _evidence(provider="fake-provider"):
    return EvidenceRecord(evidence_id="EV-runtime-1", level="OBSERVED", source_ref="runtime/test", claim="provider completed operation", run_id="run-runtime-1", provider=provider).as_record()


def _gateway_kwargs(fence=1):
    return {**BINDING, "attempt_fence": fence}


def contract(policy_digest, max_attempts=1):
    return {"contract_type":"EXECUTION_CONTRACT", "task_id":"task-runtime", "scope":"runtime-test", "actor":"agent:test", "capabilities":["fake-provider@1"], "input_digest":"input-1", "allowed_effects":["external_effect"], "evidence_required":["provider_receipt"], "max_attempts":max_attempts, "terminal_states":["SUCCESS","FAILURE"], "policy_digest":policy_digest}


class GoodAdapter:
    name = "fake-provider"
    def execute(self, *, contract, effect, attempt_id):
        return ProviderReceipt(self.name, effect["effect_id"], attempt_id, "provider-op-1", "OBSERVED_SUCCESS", {"status":"ok", "evidence":_evidence(self.name)}, effect["target_sha"], effect["evidence_ref"], effect["lineage_ref"], effect["idempotency_key"], effect["attempt_fence"])


class BrokenAdapter:
    name = "fake-provider"
    def execute(self, *, contract, effect, attempt_id):
        raise TimeoutError("provider timed out")


def setup_authority(tmp_path, max_attempts=1):
    registry = CapabilityRegistry(); registry.register(Capability("fake-provider", "1", "test-fixture", "test", status="ACTIVE")); registry.persist(str(tmp_path), "test-fixture")
    policy = persist_policy(str(tmp_path), {"policy_type":"GOVERNING_POLICY","name":"runtime-fixture"})
    c = contract(policy, max_attempts); cid = contract_identity(c); persist_contract(str(tmp_path), c); permit = persist_permit(str(tmp_path), c, "root")
    return c, cid, permit["permit_id"]


def _execute(tmp_path, cid, pid, adapter, runtime=None, fence=1):
    return execute(str(tmp_path), cid, pid, "op-1", "agent:test", adapter, BINDING["target_sha"], BINDING["evidence_ref"], BINDING["lineage_ref"], BINDING["idempotency_key"], fence, runtime)


def test_runtime_success_is_explicitly_observed(tmp_path):
    _, cid, pid = setup_authority(tmp_path)
    result = _execute(tmp_path, cid, pid, GoodAdapter())
    assert result["state"] == "OBSERVED_SUCCESS"; assert result["provider_observation"]["provider_operation_id"] == "provider-op-1"


def test_provider_timeout_becomes_unknown(tmp_path):
    _, cid, pid = setup_authority(tmp_path)
    result = _execute(tmp_path, cid, pid, BrokenAdapter())
    assert result["state"] == "UNKNOWN"; assert "TimeoutError" in result["unknown_reason"]


def test_unauthorized_provider_is_rejected_before_call(tmp_path):
    _, cid, pid = setup_authority(tmp_path)
    class Unauthorized:
        name = "not-authorized"
        def execute(self, **kwargs): pytest.fail("provider must not be called")
    with pytest.raises(PermissionError): _execute(tmp_path, cid, pid, Unauthorized())
    assert not os.path.exists(os.path.join(str(tmp_path), "effects"))


def test_mismatched_receipt_is_protocol_failure_not_unknown(tmp_path):
    _, cid, pid = setup_authority(tmp_path)
    class BadReceipt:
        name = "fake-provider"
        def execute(self, *, contract, effect, attempt_id):
            return ProviderReceipt(self.name, effect["effect_id"] + "-wrong", attempt_id, "provider-op-2", "OBSERVED_SUCCESS", {"status":"ok", "evidence":_evidence(self.name)}, effect["target_sha"], effect["evidence_ref"], effect["lineage_ref"], effect["idempotency_key"], effect["attempt_fence"])
    with pytest.raises(ValueError, match="binding mismatch"):
        _execute(tmp_path, cid, pid, BadReceipt())


def test_execute_attempt_runs_only_a_dispatched_attempt(tmp_path):
    c, cid, pid = setup_authority(tmp_path)
    effect = create_effect(str(tmp_path), cid, "op-1", "agent:test", pid, "external_effect")
    attempt_id = f"{effect['effect_id']}:attempt:1"
    effect = dispatch(str(tmp_path), effect["effect_id"], "agent:test", attempt_id, "fake-provider", **BINDING)
    result = execute_attempt(str(tmp_path), c, effect, "agent:test", GoodAdapter(), attempt_id)
    assert result["state"] == "OBSERVED_SUCCESS"


def test_execute_attempt_rejects_non_dispatched_effect(tmp_path):
    c, cid, pid = setup_authority(tmp_path)
    effect = create_effect(str(tmp_path), cid, "op-1", "agent:test", pid, "external_effect")
    with pytest.raises(RuntimeError, match="DISPATCHED"):
        execute_attempt(str(tmp_path), c, effect, "agent:test", GoodAdapter(), f"{effect['effect_id']}:attempt:1")


def test_execute_attempt_does_not_authorize_or_create_effect(tmp_path):
    c, cid, pid = setup_authority(tmp_path)
    effect = create_effect(str(tmp_path), cid, "op-1", "agent:test", pid, "external_effect")
    attempt_id = f"{effect['effect_id']}:attempt:1"
    effect = dispatch(str(tmp_path), effect["effect_id"], "agent:test", attempt_id, "fake-provider", **BINDING)
    class CountingAdapter(GoodAdapter):
        calls = 0
        def execute(self, **kwargs): self.calls += 1; return super().execute(**kwargs)
    adapter = CountingAdapter(); result = execute_attempt(str(tmp_path), c, effect, "agent:test", adapter, attempt_id)
    assert result["state"] == "OBSERVED_SUCCESS" and adapter.calls == 1


def test_retry_dispatch_requires_unknown_and_increments_attempt(tmp_path):
    _, cid, pid = setup_authority(tmp_path, max_attempts=3)
    effect = create_effect(str(tmp_path), cid, "op-1", "agent:test", pid, "external_effect")
    first = dispatch(str(tmp_path), effect["effect_id"], "agent:test", f"{effect['effect_id']}:attempt:1", "fake-provider", **BINDING)
    unknown_effect = transition(str(tmp_path), first["effect_id"], "UNKNOWN", "agent:test", unknown_reason="timeout")
    retried = retry_dispatch(str(tmp_path), unknown_effect["effect_id"], "agent:test", f"{effect['effect_id']}:attempt:2", "fake-provider", 2, target_sha=BINDING["target_sha"], attempt_fence=2)
    assert retried["attempt"] == 2 and retried["state"] == "DISPATCHED"


def test_generic_transition_cannot_turn_unknown_into_dispatched(tmp_path):
    _, cid, pid = setup_authority(tmp_path, max_attempts=3)
    effect = create_effect(str(tmp_path), cid, "op-1", "agent:test", pid, "external_effect")
    effect = dispatch(str(tmp_path), effect["effect_id"], "agent:test", f"{effect['effect_id']}:attempt:1", "fake-provider", **BINDING)
    effect = transition(str(tmp_path), effect["effect_id"], "UNKNOWN", "agent:test", unknown_reason="timeout")
    with pytest.raises(Exception, match="undefined external-effect transition"):
        transition(str(tmp_path), effect["effect_id"], "DISPATCHED", "agent:test", attempt=2, attempt_id=f"{effect['effect_id']}:attempt:2", provider="fake-provider")


def test_execute_retry_attempt_is_bounded_by_contract(tmp_path):
    c, cid, pid = setup_authority(tmp_path, max_attempts=2)
    effect = create_effect(str(tmp_path), cid, "op-1", "agent:test", pid, "external_effect")
    effect = dispatch(str(tmp_path), effect["effect_id"], "agent:test", f"{effect['effect_id']}:attempt:1", "fake-provider", **BINDING)
    effect = transition(str(tmp_path), effect["effect_id"], "UNKNOWN", "agent:test", unknown_reason="timeout")
    result = execute_retry_attempt(str(tmp_path), cid, pid, effect, "agent:test", GoodAdapter(), f"{effect['effect_id']}:attempt:2", 2, BINDING["target_sha"], 2)
    assert result["state"] == "OBSERVED_SUCCESS" and result["attempt"] == 2


def test_execute_retry_attempt_rejects_over_max_before_dispatch(tmp_path):
    _, cid, pid = setup_authority(tmp_path, max_attempts=1)
    effect = create_effect(str(tmp_path), cid, "op-1", "agent:test", pid, "external_effect")
    effect = dispatch(str(tmp_path), effect["effect_id"], "agent:test", f"{effect['effect_id']}:attempt:1", "fake-provider", **BINDING)
    effect = transition(str(tmp_path), effect["effect_id"], "UNKNOWN", "agent:test", unknown_reason="timeout")
    with pytest.raises(PermissionError, match="max_attempts"):
        execute_retry_attempt(str(tmp_path), cid, pid, effect, "agent:test", GoodAdapter(), f"{effect['effect_id']}:attempt:2", 2, BINDING["target_sha"], 2)
    assert effect["state"] == "UNKNOWN"
