import pytest

from core.authority import persist_contract, persist_permit
from core.contract import contract_identity
from core.effect_authority import load_effects
from core.runtime import ProviderReceipt, execute


def contract():
    return {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": "task-runtime",
        "scope": "runtime-test",
        "actor": "agent:test",
        "capabilities": ["fake-provider"],
        "input_digest": "input-1",
        "allowed_effects": ["external_effect"],
        "evidence_required": ["provider_receipt"],
        "max_attempts": 1,
        "terminal_states": ["SUCCESS", "FAILURE"],
        "policy_digest": "policy-1",
    }


class GoodAdapter:
    name = "fake-provider"

    def execute(self, *, contract, effect, attempt_id):
        return ProviderReceipt(
            provider=self.name,
            effect_id=effect["effect_id"],
            attempt_id=attempt_id,
            provider_operation_id="provider-op-1",
            outcome="OBSERVED_SUCCESS",
            observation={"status": "ok"},
        )


class BrokenAdapter:
    name = "fake-provider"

    def execute(self, *, contract, effect, attempt_id):
        raise TimeoutError("provider timed out")


def setup_authority(tmp_path):
    c = contract()
    cid = contract_identity(c)
    persist_contract(str(tmp_path), c)
    permit = persist_permit(str(tmp_path), c, "root")
    return cid, permit["permit_id"]


def test_runtime_success_is_explicitly_observed(tmp_path):
    cid, pid = setup_authority(tmp_path)
    result = execute(str(tmp_path), cid, pid, "op-1", "agent:test", GoodAdapter())
    assert result["state"] == "OBSERVED_SUCCESS"
    assert result["provider_observation"]["provider_operation_id"] == "provider-op-1"


def test_provider_timeout_becomes_unknown(tmp_path):
    cid, pid = setup_authority(tmp_path)
    result = execute(str(tmp_path), cid, pid, "op-1", "agent:test", BrokenAdapter())
    assert result["state"] == "UNKNOWN"
    assert "TimeoutError" in result["unknown_reason"]


def test_unauthorized_provider_is_rejected_before_call(tmp_path):
    cid, pid = setup_authority(tmp_path)

    class Unauthorized:
        name = "not-authorized"
        def execute(self, **kwargs):
            pytest.fail("provider must not be called")

    with pytest.raises(PermissionError):
        execute(str(tmp_path), cid, pid, "op-1", "agent:test", Unauthorized())
    assert load_effects(str(tmp_path)) == []


def test_mismatched_receipt_becomes_unknown(tmp_path):
    cid, pid = setup_authority(tmp_path)

    class BadReceipt:
        name = "fake-provider"
        def execute(self, *, contract, effect, attempt_id):
            return ProviderReceipt(
                provider=self.name,
                effect_id=effect["effect_id"] + "-wrong",
                attempt_id=attempt_id,
                provider_operation_id="provider-op-2",
                outcome="OBSERVED_SUCCESS",
                observation={"status": "ok"},
            )

    result = execute(str(tmp_path), cid, pid, "op-1", "agent:test", BadReceipt())
    assert result["state"] == "UNKNOWN"
    assert "binding mismatch" in result["unknown_reason"]
