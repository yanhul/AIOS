import json
import sys

from adapters.process import SubprocessAdapter
from core.authority import persist_contract, persist_permit
from core.contract import contract_identity
from core.runtime import execute


def make_contract():
    return {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": "task-process",
        "scope": "process-test",
        "actor": "agent:test",
        "capabilities": ["process-provider@1"],
        "input_digest": "input-1",
        "allowed_effects": ["external_effect"],
        "evidence_required": ["provider_receipt"],
        "max_attempts": 1,
        "terminal_states": ["SUCCESS", "FAILURE"],
        "policy_digest": "policy-1",
    }


def setup(tmp_path):
    contract = make_contract()
    cid = contract_identity(contract)
    persist_contract(str(tmp_path), contract)
    permit = persist_permit(str(tmp_path), contract, "root")
    return cid, permit["permit_id"]


def test_subprocess_adapter_returns_bound_receipt(tmp_path):
    cid, pid = setup(tmp_path)
    code = (
        "import json,sys; r=json.load(sys.stdin); "
        "print(json.dumps({'provider':'process-provider','effect_id':r['effect']['effect_id'],"
        "'attempt_id':r['attempt_id'],'provider_operation_id':'proc-1',"
        "'outcome':'OBSERVED_SUCCESS','observation':{'exit':0}}))"
    )
    adapter = SubprocessAdapter("process-provider", [sys.executable, "-c", code])
    result = execute(str(tmp_path), cid, pid, "op-1", "agent:test", adapter)
    assert result["state"] == "OBSERVED_SUCCESS"
    assert result["provider_observation"]["provider_operation_id"] == "proc-1"


def test_subprocess_malformed_output_becomes_unknown(tmp_path):
    cid, pid = setup(tmp_path)
    adapter = SubprocessAdapter("process-provider", [sys.executable, "-c", "print('not-json')"])
    result = execute(str(tmp_path), cid, pid, "op-1", "agent:test", adapter)
    assert result["state"] == "UNKNOWN"
    assert "JSON" in result["unknown_reason"]


def test_subprocess_timeout_becomes_unknown(tmp_path):
    cid, pid = setup(tmp_path)
    code = "import time; time.sleep(1)"
    adapter = SubprocessAdapter("process-provider", [sys.executable, "-c", code], timeout_seconds=0.05)
    result = execute(str(tmp_path), cid, pid, "op-1", "agent:test", adapter)
    assert result["state"] == "UNKNOWN"
    assert "timed out" in result["unknown_reason"]


def test_subprocess_output_limit_becomes_unknown(tmp_path):
    cid, pid = setup(tmp_path)
    code = "print('x' * 10000)"
    adapter = SubprocessAdapter("process-provider", [sys.executable, "-c", code], max_output_bytes=128)
    result = execute(str(tmp_path), cid, pid, "op-1", "agent:test", adapter)
    assert result["state"] == "UNKNOWN"
    assert "output limit" in result["unknown_reason"]


def test_subprocess_command_is_not_shell_interpolated(tmp_path):
    cid, pid = setup(tmp_path)
    code = "import json,sys; r=json.load(sys.stdin); print(json.dumps({'provider':'process-provider','effect_id':r['effect']['effect_id'],'attempt_id':r['attempt_id'],'provider_operation_id':'proc-safe','outcome':'OBSERVED_SUCCESS','observation':{'safe':True}}))"
    adapter = SubprocessAdapter(
        "process-provider",
        [sys.executable, "-c", code, "literal;not;a;shell;command"],
    )
    result = execute(str(tmp_path), cid, pid, "op-1", "agent:test", adapter)
    assert result["state"] == "OBSERVED_SUCCESS"
