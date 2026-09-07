import json
import sys
import pytest
from adapters.minimind.runner import MiniMindAdapter

def _receipt():
    artifacts={"workload_revision":"rev-1","dataset_digest":"sha256:data","tokenizer_digest":"sha256:tok","model_digest":"sha256:model","environment_digest":"sha256:env"}
    return {"capability":"minimind.learning@1","task_id":"task-1","terminal_state":"INCONCLUSIVE","artifacts":artifacts,"evidence":{name:{**artifacts,"steps":1} for name in ("training_receipt","evaluation_receipt","provenance")}}
def _adapter(payload):
    code="import json,sys; print(json.dumps("+repr(payload)+"))"
    return MiniMindAdapter(command=[sys.executable,"-c",code])
def _contract(): return {"task_id":"task-1","capabilities":["minimind.learning@1"]}
def _effect(): return {"effect_id":"effect-1"}
def test_runner_accepts_valid_receipt_and_binds_operation():
    result=_adapter(_receipt()).execute(contract=_contract(),effect=_effect(),attempt_id="attempt-1")
    assert result.provider=="minimind" and result.outcome=="OBSERVED_SUCCESS" and result.effect_id=="effect-1" and result.attempt_id=="attempt-1"
    assert result.observation["minimind_receipt"]["terminal_state"]=="INCONCLUSIVE"
def test_runner_rejects_invalid_receipt():
    value=_receipt(); del value["artifacts"]["dataset_digest"]
    with pytest.raises(ValueError,match="artifact lineage"): _adapter(value).execute(contract=_contract(),effect=_effect(),attempt_id="attempt-1")
def test_runner_rejects_wrong_task_binding():
    value=_receipt(); value["task_id"]="other-task"
    with pytest.raises(ValueError,match="task binding"): _adapter(value).execute(contract=_contract(),effect=_effect(),attempt_id="attempt-1")
def test_runner_requires_minimind_capability():
    with pytest.raises(PermissionError,match="capability"): _adapter(_receipt()).execute(contract={"task_id":"task-1","capabilities":["other@1"]},effect=_effect(),attempt_id="attempt-1")
def test_runner_fails_closed_on_nonzero_exit():
    adapter=MiniMindAdapter(command=[sys.executable,"-c","raise SystemExit(7)"])
    with pytest.raises(RuntimeError,match="code 7"): adapter.execute(contract=_contract(),effect=_effect(),attempt_id="attempt-1")
def test_runner_preserves_workload_terminal_state_as_observation():
    value=_receipt(); value["terminal_state"]="REJECT"
    result=_adapter(value).execute(contract=_contract(),effect=_effect(),attempt_id="attempt-1")
    assert result.outcome=="OBSERVED_SUCCESS"
    assert result.observation["minimind_receipt"]["terminal_state"]=="REJECT"
