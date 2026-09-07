import pytest
from adapters.minimind.contract import MINIMIND_CAPABILITY, validate_receipt

def receipt(**overrides):
    artifacts = {"workload_revision":"rev-1","dataset_digest":"sha256:data","tokenizer_digest":"sha256:tok","model_digest":"sha256:model","environment_digest":"sha256:env"}
    value = {"capability":MINIMIND_CAPABILITY,"task_id":"task-1","terminal_state":"INCONCLUSIVE","artifacts":artifacts,"evidence":{name:{**artifacts,"steps":1} for name in ("training_receipt","evaluation_receipt","provenance")}}
    value["evidence"]["evaluation_receipt"].update({"independent":True,"holdout":True})
    value.update(overrides)
    return value

def test_valid_learning_receipt(): assert validate_receipt(receipt())["task_id"] == "task-1"
def test_reward_only_cannot_promote():
    value=receipt(terminal_state="PROMOTE"); value["evidence"]["evaluation_receipt"]={"reward":2.9}
    with pytest.raises(ValueError,match="does not match declared artifact lineage"): validate_receipt(value)
def test_promotion_requires_locked_holdout():
    value=receipt(terminal_state="PROMOTE"); value["evidence"]["evaluation_receipt"]["holdout"]=False
    with pytest.raises(ValueError,match="holdout"): validate_receipt(value)
def test_missing_lineage_blocks():
    value=receipt(); del value["artifacts"]["dataset_digest"]
    with pytest.raises(ValueError,match="artifact lineage"): validate_receipt(value)
def test_wrong_capability_blocks():
    with pytest.raises(ValueError,match="capability"): validate_receipt(receipt(capability="minimind.learning@999"))
def test_evidence_artifact_binding_blocks_tampering():
    value=receipt(); value["evidence"]["evaluation_receipt"]["model_digest"]="sha256:attacker"
    with pytest.raises(ValueError,match="model_digest"): validate_receipt(value)
