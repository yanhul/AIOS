import pytest

from adapters.minimind.contract import MINIMIND_CAPABILITY, validate_receipt


def receipt(**overrides):
    value = {
        "capability": MINIMIND_CAPABILITY,
        "task_id": "task-1",
        "terminal_state": "INCONCLUSIVE",
        "artifacts": {
            "workload_revision": "rev-1",
            "dataset_digest": "sha256:data",
            "tokenizer_digest": "sha256:tok",
            "model_digest": "sha256:model",
            "environment_digest": "sha256:env",
        },
        "evidence": {
            "training_receipt": {"steps": 1},
            "evaluation_receipt": {"independent": True, "holdout": True},
            "provenance": {"source": "minimind"},
        },
    }
    value.update(overrides)
    return value


def test_valid_learning_receipt():
    assert validate_receipt(receipt())["task_id"] == "task-1"


def test_reward_only_cannot_promote():
    value = receipt(terminal_state="PROMOTE")
    value["evidence"]["evaluation_receipt"] = {"reward": 2.9}
    with pytest.raises(ValueError, match="independent"):
        validate_receipt(value)


def test_promotion_requires_locked_holdout():
    value = receipt(terminal_state="PROMOTE")
    value["evidence"]["evaluation_receipt"] = {"independent": True, "holdout": False}
    with pytest.raises(ValueError, match="holdout"):
        validate_receipt(value)


def test_missing_lineage_blocks():
    value = receipt()
    del value["artifacts"]["dataset_digest"]
    with pytest.raises(ValueError, match="artifact lineage"):
        validate_receipt(value)


def test_wrong_capability_blocks():
    with pytest.raises(ValueError, match="capability"):
        validate_receipt(receipt(capability="minimind.learning@999"))
