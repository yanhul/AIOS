# AIOS-CONTRACT: validates the fail-closed PCB/EDA receipt contract.
# AIOS-REGRESSION: protects capability, closure-gate, optimization, and operation binding.
# AIOS-OWNER: PCB/EDA domain adapter boundary.
# AIOS-COVERAGE-GAP: subprocess execution and full durable-runtime E2E are covered separately.
# AIOS-BASELINE: existing contract-test conventions; no source inspection required.

import pytest

from adapters.pcb_eda.contract import PCB_CAPABILITY, validate_receipt


def receipt(**overrides):
    value = {
        "capability": PCB_CAPABILITY,
        "task_id": "pcb-task-1",
        "operation": "audit",
        "terminal_state": "INCONCLUSIVE",
        "artifacts": {
            "input_digest": "sha256:input",
            "output_digest": "sha256:output",
            "workload_revision": "kit-rev-1",
        },
        "evidence": {
            "intake": {"status": "VERIFIED"},
            "connectivity": {"status": "VERIFIED"},
            "placement": {"status": "VERIFIED"},
            "routing": {"status": "VERIFIED", "optimization_status": "NOT_PROVEN"},
            "provenance": {"attempt_id": "a1", "effect_id": "e1"},
        },
    }
    value.update(overrides)
    return value


def test_valid_receipt():
    assert validate_receipt(receipt())["task_id"] == "pcb-task-1"


def test_wrong_capability_blocks():
    with pytest.raises(ValueError, match="capability"):
        validate_receipt(receipt(capability="pcb.eda@999"))


def test_pass_requires_all_closure_gates():
    value = receipt(terminal_state="PASS")
    value["evidence"]["routing"]["status"] = "UNKNOWN"
    with pytest.raises(ValueError, match="routing"):
        validate_receipt(value)


def test_optimization_pass_requires_verified_optimization():
    value = receipt(operation="optimize", terminal_state="PASS")
    value["evidence"]["routing"]["optimization_status"] = "NOT_PROVEN"
    with pytest.raises(ValueError, match="optimization_status"):
        validate_receipt(value)


def test_operation_binding():
    with pytest.raises(ValueError, match="operation"):
        validate_receipt(receipt(), expected_operation="repair")
