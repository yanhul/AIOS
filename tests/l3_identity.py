# AIOS-CONTRACT: test-only L3 operation identity hook, stable per persisted step.
# AIOS-REGRESSION: Decision A requires operation_identity for receipt-governed loops.
# AIOS-OWNER: AIOS control-plane durable execution (L3)
# AIOS-COVERAGE-GAP: Test helper only; no assertions by design.
# AIOS-BASELINE: Used by tests/test_durable_loop*.py.
"""Test-only L3 operation identity hook (Decision A): stable per persisted step."""


def TEST_OPERATION_IDENTITY(decision, state):
    return {"contract_id": "CT-test-loop", "actor": "test-actor",
            "logical_operation_id": f"op-step-{state.get('step', 0)}"}
