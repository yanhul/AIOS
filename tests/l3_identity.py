"""Test-only L3 operation identity hook (Decision A): stable per persisted step."""


def TEST_OPERATION_IDENTITY(decision, state):
    return {"contract_id": "CT-test-loop", "actor": "test-actor",
            "logical_operation_id": f"op-step-{state.get('step', 0)}"}
