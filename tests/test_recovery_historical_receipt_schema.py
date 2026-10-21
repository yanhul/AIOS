import pytest

from core.durable_loop import LoopPolicy, _validate_loaded_state


def test_resume_rejects_historical_receipt_without_evidence():
    policy = LoopPolicy(
        max_steps=3,
        terminal_evaluator=lambda verification, state: None,
        action_authorizer=lambda decision, state: None,
        require_execution_receipt=True,
        execution_receipt_validator=lambda receipt, state: None,
        state_patch_validator=lambda patch, receipt, state: None,
    )
    state = {
        "step": 1,
        "status": "RUNNING",
        "history": [
            {
                "step": 1,
                "verification": {
                    "receipt": {
                        "effect_id": "effect-1",
                        "attempt_id": "attempt-1",
                        "status": "OBSERVED",
                    }
                },
            }
        ],
    }

    with pytest.raises(ValueError, match="evidence is missing or empty"):
        _validate_loaded_state(state, policy)
