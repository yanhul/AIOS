import pytest

from core.durable_runtime import RuntimeSubmission, validate_submission


def effect():
    return {"effect_id": "E-1"}


def test_submission_binds_effect_and_attempt():
    validate_submission(effect(), RuntimeSubmission("E-1", "E-1:attempt:2", "temporal"), "E-1:attempt:2")


@pytest.mark.parametrize(
    "submission,attempt,error",
    [
        (RuntimeSubmission("E-2", "E-1:attempt:2", "temporal"), "E-1:attempt:2", "effect mismatch"),
        (RuntimeSubmission("E-1", "E-1:attempt:1", "temporal"), "E-1:attempt:2", "attempt mismatch"),
        (RuntimeSubmission("E-1", "E-1:attempt:2", ""), "E-1:attempt:2", "provider missing"),
    ],
)
def test_submission_mismatch_fails_closed(submission, attempt, error):
    with pytest.raises(ValueError, match=error):
        validate_submission(effect(), submission, attempt)
