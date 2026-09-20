import pytest

from core.evaluation_plane import ExecutionReceipt, evaluate_receipt


def _receipt(status="OBSERVED"):
    return ExecutionReceipt(
        effect_id="effect-1",
        attempt_id="attempt-1",
        status=status,
        evidence={"test": {"ok": True}},
    )


def _evaluate(receipt=None, **kwargs):
    return evaluate_receipt(
        receipt or _receipt(),
        evaluation_id="eval-1",
        receipt_id="receipt-1",
        evaluator_version="evaluator-v1",
        rubric_version="rubric-v1",
        verdict="PASS",
        result={"score": 1},
        evidence_refs=("test",),
        **kwargs,
    )


def test_evaluation_binds_exact_execution_lineage():
    record = _evaluate()
    assert record.effect_id == "effect-1"
    assert record.attempt_id == "attempt-1"
    assert record.receipt_id == "receipt-1"


def test_unknown_receipt_cannot_be_evaluated():
    with pytest.raises(ValueError, match="UNKNOWN"):
        _evaluate(_receipt("UNKNOWN"))


def test_missing_evidence_cannot_be_repaired_by_evaluator():
    with pytest.raises(ValueError, match="evidence_refs"):
        evaluate_receipt(
            _receipt(),
            evaluation_id="eval-1",
            receipt_id="receipt-1",
            evaluator_version="evaluator-v1",
            rubric_version="rubric-v1",
            verdict="PASS",
            result={"score": 1},
            evidence_refs=("invented",),
        )


def test_receipt_is_immutable_after_creation():
    receipt = _receipt()
    with pytest.raises(Exception):
        receipt.status = "UNKNOWN"
    with pytest.raises(TypeError):
        receipt.evidence["test"] = {"forged": True}


def test_evaluation_is_immutable_after_creation():
    record = _evaluate()
    with pytest.raises(Exception):
        record.verdict = "PASS_WITH_AUTHORITY"
    with pytest.raises(TypeError):
        record.result["authority"] = True


def test_evaluation_cannot_bind_a_different_attempt():
    receipt = _receipt()
    record = _evaluate(receipt)
    assert record.attempt_id == receipt.attempt_id
    assert record.effect_id == receipt.effect_id
