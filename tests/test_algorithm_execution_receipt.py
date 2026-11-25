import copy
import hashlib

import pytest

from core.algorithm_execution_receipt import (
    AlgorithmExecutionReceiptError,
    verify_algorithm_execution_receipt,
)
from core.mutation import canonical_json


REVISION = "a" * 40
EXECUTOR_SHA = "b" * 64
SPEC = {"operation": "maze.shortest_path", "version": 1, "max_expansions": 1000}


def digest(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def make_receipt(grid=None, path=None):
    grid = grid or ["S..", ".#.", "..G"]
    path = path or [[0, 0], [0, 1], [0, 2], [1, 2], [2, 2]]
    candidate = {"path": path, "expansions": 8}
    receipt = {
        "schema": "try.algorithm-execution-receipt.v1",
        "spec": dict(SPEC),
        "spec_sha256": digest(SPEC),
        "input_sha256": digest(grid),
        "executor_revision": REVISION,
        "executor_sha256": EXECUTOR_SHA,
        "candidate": candidate,
        "candidate_sha256": digest(candidate),
        "verification": {"verified": True, "reason": "shortest_path_confirmed"},
        "decision": "VERIFIED",
        "promotion": "NOT_REQUESTED",
    }
    receipt["receipt_sha256"] = digest(receipt)
    return receipt


def verify(receipt, grid=None, **kwargs):
    return verify_algorithm_execution_receipt(
        receipt, grid=grid or ["S..", ".#.", "..G"], spec=SPEC,
        expected_executor_revision=kwargs.get("revision", REVISION),
        expected_executor_sha256=kwargs.get("executor_sha", EXECUTOR_SHA),
    )


def resign(receipt):
    receipt["receipt_sha256"] = digest({k: v for k, v in receipt.items() if k != "receipt_sha256"})
    return receipt


def test_independently_verifies_shortest_path_without_authorizing_promotion():
    result = verify(make_receipt())
    assert result["status"] == "INDEPENDENTLY_VERIFIED"
    assert result["oracle_distance"] == 4
    assert result["promotion"] == "NOT_AUTHORIZED"


def test_confirms_unreachable_maze():
    receipt = make_receipt(["S#G"], None)
    result = verify(receipt, ["S#G"])
    assert result["oracle_distance"] is None
    assert result["candidate_distance"] is None


@pytest.mark.parametrize("field,value", [
    ("input_sha256", "0" * 64),
    ("spec_sha256", "0" * 64),
    ("executor_revision", "c" * 40),
    ("executor_sha256", "0" * 64),
    ("candidate_sha256", "0" * 64),
    ("receipt_sha256", "0" * 64),
])
def test_digest_and_revision_tampering_fail_closed(field, value):
    receipt = make_receipt()
    receipt[field] = value
    with pytest.raises(AlgorithmExecutionReceiptError):
        verify(receipt)


def test_wrong_contract_pins_fail_closed():
    receipt = make_receipt()
    with pytest.raises(AlgorithmExecutionReceiptError, match="executor revision"):
        verify(receipt, revision="c" * 40)
    with pytest.raises(AlgorithmExecutionReceiptError, match="executor source digest"):
        verify(receipt, executor_sha="c" * 64)


def test_non_shortest_candidate_is_rejected_even_if_try_says_verified():
    receipt = make_receipt(path=[[0, 0], [1, 0], [2, 0], [2, 1], [2, 2], [1, 2], [0, 2]])
    resign(receipt)
    with pytest.raises(AlgorithmExecutionReceiptError, match="not a shortest path"):
        verify(receipt)


def test_forged_wall_crossing_candidate_is_rejected():
    receipt = make_receipt(path=[[0, 0], [0, 1], [1, 1], [2, 1], [2, 2]])
    resign(receipt)
    with pytest.raises(AlgorithmExecutionReceiptError, match="wall"):
        verify(receipt)


def test_promotion_claim_is_rejected_even_with_recomputed_checksum():
    receipt = make_receipt()
    receipt["promotion"] = "ABSORBED"
    resign(receipt)
    with pytest.raises(AlgorithmExecutionReceiptError, match="promotion"):
        verify(receipt)


def test_nested_try_verification_claim_is_not_trusted():
    receipt = make_receipt()
    receipt["verification"] = {"verified": False, "reason": "not checked"}
    resign(receipt)
    assert verify(receipt)["status"] == "INDEPENDENTLY_VERIFIED"


def test_wrong_input_and_specification_are_rejected():
    receipt = make_receipt()
    with pytest.raises(AlgorithmExecutionReceiptError, match="input digest"):
        verify(receipt, ["S.G"])
    with pytest.raises(AlgorithmExecutionReceiptError, match="specification binding"):
        verify_algorithm_execution_receipt(
            receipt, grid=["S..", ".#.", "..G"],
            spec={"operation": "python.eval", "version": 1, "max_expansions": 1000},
            expected_executor_revision=REVISION, expected_executor_sha256=EXECUTOR_SHA,
        )
