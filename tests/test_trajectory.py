import pytest

from core.trajectory import verify_trajectory


def record(step, verification=None):
    return {
        "step": step,
        "observation": {"value": step},
        "decision": {"operation": f"op-{step}"},
        "action": {"effect_id": f"effect-{step}"},
        "verification": verification if verification is not None else {"verified": True},
    }


def test_trajectory_verification_accepts_contiguous_records():
    result = verify_trajectory(
        [record(1, {"verified": True, "evidence_ref": "e1"}), record(2, {"verified": True, "evidence_ref": "e2"})],
        max_steps=3,
        required_verification_fields=("verified", "evidence_ref"),
    )
    assert result["verified"] is True
    assert result["record_count"] == 2
    assert result["last_step"] == 2


def test_trajectory_verification_rejects_step_gaps():
    with pytest.raises(ValueError, match="step discontinuity"):
        verify_trajectory([record(1), record(3)], max_steps=3)


def test_trajectory_verification_rejects_missing_structural_record_field():
    broken = record(1)
    del broken["authorization"] if "authorization" in broken else broken["action"]
    with pytest.raises(ValueError, match="missing fields"):
        verify_trajectory([broken], max_steps=1)


def test_trajectory_verification_rejects_missing_required_verification():
    with pytest.raises(ValueError, match="required field"):
        verify_trajectory([record(1, {"verified": True})], max_steps=1,
                          required_verification_fields=("evidence_ref",))


def test_trajectory_verification_rejects_budget_overrun():
    with pytest.raises(ValueError, match="step budget"):
        verify_trajectory([record(1), record(2)], max_steps=1)
