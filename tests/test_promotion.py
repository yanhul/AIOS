import pytest

from core.promotion import PromotionError, PromotionPolicy, evaluate_promotion


def test_promotion_requires_pass_and_policy_binding():
    policy = PromotionPolicy("p1", required_evidence=("EV-1",), required_verification_levels=("VERIFIED_DIGITAL",))
    assert evaluate_promotion(
        policy=policy, policy_digest="wrong", terminal="PASS",
        evidence=[{"ref": "EV-1", "verification_level": "VERIFIED_DIGITAL"}],
    )["decision"] == "BLOCKED"
    assert evaluate_promotion(
        policy=policy, policy_digest="p1", terminal="INCONCLUSIVE", evidence=[],
    )["decision"] == "INCONCLUSIVE"


def test_promotion_blocks_missing_evidence_and_unresolved_contradictions():
    policy = PromotionPolicy("p1", required_evidence=("EV-1",), required_verification_levels=("VERIFIED_DIGITAL",))
    missing = evaluate_promotion(
        policy=policy, policy_digest="p1", terminal="PASS",
        evidence=[{"ref": "EV-2", "verification_level": "VERIFIED_DIGITAL"}],
    )
    assert missing["decision"] == "BLOCKED"

    contradiction = evaluate_promotion(
        policy=policy, policy_digest="p1", terminal="PASS",
        evidence=[{"ref": "EV-1", "verification_level": "VERIFIED_DIGITAL"}],
        contradictions=[{"status": "unresolved"}],
    )
    assert contradiction["decision"] == "BLOCKED"


def test_promotion_only_after_all_gates():
    policy = PromotionPolicy("p1", required_evidence=("EV-1",), required_verification_levels=("VERIFIED_DIGITAL",))
    result = evaluate_promotion(
        policy=policy, policy_digest="p1", terminal="PASS",
        evidence=[{"ref": "EV-1", "verification_level": "VERIFIED_DIGITAL"}],
    )
    assert result["decision"] == "PROMOTED"


def test_unknown_verification_level_is_rejected_at_policy_creation():
    with pytest.raises(PromotionError):
        PromotionPolicy("p1", required_verification_levels=("TRUSTED",))
