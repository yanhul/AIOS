from core.promotion import PromotionPolicy, evaluate_promotion


def test_promotion_requires_independent_evaluation_when_policy_demands_it():
    policy = PromotionPolicy("p1", require_independent_evaluation=True)
    blocked = evaluate_promotion(policy=policy, policy_digest="p1", terminal="PASS", evidence=[], independent_evaluation=None)
    passed = evaluate_promotion(
        policy=policy,
        policy_digest="p1",
        terminal="PASS",
        evidence=[],
        independent_evaluation={"decision": "PASS", "holdout_digest": "h1"},
    )
    assert blocked["decision"] == "BLOCKED"
    assert passed["decision"] == "PROMOTED"
