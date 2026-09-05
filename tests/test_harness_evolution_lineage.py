import pytest

from core.harness_evolution_lineage import EvolutionLineage, make_lineage


def test_pass_lineage_is_rollbackable_and_requires_evidence():
    record = make_lineage(
        change_id="chg-1",
        parent_digest="parent",
        candidate_digest="candidate",
        prediction="score improves",
        policy_digest="policy-v1",
        holdout_digest="holdout-v1",
        observed_prediction="score improves",
        decision="PASS",
        evidence_refs=("ev-1",),
        verification_refs=("ver-1",),
    )
    assert record.rollback_target == "parent"
    assert record.promotable is True
    assert record.artifact()["candidate_digest"] == "candidate"


def test_pass_without_evidence_is_not_promotable():
    record = make_lineage(
        change_id="chg-2",
        parent_digest="parent",
        candidate_digest="candidate",
        prediction="x",
        policy_digest="policy-v1",
        holdout_digest="holdout-v1",
        observed_prediction="x",
        decision="PASS",
    )
    assert record.rollback_target == "parent"
    assert record.promotable is False


def test_blocked_has_no_rollback_or_promotion():
    record = make_lineage(
        change_id="chg-3",
        parent_digest="parent",
        candidate_digest="candidate",
        prediction="x",
        policy_digest="policy-v1",
        holdout_digest="holdout-v1",
        observed_prediction="y",
        decision="BLOCKED",
    )
    assert record.rollback_target is None
    assert record.promotable is False


def test_invalid_terminal_is_rejected():
    with pytest.raises(ValueError, match="decision"):
        make_lineage(
            change_id="chg-4",
            parent_digest="parent",
            candidate_digest="candidate",
            prediction="x",
            policy_digest="policy-v1",
            holdout_digest="holdout-v1",
            observed_prediction="x",
            decision="PROMOTE",
        )


def test_pass_must_have_parent_rollback_target():
    with pytest.raises(ValueError):
        EvolutionLineage(
            change_id="chg-5",
            parent_digest="parent",
            candidate_digest="candidate",
            prediction="x",
            policy_digest="policy-v1",
            holdout_digest="holdout-v1",
            observed_prediction="x",
            decision="PASS",
            evidence_refs=("ev",),
            verification_refs=("ver",),
            rollback_target="other",
        )
