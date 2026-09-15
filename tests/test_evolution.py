import pytest

from core.evolution import (
    Candidate,
    EvaluationEvidence,
    MemoryCandidateStore,
    admit,
    promote,
    record_evaluation,
    transition,
)


def _candidate():
    return Candidate(candidate_id="c1", parent_id=None, artifact_ref="artifact:c1")


def _evidence(digest="eval-v1", held_in_status="PASS", held_out_status="PASS"):
    return EvaluationEvidence(
        evaluator_digest=digest,
        held_in={"status": held_in_status, "metric": 1.2},
        held_out={"status": held_out_status, "metric": 1.1},
        evidence_refs=("receipt:r1",),
    )


def _evaluated(evidence=None):
    candidate = transition(_candidate(), "CANDIDATE")
    candidate = transition(candidate, "CHALLENGER")
    return record_evaluation(candidate, evidence or _evidence(), evaluator_digest="eval-v1")


def test_candidate_progresses_through_governed_states():
    candidate = admit(_evaluated())
    candidate = promote(candidate, authorize=lambda _: None)
    assert candidate.state == "ACTIVE"
    assert candidate.evaluation is not None


def test_invalid_transition_is_blocked():
    with pytest.raises(ValueError, match="unauthorized transition"):
        transition(_candidate(), "ACTIVE")


def test_evaluator_digest_is_authoritative():
    candidate = transition(_candidate(), "CANDIDATE")
    candidate = transition(candidate, "CHALLENGER")
    with pytest.raises(ValueError, match="unauthorized evaluator"):
        record_evaluation(candidate, _evidence("wrong"), evaluator_digest="eval-v1")


def test_held_out_evidence_is_required():
    with pytest.raises(ValueError, match="held_out evidence"):
        EvaluationEvidence(
            evaluator_digest="eval-v1",
            held_in={"status": "PASS"},
            held_out={},
            evidence_refs=("receipt:r1",),
        )


def test_admission_requires_both_held_sets_to_pass():
    with pytest.raises(ValueError, match="held-out evidence"):
        admit(_evaluated(_evidence(held_out_status="FAIL")))
    with pytest.raises(ValueError, match="held-in evidence"):
        admit(_evaluated(_evidence(held_in_status="FAIL")))


def test_direct_evaluated_to_promotable_transition_is_blocked():
    with pytest.raises(ValueError, match="unauthorized transition"):
        transition(_evaluated(), "PROMOTABLE")


def test_promotion_requires_external_authority():
    candidate = admit(_evaluated())
    calls = []

    def deny(candidate):
        calls.append(candidate.candidate_id)
        raise PermissionError("promotion denied")

    with pytest.raises(PermissionError, match="promotion denied"):
        promote(candidate, authorize=deny)
    assert calls == ["c1"]


def test_store_does_not_accept_lineage_rollback():
    store = MemoryCandidateStore()
    store.save(Candidate("c1", None, "artifact:c1", lineage_depth=2))
    with pytest.raises(ValueError, match="lineage depth"):
        store.save(Candidate("c1", None, "artifact:c1", lineage_depth=1))
