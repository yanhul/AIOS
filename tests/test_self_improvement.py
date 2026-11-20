import hashlib
import json

import pytest

from core.experience_memory import (
    ExperienceError,
    load_experiences,
    record_experience,
)
from core.capability_versions import (
    CapabilityEvolutionError,
    active_version,
    evaluate_candidate,
    load_candidates,
    load_decisions,
    promote_candidate,
    propose_candidate,
    rollback_capability,
)


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def state_dir(tmp_path):
    return str(tmp_path / ".aios")


def experience_args(**overrides):
    values = {
        "capability_id": "research.deep",
        "capability_version": "1.0.0",
        "task_id": "task-001",
        "outcome": "BLOCKED",
        "contributor": "agent-a",
        "evidence_refs": ["EV-1", "LOG-1"],
        "run_id": "run-123",
        "source_commit": "a" * 40,
        "artifact_digest": sha("artifact"),
        "actor": "aios-ledger",
    }
    values.update(overrides)
    return values


def candidate_args(**overrides):
    values = {
        "capability_id": "research.deep",
        "base_version": "1.0.0",
        "candidate_version": "1.1.0",
        "proposer": "agent-proposer",
        "source_commit": "b" * 40,
        "patch_digest": sha("patch"),
        "change_summary": "Improve source reconciliation",
        "evidence_refs": ["EV-CANDIDATE-1"],
        "run_id": "run-candidate-1",
        "actor": "aios-ledger",
    }
    values.update(overrides)
    return values


def test_negative_experience_is_persisted_and_replay_is_idempotent(tmp_path):
    root = state_dir(tmp_path)
    first = record_experience(root, **experience_args())
    second = record_experience(root, **experience_args())
    records = load_experiences(root)
    assert first["outcome"] == "BLOCKED"
    assert first["replayed"] is False
    assert second["replayed"] is True
    assert len(records) == 1
    assert next(iter(records.values()))["outcome"] == "BLOCKED"


def test_pass_experience_requires_exact_execution_and_verification_lineage(tmp_path):
    with pytest.raises(ExperienceError, match="effect_id"):
        record_experience(state_dir(tmp_path), **experience_args(outcome="PASS"))


def test_pass_experience_rejects_self_verification(tmp_path):
    with pytest.raises(ExperienceError, match="self-verification"):
        record_experience(
            state_dir(tmp_path),
            **experience_args(
                outcome="PASS", effect_id="EF-1", attempt_id="AT-1", receipt_id="RC-1",
                verifier="agent-a", evaluation_id="EVL-1", verification_status="VERIFIED_DIGITAL",
            ),
        )


def test_pass_experience_accepts_complete_independent_lineage(tmp_path):
    root = state_dir(tmp_path)
    result = record_experience(
        root,
        **experience_args(
            outcome="PASS", effect_id="EF-1", attempt_id="AT-1", receipt_id="RC-1",
            verifier="independent-verifier", evaluation_id="EVAL-1",
            verification_status="VERIFIED_DIGITAL",
        ),
    )
    stored = load_experiences(root)[result["experience_id"]]
    assert stored["effect_id"] == "EF-1"
    assert stored["attempt_id"] == "AT-1"
    assert stored["receipt_id"] == "RC-1"
    assert stored["verification_status"] == "VERIFIED_DIGITAL"


def test_experience_tampering_is_detected(tmp_path):
    root = state_dir(tmp_path)
    result = record_experience(root, **experience_args())
    path = tmp_path / ".aios" / "experiences" / f"{result['experience_id']}.json"
    record = json.loads(path.read_text())
    record["outcome"] = "PASS"
    path.write_text(json.dumps(record))
    with pytest.raises(Exception, match="identity"):
        load_experiences(root)


def test_candidate_is_not_active_until_independent_evaluation_and_authority(tmp_path):
    root = state_dir(tmp_path)
    proposed = propose_candidate(root, **candidate_args())
    candidate_id = proposed["candidate_id"]
    assert active_version(root, "research.deep", "1.0.0") == "1.0.0"
    with pytest.raises(CapabilityEvolutionError, match="no independent evaluation"):
        promote_candidate(
            root, candidate_id=candidate_id, approver="approver",
            evidence_verifier=lambda refs: True,
            promotion_authorizer=lambda candidate, evaluation, actor: True,
        )


def test_candidate_proposer_cannot_evaluate_own_patch(tmp_path):
    root = state_dir(tmp_path)
    candidate_id = propose_candidate(root, **candidate_args())["candidate_id"]
    with pytest.raises(CapabilityEvolutionError, match="cannot evaluate"):
        evaluate_candidate(
            root, candidate_id=candidate_id, evaluator="agent-proposer",
            evaluator_version="verifier@1", verdict="PASS",
            test_suite_digest=sha("tests"), comparison_digest=sha("comparison"),
            evidence_refs=["EV-EVAL-1"], run_id="run-eval", actor="aios-ledger",
        )


def test_promotion_requires_three_distinct_identities_and_exact_true_callbacks(tmp_path):
    root = state_dir(tmp_path)
    candidate_id = propose_candidate(root, **candidate_args())["candidate_id"]
    evaluate_candidate(
        root, candidate_id=candidate_id, evaluator="independent-evaluator",
        evaluator_version="verifier@1", verdict="PASS",
        test_suite_digest=sha("tests"), comparison_digest=sha("comparison"),
        evidence_refs=["EV-EVAL-1"], run_id="run-eval", actor="aios-ledger",
    )
    with pytest.raises(CapabilityEvolutionError, match="three distinct"):
        promote_candidate(
            root, candidate_id=candidate_id, approver="independent-evaluator",
            evidence_verifier=lambda refs: True,
            promotion_authorizer=lambda candidate, evaluation, actor: True,
        )
    with pytest.raises(CapabilityEvolutionError, match="not independently verified"):
        promote_candidate(
            root, candidate_id=candidate_id, approver="independent-approver",
            evidence_verifier=lambda refs: None,
            promotion_authorizer=lambda candidate, evaluation, actor: True,
        )
    with pytest.raises(PermissionError, match="denied"):
        promote_candidate(
            root, candidate_id=candidate_id, approver="independent-approver",
            evidence_verifier=lambda refs: True,
            promotion_authorizer=lambda candidate, evaluation, actor: None,
        )


def test_promotion_and_rollback_are_append_only_and_authorized(tmp_path):
    root = state_dir(tmp_path)
    candidate_id = propose_candidate(root, **candidate_args())["candidate_id"]
    evaluation = evaluate_candidate(
        root, candidate_id=candidate_id, evaluator="independent-evaluator",
        evaluator_version="verifier@1", verdict="PASS",
        test_suite_digest=sha("tests"), comparison_digest=sha("comparison"),
        evidence_refs=["EV-EVAL-1"], run_id="run-eval", actor="aios-ledger",
    )
    promoted = promote_candidate(
        root, candidate_id=candidate_id, approver="independent-approver",
        evidence_verifier=lambda refs: True,
        promotion_authorizer=lambda candidate, evaluation_record, actor: True,
    )
    assert promoted["status"] == "PROMOTED"
    assert active_version(root, "research.deep") == "1.1.0"
    rollback = rollback_capability(
        root, capability_id="research.deep", target_version="1.0.0",
        approver="release-manager", evidence_verifier=lambda refs: True,
        rollback_authorizer=lambda capability, current, target: True,
    )
    assert rollback["status"] == "ROLLED_BACK"
    assert active_version(root, "research.deep") == "1.0.0"
    assert len(load_decisions(root)) == 2


def test_failed_latest_evaluation_blocks_promotion(tmp_path):
    root = state_dir(tmp_path)
    candidate_id = propose_candidate(root, **candidate_args())["candidate_id"]
    for verdict, run_id in [("PASS", "run-1"), ("FAIL", "run-2")]:
        evaluate_candidate(
            root, candidate_id=candidate_id, evaluator="independent-evaluator",
            evaluator_version="verifier@1", verdict=verdict,
            test_suite_digest=sha("tests-" + run_id),
            comparison_digest=sha("comparison-" + run_id),
            evidence_refs=["EV-" + run_id], run_id=run_id, actor="aios-ledger",
        )
    with pytest.raises(CapabilityEvolutionError, match="not PASS"):
        promote_candidate(
            root, candidate_id=candidate_id, approver="independent-approver",
            evidence_verifier=lambda refs: True,
            promotion_authorizer=lambda candidate, evaluation, actor: True,
        )


def test_stale_candidate_cannot_replace_new_active_version(tmp_path):
    root = state_dir(tmp_path)
    first_id = propose_candidate(root, **candidate_args())["candidate_id"]
    evaluate_candidate(
        root, candidate_id=first_id, evaluator="evaluator-1", evaluator_version="v1",
        verdict="PASS", test_suite_digest=sha("t1"), comparison_digest=sha("c1"),
        evidence_refs=["EV-1"], run_id="r1", actor="ledger",
    )
    promote_candidate(
        root, candidate_id=first_id, approver="approver-1",
        evidence_verifier=lambda refs: True,
        promotion_authorizer=lambda candidate, evaluation, actor: True,
    )
    second_id = propose_candidate(
        root,
        **candidate_args(candidate_version="1.2.0", proposer="agent-2", run_id="run-2"),
    )["candidate_id"]
    evaluate_candidate(
        root, candidate_id=second_id, evaluator="evaluator-2", evaluator_version="v1",
        verdict="PASS", test_suite_digest=sha("t2"), comparison_digest=sha("c2"),
        evidence_refs=["EV-2"], run_id="r2", actor="ledger",
    )
    with pytest.raises(CapabilityEvolutionError, match="stale"):
        promote_candidate(
            root, candidate_id=second_id, approver="approver-2",
            evidence_verifier=lambda refs: True,
            promotion_authorizer=lambda candidate, evaluation, actor: True,
        )


def test_rollback_rejects_version_not_in_history(tmp_path):
    root = state_dir(tmp_path)
    candidate_id = propose_candidate(root, **candidate_args())["candidate_id"]
    evaluate_candidate(
        root, candidate_id=candidate_id, evaluator="independent-evaluator",
        evaluator_version="v1", verdict="PASS", test_suite_digest=sha("tests"),
        comparison_digest=sha("comparison"), evidence_refs=["EV-1"],
        run_id="r1", actor="ledger",
    )
    promote_candidate(
        root, candidate_id=candidate_id, approver="independent-approver",
        evidence_verifier=lambda refs: True,
        promotion_authorizer=lambda candidate, evaluation, actor: True,
    )
    with pytest.raises(CapabilityEvolutionError, match="previously active"):
        rollback_capability(
            root, capability_id="research.deep", target_version="9.9.9",
            approver="rollback-approver", evidence_verifier=lambda refs: True,
            rollback_authorizer=lambda capability, current, target: True,
        )
