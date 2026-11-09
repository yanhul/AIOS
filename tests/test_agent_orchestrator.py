import pytest
from core.agent_orchestrator import OrchestrationPlan, ReviewRecord, validate_plan, validate_review

def test_plan_requires_valid_source_and_authorized_capabilities():
    p = OrchestrationPlan("t1", "a"*40, "worktrees/t1", ("inspect", "patch"), ("repo.read",))
    validate_plan(p, {"repo.read"})

def test_plan_rejects_unsafe_worktree_and_unapproved_capability():
    with pytest.raises(ValueError):
        validate_plan(OrchestrationPlan("t1", "a"*40, "../escape", ("inspect",)), set())
    with pytest.raises(PermissionError):
        validate_plan(OrchestrationPlan("t1", "a"*40, "worktrees/t1", ("inspect",), ("shell.unrestricted",)), set())

def test_review_must_be_independent_and_cannot_claim_pass():
    validate_review(ReviewRecord("t1", "executor", "reviewer", "APPROVED_FOR_AI0S_VERIFICATION", ("artifact://diff",)))
    with pytest.raises(PermissionError):
        validate_review(ReviewRecord("t1", "same", "same", "APPROVED_FOR_AI0S_VERIFICATION", ("artifact://diff",)))
    with pytest.raises(ValueError):
        validate_review(ReviewRecord("t1", "executor", "reviewer", "PASS", ("artifact://diff",)))
