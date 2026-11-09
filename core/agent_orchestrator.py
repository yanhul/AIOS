"""Governed orchestration boundary adapted from AgentKit patterns.
Plans and review are advisory. AIOS authority, evidence, verification and promotion remain external.
No worktree creation, shell execution, permit issuance or policy mutation occurs here.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Iterable

_SHA = re.compile(r"^[0-9a-f]{40}$")

@dataclass(frozen=True)
class OrchestrationPlan:
    task_id: str
    source_commit: str
    worktree_ref: str
    steps: tuple[str, ...]
    requested_capabilities: tuple[str, ...] = ()

@dataclass(frozen=True)
class ReviewRecord:
    task_id: str
    executor_id: str
    reviewer_id: str
    decision: str
    evidence_refs: tuple[str, ...]

def validate_plan(plan: OrchestrationPlan, authorized_capabilities: Iterable[str]) -> None:
    if not plan.task_id.strip():
        raise ValueError("task_id is required")
    if not _SHA.fullmatch(plan.source_commit):
        raise ValueError("source_commit must be a full commit SHA")
    if not plan.worktree_ref.strip() or plan.worktree_ref.startswith("/") or ".." in plan.worktree_ref.split("/"):
        raise ValueError("worktree_ref must be repository-relative and safe")
    if not plan.steps or any(not isinstance(s, str) or not s.strip() for s in plan.steps):
        raise ValueError("plan requires non-empty steps")
    if len(set(plan.steps)) != len(plan.steps):
        raise ValueError("plan steps must be unique")
    if set(plan.requested_capabilities) - frozenset(authorized_capabilities):
        raise PermissionError("plan requests capabilities not authorized by AIOS")

def validate_review(review: ReviewRecord) -> None:
    if not all(isinstance(v, str) and v.strip() for v in
               (review.task_id, review.executor_id, review.reviewer_id)):
        raise ValueError("review lineage fields are required")
    if review.executor_id == review.reviewer_id:
        raise PermissionError("executor cannot independently review its own work")
    if review.decision not in {"APPROVED_FOR_AIOS_VERIFICATION", "CHANGES_REQUESTED", "BLOCKED"}:
        raise ValueError("review cannot set PASS or an unsupported decision")
    if not review.evidence_refs or any(not r.strip() for r in review.evidence_refs):
        raise ValueError("review requires explicit evidence references")

__all__ = ["OrchestrationPlan", "ReviewRecord", "validate_plan", "validate_review"]
