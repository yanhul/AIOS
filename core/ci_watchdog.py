"""Deterministic CI watchdog policy for AIOS.

The watchdog never treats a GitHub conclusion as proof of PASS. It classifies
run liveness, evidence completeness, and bounded retry eligibility. Execution
and authority remain outside this module.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet


class CIWatchError(ValueError):
    pass


RUN_STATES: FrozenSet[str] = frozenset({
    "requested", "queued", "waiting", "pending", "in_progress", "completed",
})
CONCLUSIONS: FrozenSet[str] = frozenset({
    "success", "failure", "cancelled", "timed_out", "action_required",
    "neutral", "skipped", "stale", "startup_failure",
})


@dataclass(frozen=True)
class CIWatch:
    repository: str
    workflow: str
    run_id: int
    sha: str
    status: str
    conclusion: str | None
    age_seconds: int
    queue_timeout_seconds: int = 600
    execution_timeout_seconds: int = 1800
    retry_count: int = 0
    max_retries: int = 2
    evidence_present: bool = False

    def validate(self) -> None:
        if not self.repository or not self.workflow:
            raise CIWatchError("repository/workflow required")
        if self.run_id <= 0:
            raise CIWatchError("run_id must be positive")
        if len(self.sha) != 40 or any(c not in "0123456789abcdef" for c in self.sha.lower()):
            raise CIWatchError("sha must be a 40-character hexadecimal commit")
        if self.status not in RUN_STATES:
            raise CIWatchError("unsupported run status")
        if self.conclusion is not None and self.conclusion not in CONCLUSIONS:
            raise CIWatchError("unsupported conclusion")
        if self.age_seconds < 0:
            raise CIWatchError("age_seconds must be non-negative")
        if self.queue_timeout_seconds <= 0 or self.execution_timeout_seconds <= 0:
            raise CIWatchError("timeouts must be positive")
        if self.retry_count < 0 or self.max_retries < 0:
            raise CIWatchError("retry budget must be non-negative")
        if self.retry_count > self.max_retries:
            raise CIWatchError("retry budget exhausted")

    @property
    def terminal(self) -> bool:
        return self.status == "completed"

    @property
    def queue_timed_out(self) -> bool:
        return self.status in {"requested", "queued", "waiting", "pending"} and self.age_seconds >= self.queue_timeout_seconds

    @property
    def execution_timed_out(self) -> bool:
        return self.status == "in_progress" and self.age_seconds >= self.execution_timeout_seconds

    @property
    def evidence_ok(self) -> bool:
        return self.terminal and self.conclusion == "success" and self.evidence_present

    @property
    def next_action(self) -> str:
        self.validate()
        if self.queue_timed_out:
            return "CANCEL_AND_RETRY" if self.retry_count < self.max_retries else "BLOCKED"
        if self.execution_timed_out:
            return "CANCEL_AND_RETRY" if self.retry_count < self.max_retries else "BLOCKED"
        if not self.terminal:
            return "WATCH"
        if self.conclusion == "success":
            return "VERIFY_EVIDENCE" if not self.evidence_present else "VERIFY"
        if self.conclusion in {"failure", "cancelled", "timed_out", "startup_failure"}:
            return "DIAGNOSE"
        return "REVIEW"


def classify_watch(watch: CIWatch) -> str:
    return watch.next_action
