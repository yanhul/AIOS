"""Immutable experiment/run lineage primitives for AIOS-owned workers."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any, Mapping


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

@dataclass(frozen=True)
class ExperimentRun:
    run_id: str
    parent_run_id: str | None
    capability_id: str
    capability_version: str
    source_commit: str
    worktree: str
    policy_digest: str
    created_at: str
    artifact_refs: tuple[str, ...] = ()
    result_refs: tuple[str, ...] = ()
    log_refs: tuple[str, ...] = ()

    @property
    def lineage_digest(self) -> str:
        payload = {"run_id": self.run_id, "parent_run_id": self.parent_run_id,
                   "capability_id": self.capability_id, "capability_version": self.capability_version,
                   "source_commit": self.source_commit, "worktree": self.worktree,
                   "policy_digest": self.policy_digest, "created_at": self.created_at,
                   "artifact_refs": self.artifact_refs, "result_refs": self.result_refs,
                   "log_refs": self.log_refs}
        return sha256(_canonical(payload).encode()).hexdigest()

    def as_record(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "parent_run_id": self.parent_run_id,
                "capability_id": self.capability_id, "capability_version": self.capability_version,
                "source_commit": self.source_commit, "worktree": self.worktree,
                "policy_digest": self.policy_digest, "created_at": self.created_at,
                "artifact_refs": list(self.artifact_refs), "result_refs": list(self.result_refs),
                "log_refs": list(self.log_refs), "lineage_digest": self.lineage_digest}


def new_run(run_id: str, capability_id: str, capability_version: str, source_commit: str,
            worktree: str, policy_digest: str, parent_run_id: str | None = None) -> ExperimentRun:
    if not all(isinstance(v, str) and v.strip() for v in (run_id, capability_id, capability_version, source_commit, worktree, policy_digest)):
        raise ValueError("run identity, source commit, worktree and policy digest are required")
    return ExperimentRun(run_id, parent_run_id, capability_id, capability_version,
                         source_commit, worktree, policy_digest,
                         datetime.now(timezone.utc).isoformat())


def verify_record(record: Mapping[str, Any]) -> bool:
    required = ("run_id", "capability_id", "capability_version", "source_commit", "worktree", "policy_digest", "created_at", "lineage_digest")
    if any(k not in record for k in required):
        return False
    expected = ExperimentRun(
        run_id=str(record["run_id"]), parent_run_id=record.get("parent_run_id"),
        capability_id=str(record["capability_id"]), capability_version=str(record["capability_version"]),
        source_commit=str(record["source_commit"]), worktree=str(record["worktree"]),
        policy_digest=str(record["policy_digest"]), created_at=str(record["created_at"]),
        artifact_refs=tuple(record.get("artifact_refs", ())), result_refs=tuple(record.get("result_refs", ())),
        log_refs=tuple(record.get("log_refs", ())))
    return expected.lineage_digest == record["lineage_digest"]

__all__ = ["ExperimentRun", "new_run", "verify_record"]
