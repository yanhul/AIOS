"""Durable worker lifecycle with bounded transitions and resumable checkpoints."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Mapping

STATES = frozenset({"WORKING", "BLOCKED", "DONE"})
_ALLOWED = {"WORKING": frozenset({"WORKING", "BLOCKED", "DONE"}),
            "BLOCKED": frozenset({"WORKING", "BLOCKED"}),
            "DONE": frozenset()}

@dataclass
class WorkerState:
    worker_id: str
    state: str = "WORKING"
    checkpoint: int = 0
    resume_token: str | None = None
    reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def transition(self, target: str, reason: str | None = None) -> None:
        if target not in STATES:
            raise ValueError("invalid worker state")
        if target not in _ALLOWED[self.state]:
            raise ValueError(f"invalid worker transition: {self.state} -> {target}")
        self.state = target
        self.reason = reason

    def checkpoint_at(self, checkpoint: int, resume_token: str | None = None) -> None:
        if not isinstance(checkpoint, int) or checkpoint < self.checkpoint:
            raise ValueError("checkpoint must be monotonic")
        self.checkpoint = checkpoint
        self.resume_token = resume_token

    def as_record(self) -> dict[str, Any]:
        return {"worker_id": self.worker_id, "state": self.state, "checkpoint": self.checkpoint,
                "resume_token": self.resume_token, "reason": self.reason, "metadata": dict(self.metadata)}


def restore_worker(record: Mapping[str, Any]) -> WorkerState:
    worker = WorkerState(str(record["worker_id"]), str(record["state"]), int(record["checkpoint"]),
                         record.get("resume_token"), record.get("reason"), dict(record.get("metadata", {})))
    if worker.state not in STATES or worker.checkpoint < 0:
        raise ValueError("corrupt worker state")
    return worker

__all__ = ["STATES", "WorkerState", "restore_worker"]
