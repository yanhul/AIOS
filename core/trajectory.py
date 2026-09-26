"""Strict trajectory/step provenance primitives absorbed from agentic execution research.

Raw output is immutable evidence. Normalization is a derived view. Evaluation and
credit are downstream and cannot rewrite raw evidence.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Mapping

def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def digest(value: Any) -> str:
    return sha256(canonical(value).encode("utf-8")).hexdigest()

@dataclass(frozen=True)
class TrajectoryStep:
    trajectory_id: str
    step_id: str
    attempt_id: str
    environment_revision: str
    capability_snapshot: Mapping[str, Any]
    raw_output: str
    normalized_tool_calls: tuple[Mapping[str, Any], ...] = ()
    intervention_id: str | None = None

    def __post_init__(self) -> None:
        for value, name in ((self.trajectory_id,"trajectory_id"),(self.step_id,"step_id"),
                            (self.attempt_id,"attempt_id"),(self.environment_revision,"environment_revision")):
            if not isinstance(value,str) or not value.strip():
                raise ValueError(f"{name} must be non-empty")
        if not isinstance(self.capability_snapshot, Mapping) or not self.capability_snapshot:
            raise ValueError("capability_snapshot must be non-empty")
        if not isinstance(self.raw_output,str):
            raise ValueError("raw_output must be a string")
        for call in self.normalized_tool_calls:
            if not isinstance(call, Mapping) or not call.get("name"):
                raise ValueError("normalized tool call must contain name")

    @property
    def raw_output_digest(self) -> str:
        return digest(self.raw_output)

    @property
    def normalized_digest(self) -> str:
        return digest(list(self.normalized_tool_calls))

    @property
    def digest(self) -> str:
        return digest(self.as_record(include_digest=False))

    def as_record(self, *, include_digest: bool=True) -> dict[str,Any]:
        record={
            "trajectory_id":self.trajectory_id,
            "step_id":self.step_id,
            "attempt_id":self.attempt_id,
            "environment_revision":self.environment_revision,
            "capability_snapshot":dict(self.capability_snapshot),
            "raw_output":self.raw_output,
            "raw_output_digest":self.raw_output_digest,
            "normalized_tool_calls":[dict(x) for x in self.normalized_tool_calls],
            "normalized_digest":self.normalized_digest,
            "intervention_id":self.intervention_id,
        }
        if include_digest: record["step_digest"]=self.digest
        return record

def validate_step(record: Mapping[str,Any]) -> TrajectoryStep:
    if not isinstance(record,Mapping) or record.get("step_digest") is None:
        raise ValueError("trajectory step is incomplete")
    obj=TrajectoryStep(
        trajectory_id=record["trajectory_id"], step_id=record["step_id"],
        attempt_id=record["attempt_id"], environment_revision=record["environment_revision"],
        capability_snapshot=record["capability_snapshot"], raw_output=record["raw_output"],
        normalized_tool_calls=tuple(record.get("normalized_tool_calls",())),
        intervention_id=record.get("intervention_id"))
    if record.get("raw_output_digest") != obj.raw_output_digest:
        raise ValueError("raw output digest mismatch")
    if record.get("normalized_digest") != obj.normalized_digest:
        raise ValueError("normalized tool-call digest mismatch")
    if record["step_digest"] != obj.digest:
        raise ValueError("trajectory step digest mismatch")
    return obj

__all__=["TrajectoryStep","validate_step","canonical","digest"]
