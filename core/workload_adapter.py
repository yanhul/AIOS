"""Common boundary for independently owned workload adapters."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


TERMINAL = {"PASS", "BLOCKED", "INCONCLUSIVE"}


@dataclass(frozen=True)
class WorkloadResult:
    workload_id: str
    execution_id: str
    status: str
    artifact_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    verification_refs: tuple[str, ...]
    provenance: Mapping[str, str]

    def __post_init__(self) -> None:
        for name in ("workload_id", "execution_id", "status"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty")
        if self.status not in TERMINAL:
            raise ValueError("workload status must be PASS, BLOCKED, or INCONCLUSIVE")
        for name in ("artifact_refs", "evidence_refs", "verification_refs"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or not all(isinstance(x, str) and x.strip() for x in values):
                raise ValueError(f"{name} must contain non-empty strings")
        if not isinstance(self.provenance, Mapping):
            raise ValueError("provenance must be a mapping")
        if self.status == "PASS" and (not self.evidence_refs or not self.verification_refs):
            raise ValueError("PASS workload result requires evidence and verification refs")

    def to_aios_terminal(self) -> str:
        return self.status


def validate_adapter_result(*, workload_id: str, execution_id: str,
                            result: Mapping[str, object]) -> WorkloadResult:
    """Normalize an external adapter result without granting it AIOS authority."""
    if not isinstance(result, Mapping):
        raise ValueError("adapter result must be a mapping")
    status = result.get("status")
    if status not in TERMINAL:
        raise ValueError("adapter result has invalid terminal status")
    refs = result.get("evidence_refs", ())
    ver = result.get("verification_refs", ())
    artifacts = result.get("artifact_refs", ())
    provenance = result.get("provenance", {})
    return WorkloadResult(
        workload_id=workload_id,
        execution_id=execution_id,
        status=status,
        artifact_refs=tuple(artifacts),
        evidence_refs=tuple(refs),
        verification_refs=tuple(ver),
        provenance=provenance,
    )


__all__ = ["TERMINAL", "WorkloadResult", "validate_adapter_result"]
