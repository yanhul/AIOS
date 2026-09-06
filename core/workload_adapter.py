"""Common fail-closed boundary for independently owned workload adapters."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import urlparse

TERMINAL = frozenset({"PASS", "BLOCKED", "INCONCLUSIVE"})


def _validate_refs(*, name: str, values: tuple[str, ...], cwd: Path) -> None:
    for ref in values:
        parsed = urlparse(ref)
        if parsed.scheme:
            continue
        path = Path(ref)
        if not path.is_absolute():
            path = cwd / path
        if not path.exists():
            raise ValueError(f"{name} references missing local artifact: {ref}")


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
        if not isinstance(self.provenance, Mapping) or not self.provenance:
            raise ValueError("provenance must be a non-empty mapping")
        if not all(isinstance(k, str) and k.strip() and isinstance(v, str) and v.strip()
                   for k, v in self.provenance.items()):
            raise ValueError("provenance keys and values must be non-empty strings")
        if self.status == "PASS" and (not self.evidence_refs or not self.verification_refs):
            raise ValueError("PASS workload result requires evidence and verification refs")

    def to_aios_terminal(self) -> str:
        return self.status


def validate_adapter_result(*, workload_id: str, execution_id: str,
                            result: Mapping[str, object], cwd: str | Path = ".") -> WorkloadResult:
    """Normalize an adapter result; it cannot grant AIOS authority or promotion."""
    if not isinstance(result, Mapping):
        raise ValueError("adapter result must be a mapping")
    status = result.get("status")
    if status not in TERMINAL:
        raise ValueError("adapter result has invalid terminal status")
    def refs(name: str) -> tuple[str, ...]:
        value = result.get(name, ())
        if not isinstance(value, (tuple, list)):
            raise ValueError(f"{name} must be a sequence")
        return tuple(value)
    result_obj = WorkloadResult(
        workload_id=workload_id,
        execution_id=execution_id,
        status=status,
        artifact_refs=refs("artifact_refs"),
        evidence_refs=refs("evidence_refs"),
        verification_refs=refs("verification_refs"),
        provenance=result.get("provenance", {}),
    )
    base = Path(cwd).resolve()
    _validate_refs(name="artifact_refs", values=result_obj.artifact_refs, cwd=base)
    _validate_refs(name="evidence_refs", values=result_obj.evidence_refs, cwd=base)
    _validate_refs(name="verification_refs", values=result_obj.verification_refs, cwd=base)
    return result_obj

__all__ = ["TERMINAL", "WorkloadResult", "validate_adapter_result"]
