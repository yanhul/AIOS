"""AIOS machine-readable findings (A1).

A finding is an observed verification problem, not an agent opinion.
It is immutable data linking an issue to concrete evidence references.
Stdlib only.
"""

from dataclasses import dataclass
from typing import Any, Mapping, Sequence


SEVERITIES = ("INFO", "WARN", "ERROR", "BLOCKER")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    severity: str
    location: str
    expected: str
    observed: str
    evidence_refs: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        for name, value in (
            ("finding_id", self.finding_id),
            ("location", self.location),
            ("expected", self.expected),
            ("observed", self.observed),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if self.severity not in SEVERITIES:
            raise ValueError("invalid severity")
        if not isinstance(self.evidence_refs, tuple):
            raise ValueError("evidence_refs must be a tuple")
        for ref in self.evidence_refs:
            if (not isinstance(ref, tuple) or len(ref) != 2
                    or not all(isinstance(v, str) and v.strip() for v in ref)):
                raise ValueError("each evidence_ref must be a (family, id) tuple")
            if ref[0] != "EVIDENCE":
                raise ValueError("evidence_ref family must be EVIDENCE")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "Finding":
        if not isinstance(value, Mapping):
            raise ValueError("finding must be a mapping")
        refs = value.get("evidence_refs")
        if not isinstance(refs, Sequence) or isinstance(refs, (str, bytes)):
            raise ValueError("evidence_refs must be a sequence")
        normalized = []
        for ref in refs:
            if not isinstance(ref, (list, tuple)) or len(ref) != 2:
                raise ValueError("each evidence_ref must contain family and id")
            normalized.append((ref[0], ref[1]))
        return cls(
            finding_id=value.get("finding_id"),
            severity=value.get("severity"),
            location=value.get("location"),
            expected=value.get("expected"),
            observed=value.get("observed"),
            evidence_refs=tuple(normalized),
        )

    def as_record(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "location": self.location,
            "expected": self.expected,
            "observed": self.observed,
            "evidence_refs": [list(ref) for ref in self.evidence_refs],
        }


__all__ = ["SEVERITIES", "Finding"]
