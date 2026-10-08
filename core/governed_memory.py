"""Governed memory candidates for the AIOS control plane.

Memory is contextual evidence, never authority or durable execution state.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from .mutation import canonical_json

MEMORY_TYPES = frozenset({"SEMANTIC", "EPISODIC", "PROCEDURAL"})
MEMORY_STATUSES = frozenset({"ACTIVE", "SUPERSEDED", "REVOKED"})


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _evidence_refs(value: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list) or not value:
        raise ValueError("evidence_refs must be a non-empty list")
    refs = []
    for pos, ref in enumerate(value):
        if (not isinstance(ref, (list, tuple)) or len(ref) != 2
                or not all(isinstance(x, str) and x.strip() for x in ref)):
            raise ValueError(f"evidence_refs[{pos}] must be [family, id] strings")
        family, evidence_id = ref
        if family != "EVIDENCE" or not evidence_id.startswith("EV-"):
            raise ValueError(f"evidence_refs[{pos}] must reference persisted EVIDENCE as [EVIDENCE, EV-*]")
        refs.append((family, evidence_id))
    return tuple(refs)


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class MemoryRecord:
    memory_id: str
    memory_type: str
    content: Mapping[str, Any]
    evidence_refs: tuple[tuple[str, str], ...]
    predecessor: str
    authority: str
    source_commit: str
    version: int = 1
    status: str = "ACTIVE"

    def as_dict(self) -> dict[str, Any]:
        return {
            "memory_id": self.memory_id,
            "memory_type": self.memory_type,
            "content": dict(self.content),
            "evidence_refs": [list(ref) for ref in self.evidence_refs],
            "predecessor": self.predecessor,
            "authority": self.authority,
            "source_commit": self.source_commit,
            "version": self.version,
            "status": self.status,
        }


def build_memory_record(
    *,
    memory_type: str,
    content: Mapping[str, Any],
    evidence_refs: list[list[str] | tuple[str, str]],
    predecessor: str,
    authority: str,
    source_commit: str,
    version: int = 1,
    status: str = "ACTIVE",
) -> MemoryRecord:
    if memory_type not in MEMORY_TYPES:
        raise ValueError("unauthorized memory_type")
    if not isinstance(content, Mapping) or not content:
        raise ValueError("memory content must be a non-empty mapping")
    refs = _evidence_refs(evidence_refs)
    _text(predecessor, "predecessor")
    if authority != "AIOS_CONTROL_PLANE":
        raise ValueError("memory authority must be AIOS_CONTROL_PLANE")
    _text(source_commit, "source_commit")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ValueError("memory version must be a positive integer")
    if status not in MEMORY_STATUSES:
        raise ValueError("unauthorized memory status")

    unsigned = {
        "memory_type": memory_type,
        "content": dict(content),
        "evidence_refs": [list(ref) for ref in refs],
        "predecessor": predecessor,
        "authority": authority,
        "source_commit": source_commit,
        "version": version,
        "status": status,
    }
    memory_id = "MEM-" + _digest(unsigned)
    return MemoryRecord(
        memory_id=memory_id,
        memory_type=memory_type,
        content=dict(content),
        evidence_refs=refs,
        predecessor=predecessor,
        authority=authority,
        source_commit=source_commit,
        version=version,
        status=status,
    ),\n        evidence_refs=refs,\n        predecessor=predecessor,\n        authority=authority,\n        source_commit=source_commit,\n        version=version,\n        status=status,\n    )


def validate_memory_record(record: Mapping[str, Any]) -> bool:
    if not isinstance(record, Mapping):
        raise ValueError("memory record must be a mapping")
    required = {"memory_id","memory_type","content","evidence_refs","predecessor",
                "authority","source_commit","version","status"}
    missing = required - set(record)
    if missing:
        raise ValueError(f"memory record missing fields: {sorted(missing)}")
    expected = build_memory_record(
        memory_type=record["memory_type"],
        content=record["content"],
        evidence_refs=record["evidence_refs"],
        predecessor=record["predecessor"],
        authority=record["authority"],
        source_commit=record["source_commit"],
        version=record["version"],
        status=record["status"],
    )
    if record["memory_id"] != expected.memory_id:
        raise ValueError("memory identity mismatch")
    return True


def retrieve_memory(
    records: list[Mapping[str, Any]],
    *,
    query: str,
    current_commit: str,
    aios_dir: str | None = None,
    evidence_resolver=None,
    allowed_types: set[str] | None = None,
) -> list[Mapping[str, Any]]:
    """Return context candidates only; retrieval grants no authority."""
    _text(query, "query")
    _text(current_commit, "current_commit")
    allowed = MEMORY_TYPES if allowed_types is None else set(allowed_types)
    if not allowed <= MEMORY_TYPES:
        raise ValueError("allowed_types contains unauthorized memory type")
    if evidence_resolver is None:
        if not aios_dir:
            raise ValueError("aios_dir is required for governed evidence resolution")
        from .verification import resolve_evidence
        evidence_resolver = lambda refs: resolve_evidence(aios_dir, refs)
    result: list[Mapping[str, Any]] = []
    q = query.casefold()
    for raw in records:
        validate_memory_record(raw)
        if raw["status"] != "ACTIVE":
            continue
        _, unresolved = evidence_resolver([list(ref) for ref in raw["evidence_refs"]])
        if unresolved:
            continue
        # source_commit is provenance, not a freshness oracle. Prior-commit
        # memories remain candidates; callers must reconcile them with current state.
        if raw["memory_type"] not in allowed:
            continue
        haystack = canonical_json(raw["content"]).casefold()
        if q in haystack:
            candidate = dict(raw)
            candidate["context_role"] = "MEMORY_CANDIDATE"
            candidate["authority"] = "NONE"
            result.append(candidate)
    return result


__all__ = [
    "MEMORY_TYPES",
    "MEMORY_STATUSES",
    "MemoryRecord",
    "build_memory_record",
    "validate_memory_record",
    "retrieve_memory",
]
