"""Governed memory candidates and durable persistence for the AIOS control plane.

Memory is contextual evidence, never authority or durable execution state.
Persistence shares the AIOS durable WAL boundary with control-plane state.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from .mutation import canonical_json

MEMORY_TYPES = frozenset({"SEMANTIC", "EPISODIC", "PROCEDURAL"})
MEMORY_STATUSES = frozenset({"ACTIVE", "SUPERSEDED", "REVOKED"})
MEMORY_AUTHORITIES = frozenset({"AIOS_CONTROL_PLANE", "NONE"})


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
            raise ValueError(
                f"evidence_refs[{pos}] must reference persisted EVIDENCE as [EVIDENCE, EV-*]"
            )
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
    return MemoryRecord(
        memory_id="MEM-" + _digest(unsigned),
        memory_type=memory_type,
        content=dict(content),
        evidence_refs=refs,
        predecessor=predecessor,
        authority=authority,
        source_commit=source_commit,
        version=version,
        status=status,
    )


def validate_memory_record(record: Mapping[str, Any]) -> bool:
    if not isinstance(record, Mapping):
        raise ValueError("memory record must be a mapping")
    required = {
        "memory_id", "memory_type", "content", "evidence_refs", "predecessor",
        "authority", "source_commit", "version", "status",
    }
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


def _validate_execution_lineage(record: Mapping[str, Any]) -> None:
    lineage = record.get("execution_lineage")
    if lineage is None:
        return
    if not isinstance(lineage, Mapping):
        raise ValueError("execution_lineage must be a mapping")
    status = lineage.get("status")
    if status == "UNKNOWN":
        raise ValueError("UNKNOWN execution lineage cannot materialize as factual memory")
    for field in ("effect_id", "attempt_id"):
        if not isinstance(lineage.get(field), str) or not lineage[field].strip():
            raise ValueError(f"execution_lineage.{field} is required")


def persist_memory(store, record: Mapping[str, Any], *, decision_id: str,
                   mutation_id: str, authority: str,
                   execution_lineage: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    """Governed memory write: decision -> authority -> mutation -> shared WAL."""
    validate_memory_record(record)
    _text(decision_id, "decision_id")
    _text(mutation_id, "mutation_id")
    if authority != "AIOS_CONTROL_PLANE":
        raise ValueError("memory mutation authority must be AIOS_CONTROL_PLANE")
    _validate_execution_lineage({"execution_lineage": execution_lineage} if execution_lineage else {})
    if execution_lineage and execution_lineage.get("status") == "UNKNOWN":
        raise ValueError("UNKNOWN execution lineage cannot be persisted as factual memory")
    envelope = {
        "memory": dict(record),
        "decision_id": decision_id,
        "mutation_id": mutation_id,
        "authority": authority,
        "execution_lineage": dict(execution_lineage) if execution_lineage else None,
    }
    # Append is a single fsynced WAL mutation, not a racy read/modify/write.
    # Replay folds the append into the namespace projection after process death.
    store.append_namespace("memory", envelope)
    return envelope


def load_memory(store) -> list[Mapping[str, Any]]:
    """Replay memory namespace from the shared WAL; never trust snapshot alone."""
    state = store.load_namespace("memory", default=[])
    if not isinstance(state, list):
        raise ValueError("memory WAL state must be a list")
    result = []
    for envelope in state:
        if not isinstance(envelope, Mapping):
            raise ValueError("invalid memory mutation envelope")
        memory = envelope.get("memory")
        validate_memory_record(memory)
        if envelope.get("authority") != "AIOS_CONTROL_PLANE":
            raise ValueError("invalid memory mutation authority")
        _text(envelope.get("decision_id"), "decision_id")
        _text(envelope.get("mutation_id"), "mutation_id")
        _validate_execution_lineage(envelope)
        result.append(dict(memory))
    return result


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
        _, unresolved = evidence_resolver(
            [list(ref) for ref in raw["evidence_refs"]]
        )
        if unresolved:
            continue
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
    "MEMORY_TYPES", "MEMORY_STATUSES", "MemoryRecord",
    "build_memory_record", "validate_memory_record",
    "persist_memory", "load_memory", "retrieve_memory",
]
