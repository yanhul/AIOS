"""Governed memory candidates and durable persistence for the AIOS control plane.

Memory is contextual evidence, never authority or durable execution state.
Persistence shares the AIOS durable WAL boundary with control-plane state.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Mapping

from .mutation import (canonical_json, validate_entity, _entity_relpath, _require_committed_event, _MutationLock)
from .secure_fs import SecureWriteError, secure_read_bytes_beneath
from .authority import authorize, load_contract
from .capabilities import CapabilityRegistry
from .policy_registry import resolve_policy

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
                   mutation_id: str, authority: str, aios_dir: str,
                   contract_id: str, permit_id: str, actor: str,
                   execution_lineage: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    """Persist only after native, persisted AIOS authority authorizes MEMORY_WRITE."""
    validate_memory_record(record)
    _text(aios_dir, "aios_dir")
    # Store/root binding (Batch 3): the WAL and snapshots written below must
    # live beneath the SAME trusted state root that authorizes the write; a
    # caller cannot redirect an authorized memory mutation to external paths.
    from .wal_state_store import WalStateStore, _MEMORY_WRITE_TOKEN
    if not isinstance(store, WalStateStore):
        raise ValueError("memory store must be a WalStateStore bound to aios_dir")
    try:
        store.assert_bound_to(aios_dir)
    except SecureWriteError as exc:
        raise ValueError(f"memory store is not bound to the trusted state root: {exc}") from exc
    _text(contract_id, "contract_id")
    _text(permit_id, "permit_id")
    _text(actor, "actor")
    authorize(aios_dir, contract_id, permit_id)
    contract = load_contract(aios_dir, contract_id)
    if contract.get("actor") != actor:
        raise ValueError("memory writer actor does not match authorized contract")
    if contract.get("scope") != "memory:write":
        raise ValueError("contract scope does not authorize memory:write")
    if "MEMORY_WRITE" not in contract.get("allowed_effects", []):
        raise ValueError("contract does not authorize MEMORY_WRITE")
    policy = resolve_policy(aios_dir, contract["policy_digest"])
    if "MEMORY_WRITE" not in policy.get("rules", []):
        raise ValueError("governing policy does not authorize MEMORY_WRITE")
    registry = CapabilityRegistry.load(aios_dir)
    capabilities = registry.resolve_contract(contract)
    if not any(cap.status == "ACTIVE" and "MEMORY_WRITE" in cap.permissions for cap in capabilities):
        raise ValueError("contract has no ACTIVE MEMORY_WRITE capability")
    _text(decision_id, "decision_id")
    _text(mutation_id, "mutation_id")
    if record["predecessor"] != decision_id:
        raise ValueError("memory predecessor must match the governed decision_id")
    # A caller-supplied ID is not a decision receipt: resolve the canonical
    # persisted DECISION and require its integrity-bound mutation event.
    # The id is resolved strictly by name inside decisions/: separators and
    # dot components are refused lexically, and the file is read via
    # descriptor-relative, no-follow, fstat-verified I/O (core.secure_fs).
    # Symlinked / dangling / FIFO / special / unreadable DECISION data is
    # never authorization. Nothing is written before every check passes.
    if ("/" in decision_id or "\\" in decision_id or "\x00" in decision_id
            or decision_id in (".", "..")):
        raise ValueError("decision_id does not resolve to persisted DECISION")
    decision_rel = f"decisions/{decision_id}.json"
    try:
        raw = secure_read_bytes_beneath(aios_dir, decision_rel)
    except FileNotFoundError as exc:
        raise ValueError("decision_id does not resolve to persisted DECISION") from exc
    except (OSError, SecureWriteError) as exc:
        raise ValueError(f"decision_id is not integrity-bound persisted DECISION: "
                         f"unsafe or unreadable DECISION entry refused: {exc}") from exc
    try:
        decision = json.loads(raw.decode("utf-8"))
        if not isinstance(decision, dict):
            raise ValueError("DECISION is not a JSON object")
        validate_entity(decision)
        if decision.get("entity_type") != "DECISION" or decision.get("entity_id") != decision_id:
            raise ValueError("decision identity mismatch")
        if _entity_relpath(decision).replace(os.sep, "/") != decision_rel:
            raise ValueError("DECISION is not stored at its canonical path")
        _require_committed_event(aios_dir, decision)
    except (OSError, ValueError, TypeError, UnicodeDecodeError) as exc:
        raise ValueError(f"decision_id is not integrity-bound persisted DECISION: {exc}") from exc
    # Reuse native evidence resolution at write time, not only retrieval time.
    from .verification import resolve_evidence
    _, unresolved = resolve_evidence(aios_dir, [list(ref) for ref in record["evidence_refs"]])
    if unresolved:
        raise ValueError(f"memory evidence refs unresolved at write time: {unresolved}")
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
        "contract_id": contract_id,
        "permit_id": permit_id,
        "actor": actor,
        "execution_lineage": dict(execution_lineage) if execution_lineage else None,
    }
    # mutation_id is enforced atomically by the WAL under its cross-process lock.
    with _MutationLock(aios_dir):
        committed, appended = store._append_governed_memory(envelope, _MEMORY_WRITE_TOKEN)
    if dict(committed) != envelope:
        raise ValueError("mutation_id already belongs to a different memory mutation")
    if not appended:
        return committed
    return envelope


def _validate_persisted_memory_envelope(aios_dir: str, envelope: Mapping[str, Any]) -> Mapping[str, Any]:
    memory = envelope.get("memory")
    validate_memory_record(memory)
    if envelope.get("authority") != "AIOS_CONTROL_PLANE":
        raise ValueError("invalid memory mutation authority")
    decision_id = _text(envelope.get("decision_id"), "decision_id")
    _text(envelope.get("mutation_id"), "mutation_id")
    contract_id = _text(envelope.get("contract_id"), "contract_id")
    permit_id = _text(envelope.get("permit_id"), "permit_id")
    actor = _text(envelope.get("actor"), "actor")
    if memory["predecessor"] != decision_id:
        raise ValueError("memory predecessor does not match persisted decision_id")
    if ("/" in decision_id or "\\" in decision_id or "\x00" in decision_id
            or decision_id in (".", "..")):
        raise ValueError("decision_id does not resolve to persisted DECISION")
    authorize(aios_dir, contract_id, permit_id)
    contract = load_contract(aios_dir, contract_id)
    if (contract.get("actor") != actor or contract.get("scope") != "memory:write"
            or "MEMORY_WRITE" not in contract.get("allowed_effects", [])):
        raise ValueError("persisted memory contract does not authorize this envelope")
    policy = resolve_policy(aios_dir, contract["policy_digest"])
    if "MEMORY_WRITE" not in policy.get("rules", []):
        raise ValueError("persisted memory policy does not authorize this envelope")
    registry = CapabilityRegistry.load(aios_dir)
    capabilities = registry.resolve_contract(contract)
    if not any(cap.status == "ACTIVE" and "MEMORY_WRITE" in cap.permissions for cap in capabilities):
        raise ValueError("persisted memory capability is not ACTIVE")
    decision_rel = f"decisions/{decision_id}.json"
    raw = secure_read_bytes_beneath(aios_dir, decision_rel)
    decision = json.loads(raw.decode("utf-8"))
    if (not isinstance(decision, dict) or decision.get("entity_type") != "DECISION"
            or decision.get("entity_id") != decision_id):
        raise ValueError("persisted DECISION identity mismatch")
    validate_entity(decision)
    if _entity_relpath(decision).replace(os.sep, "/") != decision_rel:
        raise ValueError("DECISION is not stored at its canonical path")
    _require_committed_event(aios_dir, decision)
    from .verification import resolve_evidence
    _, unresolved = resolve_evidence(aios_dir, memory["evidence_refs"])
    if unresolved:
        raise ValueError(f"persisted memory evidence refs unresolved: {unresolved}")
    _validate_execution_lineage(envelope)
    return memory


def load_memory(store) -> list[Mapping[str, Any]]:
    """Replay memory namespace from the shared WAL; never trust snapshot alone."""
    state = store.load_namespace("memory", default=[])
    if not isinstance(state, list):
        raise ValueError("memory WAL state must be a list")
    result = []
    seen_mutation_ids = set()
    for envelope in state:
        if not isinstance(envelope, Mapping):
            raise ValueError("invalid memory mutation envelope")
        mutation_id = _text(envelope.get("mutation_id"), "mutation_id")
        if mutation_id in seen_mutation_ids:
            raise ValueError("duplicate memory mutation_id in durable history")
        seen_mutation_ids.add(mutation_id)
        memory = _validate_persisted_memory_envelope(store.root, envelope)
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
