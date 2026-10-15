"""AIOS capability identity, registry, graph, and durable persistence.

Registration is descriptive, not trust or promotion. Durable writes use the
same atomic commit primitive as the rest of AIOS state.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .mutation import commit_batch

ALLOWED_EDGE_TYPES = frozenset({"requires", "produces", "composes_with", "validated_by", "works_under"})
VERIFICATION_LEVELS = frozenset({"OBSERVED", "EVIDENCED", "VERIFIED_DIGITAL", "VERIFIED_PHYSICAL", "PROMOTED"})
CAPABILITY_STATE_FILE = "capabilities/capability_registry.json"

class CapabilityError(ValueError):
    pass

@dataclass(frozen=True)
class Capability:
    capability_id: str
    version: str
    owner: str
    kind: str
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    environments: tuple[str, ...] = ()
    verification_methods: tuple[str, ...] = ()
    evidence_requirements: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    status: str = "CANDIDATE"
    metadata: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        for name, value in (("capability_id", self.capability_id), ("version", self.version), ("owner", self.owner), ("kind", self.kind)):
            if not isinstance(value, str) or not value:
                raise CapabilityError(f"{name} must be a non-empty string")
        if self.status not in {"CANDIDATE", "ACTIVE", "DEPRECATED"}:
            raise CapabilityError("invalid capability status")

    @property
    def key(self) -> str:
        return f"{self.capability_id}@{self.version}"

    def as_dict(self) -> dict[str, Any]:
        return {"capability_id": self.capability_id, "version": self.version, "owner": self.owner, "kind": self.kind,
                "inputs": list(self.inputs), "outputs": list(self.outputs), "permissions": list(self.permissions),
                "environments": list(self.environments), "verification_methods": list(self.verification_methods),
                "evidence_requirements": list(self.evidence_requirements), "provenance": list(self.provenance),
                "dependencies": list(self.dependencies), "status": self.status,
                "metadata": [list(x) for x in self.metadata]}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Capability":
        if not isinstance(value, dict):
            raise CapabilityError("invalid persisted capability: record must be an object")
        sequence_fields = (
            "inputs", "outputs", "permissions", "environments",
            "verification_methods", "evidence_requirements", "provenance", "dependencies",
        )
        for field in sequence_fields:
            raw = value.get(field, ())
            if not isinstance(raw, (list, tuple)) or any(not isinstance(item, str) or not item.strip() for item in raw):
                raise CapabilityError(f"invalid persisted capability: {field} must be a list of non-empty strings")
        metadata = value.get("metadata", ())
        if not isinstance(metadata, (list, tuple)) or any(
            not isinstance(item, (list, tuple)) or len(item) != 2
            or any(not isinstance(part, str) or not part for part in item)
            for item in metadata
        ):
            raise CapabilityError("invalid persisted capability: metadata must be key/value string pairs")
        try:
            return cls(capability_id=value["capability_id"], version=value["version"], owner=value["owner"], kind=value["kind"],
                       inputs=tuple(value.get("inputs", ())), outputs=tuple(value.get("outputs", ())),
                       permissions=tuple(value.get("permissions", ())), environments=tuple(value.get("environments", ())),
                       verification_methods=tuple(value.get("verification_methods", ())),
                       evidence_requirements=tuple(value.get("evidence_requirements", ())), provenance=tuple(value.get("provenance", ())),
                       dependencies=tuple(value.get("dependencies", ())), status=value.get("status", "CANDIDATE"),
                       metadata=tuple(tuple(x) for x in value.get("metadata", ())))
        except (KeyError, TypeError, ValueError) as exc:
            raise CapabilityError(f"invalid persisted capability: {exc}") from exc

@dataclass(frozen=True)
class CapabilityEdge:
    source: str
    relation: str
    target: str
    evidence_refs: tuple[str, ...] = ()
    verification_level: str = "OBSERVED"

    def __post_init__(self) -> None:
        if not all(isinstance(v, str) and v.strip() for v in (self.source, self.relation, self.target, self.verification_level)):
            raise CapabilityError("edge source, relation, target, and verification level must be non-empty strings")
        if self.relation not in ALLOWED_EDGE_TYPES:
            raise CapabilityError(f"unsupported relationship: {self.relation}")
        if self.verification_level not in VERIFICATION_LEVELS:
            raise CapabilityError("invalid verification level")

    def as_dict(self) -> dict[str, Any]:
        return {"source": self.source, "relation": self.relation, "target": self.target,
                "evidence_refs": list(self.evidence_refs), "verification_level": self.verification_level}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CapabilityEdge":
        if not isinstance(value, dict):
            raise CapabilityError("invalid persisted capability edge: record must be an object")
        refs = value.get("evidence_refs", ())
        if not isinstance(refs, (list, tuple)) or any(not isinstance(item, str) or not item.strip() for item in refs):
            raise CapabilityError("invalid persisted capability edge: evidence_refs must be a list of non-empty strings")
        try:
            return cls(source=value["source"], relation=value["relation"], target=value["target"],
                       evidence_refs=tuple(value.get("evidence_refs", ())),
                       verification_level=value.get("verification_level", "OBSERVED"))
        except (KeyError, TypeError, ValueError) as exc:
            raise CapabilityError(f"invalid persisted capability edge: {exc}") from exc

class CapabilityRegistry:
    """Deterministic registry with explicit AIOS durable-state persistence."""

    def __init__(self) -> None:
        self._capabilities: dict[str, Capability] = {}
        self._edges: dict[tuple[str, str, str], CapabilityEdge] = {}

    def register(self, capability: Capability) -> Capability:
        existing = self._capabilities.get(capability.key)
        if existing is not None and existing != capability:
            raise CapabilityError(f"capability version already registered: {capability.key}")
        self._capabilities[capability.key] = capability
        return capability

    def get(self, capability_id: str, version: str | None = None) -> Capability | None:
        if version is not None:
            return self._capabilities.get(f"{capability_id}@{version}")
        matches = [c for c in self._capabilities.values() if c.capability_id == capability_id]
        active = [c for c in matches if c.status == "ACTIVE"]
        return sorted(active or matches, key=lambda c: c.version)[-1] if matches else None

    def require(self, key: str) -> Capability:
        if not isinstance(key, str) or "@" not in key:
            raise CapabilityError(f"capability reference must be versioned: {key!r}")
        capability = self._capabilities.get(key)
        if capability is None:
            raise CapabilityError(f"capability is not registered: {key}")
        if capability.status == "CANDIDATE":
            raise CapabilityError(f"capability is not promoted ACTIVE: {key}")
        if capability.status == "DEPRECATED":
            raise CapabilityError(f"capability is deprecated: {key}")
        return capability

    def resolve_contract(self, contract: dict[str, Any]) -> tuple[Capability, ...]:
        if not isinstance(contract, dict) or not isinstance(contract.get("capabilities"), list):
            raise CapabilityError("contract capabilities must be a list")
        return tuple(self.require(key) for key in contract["capabilities"])

    def discover(self, *, kind: str | None = None, required_inputs: Iterable[str] = (), required_outputs: Iterable[str] = (),
                 environment: str | None = None, permission: str | None = None) -> list[Capability]:
        req_in, req_out = set(required_inputs), set(required_outputs)
        result = []
        for capability in self._capabilities.values():
            if capability.status == "DEPRECATED": continue
            if kind and capability.kind != kind: continue
            if req_in - set(capability.inputs) or req_out - set(capability.outputs): continue
            if environment and environment not in capability.environments: continue
            if permission and permission not in capability.permissions: continue
            result.append(capability)
        return sorted(result, key=lambda c: c.key)

    def add_edge(self, edge: CapabilityEdge) -> CapabilityEdge:
        if edge.source not in self._capabilities or edge.target not in self._capabilities:
            raise CapabilityError("edge endpoints must be registered capabilities")
        key = (edge.source, edge.relation, edge.target)
        existing = self._edges.get(key)
        if existing is not None and existing != edge:
            raise CapabilityError("relationship already exists with different evidence")
        self._edges[key] = edge
        return edge

    def relationships(self, source: str | None = None, relation: str | None = None, target: str | None = None) -> list[CapabilityEdge]:
        return sorted((e for e in self._edges.values() if (source is None or e.source == source)
                       and (relation is None or e.relation == relation) and (target is None or e.target == target)),
                      key=lambda e: (e.source, e.relation, e.target))

    def snapshot(self) -> dict[str, Any]:
        return {"capabilities": [c.as_dict() for c in sorted(self._capabilities.values(), key=lambda x: x.key)],
                "edges": [e.as_dict() for e in self.relationships()]}

    def persist(self, aios_dir: str | Path, actor: str) -> str:
        if not isinstance(actor, str) or not actor.strip():
            raise CapabilityError("actor must be a non-empty string")
        payload = {"schema_version": 1, **self.snapshot(), "persisted_by": actor}
        return commit_batch(str(aios_dir), [(CAPABILITY_STATE_FILE, payload)])[0]

    @classmethod
    def load(cls, aios_dir: str | Path) -> "CapabilityRegistry":
        filename = Path(aios_dir) / CAPABILITY_STATE_FILE
        if not filename.is_file():
            raise CapabilityError(f"capability registry not found: {filename}")
        try:
            data = json.loads(filename.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CapabilityError(f"invalid capability registry JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise CapabilityError("invalid capability registry: root must be an object")
        if data.get("schema_version") != 1:
            raise CapabilityError("unsupported capability registry schema_version")
        capabilities = data.get("capabilities", [])
        edges = data.get("edges", [])
        if not isinstance(capabilities, list) or not isinstance(edges, list):
            raise CapabilityError("invalid capability registry: capabilities and edges must be lists")
        registry = cls()
        seen_capabilities: set[str] = set()
        for raw in capabilities:
            capability = Capability.from_dict(raw)
            if capability.key in seen_capabilities:
                raise CapabilityError(f"duplicate capability record: {capability.key}")
            seen_capabilities.add(capability.key)
            registry.register(capability)
        seen_edges: set[tuple[str, str, str]] = set()
        for raw in edges:
            edge = CapabilityEdge.from_dict(raw)
            key = (edge.source, edge.relation, edge.target)
            if key in seen_edges:
                raise CapabilityError(f"duplicate capability edge: {key}")
            seen_edges.add(key)
            registry.add_edge(edge)
        return registry

__all__ = ["Capability", "CapabilityEdge", "CapabilityError", "CapabilityRegistry", "ALLOWED_EDGE_TYPES", "VERIFICATION_LEVELS", "CAPABILITY_STATE_FILE"]
