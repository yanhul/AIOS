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
        if self.relation not in ALLOWED_EDGE_TYPES:
            raise CapabilityError(f"unsupported relationship: {self.relation}")
        if not self.source or not self.target:
            raise CapabilityError("edge endpoints are required")
        if self.verification_level not in VERIFICATION_LEVELS:
            raise CapabilityError("invalid verification level")

    def as_dict(self) -> dict[str, Any]:
        return {"source": self.source, "relation": self.relation, "target": self.target,
                "evidence_refs": list(self.evidence_refs), "verification_level": self.verification_level}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CapabilityEdge":
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
        """Resolve an exact versioned capability or fail closed."""
        if not isinstance(key, str) or "@" not in key:
            raise CapabilityError(f"capability reference must be versioned: {key!r}")
        capability = self._capabilities.get(key)
        if capability is None:
            raise CapabilityError(f"capability is not registered: {key}")
        if capability.status == "DEPRECATED":
            raise CapabilityError(f"capability is deprecated: {key}")
        return capability

    def resolve_contract(self, contract: dict[str, Any]) -> tuple[Capability, ...]:
        """Bind every contract capability reference to a registered capability.

        This is intentionally separate from contract validation: the contract
        module defines syntax/binding, while the registry defines whether the
        named execution surfaces actually exist.
        """
        if not isinstance(contract, dict) or not isinstance(contract.get("capabilities"), list):
            raise CapabilityError("contract capabilities must be a list")
        resolved = tuple(self.require(key) for key in contract["capabilities"])
        return resolved

    def discover(self, *, kind: str | None = None, required_inputs: Iterable[str] = (), required_outputs: Iterable[str] = (),
                 environment: str | None = None, permission: str | None = None) -> list[Capability]:
        req_in, req_out = set(required_inputs), set(required_outputs)
        result = []
        for capability in self._capabilities.values():
            if capability.status == "DEPRECATED":
                continue
            if kind and capability.kind != kind:
                continue
            if req_in - set(capability.inputs) or req_out - set(capability.outputs):
                continue
            if environment and environment not in capability.environments:
                continue
            if permission and permission not in capability.permissions:
                continue
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
        return {"schema_version": 1,
                "capabilities": [c.as_dict() for c in sorted(self._capabilities.values(), key=lambda x: x.key)],
                "edges": [e.as_dict() for e in self.relationships()]}

    def persist(self, aios_dir: str | Path, actor: str) -> str:
        """Atomically persist the registry through AIOS' shared commit boundary."""
        if not isinstance(actor, str) or not actor.strip():
            raise CapabilityError("actor must be a non-empty string")
        payload = self.snapshot()
        payload["persisted_by"] = actor
        return commit_batch(str(aios_dir), [(CAPABILITY_STATE_FILE, payload)])[0]

    @classmethod
    def load(cls, aios_dir: str | Path) -> "CapabilityRegistry":
        """Load durable state and validate every capability and graph edge."""
        filename = Path(aios_dir) / CAPABILITY_STATE_FILE
        if not filename.is_file():
            raise CapabilityError(f"capability registry not found: {filename}")
        try:
            data = json.loads(filename.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise CapabilityError(f"invalid capability registry JSON: {exc}") from exc
        if data.get("schema_version") != 1:
            raise CapabilityError("unsupported capability registry schema_version")
        registry = cls()
        for raw in data.get("capabilities", []):
            registry.register(Capability.from_dict(raw))
        for raw in data.get("edges", []):
            registry.add_edge(CapabilityEdge.from_dict(raw))
        return registry

__all__ = ["Capability", "CapabilityEdge", "CapabilityError", "CapabilityRegistry", "ALLOWED_EDGE_TYPES", "VERIFICATION_LEVELS", "CAPABILITY_STATE_FILE"]
