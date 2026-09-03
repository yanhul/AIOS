"""AIOS capability identity, registry, and relationship graph.

The registry is deliberately model-agnostic. A capability is a governed
execution surface (agent, tool, workload, device, service, etc.), not a model
claim. Trust/reuse metadata is descriptive evidence; promotion remains an
external authority decision.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


ALLOWED_EDGE_TYPES = frozenset({
    "requires", "produces", "composes_with", "validated_by", "works_under",
})


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
        for name, value in (("capability_id", self.capability_id), ("version", self.version),
                            ("owner", self.owner), ("kind", self.kind)):
            if not value or not isinstance(value, str):
                raise CapabilityError(f"{name} must be a non-empty string")
        if self.status not in {"CANDIDATE", "ACTIVE", "DEPRECATED"}:
            raise CapabilityError("invalid capability status")

    @property
    def key(self) -> str:
        return f"{self.capability_id}@{self.version}"


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
        if self.verification_level not in {
            "OBSERVED", "EVIDENCED", "VERIFIED_DIGITAL", "VERIFIED_PHYSICAL", "PROMOTED"
        }:
            raise CapabilityError("invalid verification level")


class CapabilityRegistry:
    """In-memory deterministic registry; persistence belongs to AIOS state."""

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

    def discover(self, *, kind: str | None = None, required_inputs: Iterable[str] = (),
                 required_outputs: Iterable[str] = (), environment: str | None = None,
                 permission: str | None = None) -> list[Capability]:
        req_in = set(required_inputs)
        req_out = set(required_outputs)
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

    def relationships(self, source: str | None = None, relation: str | None = None,
                      target: str | None = None) -> list[CapabilityEdge]:
        return sorted(
            (e for e in self._edges.values()
             if (source is None or e.source == source)
             and (relation is None or e.relation == relation)
             and (target is None or e.target == target)),
            key=lambda e: (e.source, e.relation, e.target),
        )

    def snapshot(self) -> dict[str, Any]:
        return {
            "capabilities": [c.__dict__ for c in sorted(self._capabilities.values(), key=lambda x: x.key)],
            "edges": [e.__dict__ for e in self.relationships()],
        }
