"""Deterministic registry for AIOS workload adapters.

The registry is discovery metadata only. It does not grant capabilities,
issue permits, change policy, or decide promotion/terminal state.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping


@dataclass(frozen=True)
class WorkloadRegistration:
    """Immutable registration metadata for one workload adapter."""

    workload_id: str
    capability_id: str
    version: str
    adapter: str

    def __post_init__(self) -> None:
        for name, value in (
            ("workload_id", self.workload_id),
            ("capability_id", self.capability_id),
            ("version", self.version),
            ("adapter", self.adapter),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")


class WorkloadRegistry:
    """Fail-closed registry with deterministic lookup and immutable snapshots."""

    def __init__(self, registrations: Mapping[str, WorkloadRegistration] | None = None):
        self._items: dict[str, WorkloadRegistration] = {}
        if registrations:
            for key, registration in registrations.items():
                self.register(key, registration)

    def register(self, workload_id: str, registration: WorkloadRegistration) -> None:
        if not isinstance(workload_id, str) or not workload_id.strip():
            raise ValueError("workload_id must be a non-empty string")
        if not isinstance(registration, WorkloadRegistration):
            raise TypeError("registration must be WorkloadRegistration")
        if registration.workload_id != workload_id:
            raise ValueError("registration workload_id mismatch")
        if workload_id in self._items:
            raise ValueError(f"workload already registered: {workload_id}")
        if any(item.capability_id == registration.capability_id for item in self._items.values()):
            raise ValueError(f"capability already registered: {registration.capability_id}")
        self._items[workload_id] = registration

    def resolve(self, workload_id: str) -> WorkloadRegistration:
        try:
            return self._items[workload_id]
        except KeyError as exc:
            raise KeyError(f"unknown workload: {workload_id}") from exc

    def snapshot(self) -> Mapping[str, WorkloadRegistration]:
        return MappingProxyType(dict(self._items))

    def __len__(self) -> int:
        return len(self._items)

    @classmethod
    def from_capability_entries(cls, entries: list[Mapping[str, Any]]) -> "WorkloadRegistry":
        """Build discovery registry from normative capability entries.

        No authorization decision is made here; capability authority remains in
        AIOS authority/permit layers.
        """
        registry = cls()
        for entry in entries:
            required = {"capability_id", "version", "owner", "manifest"}
            missing = required - set(entry)
            if missing:
                raise ValueError(f"capability entry missing fields: {sorted(missing)}")
            capability_id = entry["capability_id"]
            owner = entry["owner"]
            workload_id = f"{owner}@{entry['version']}"
            registry.register(
                workload_id,
                WorkloadRegistration(
                    workload_id=workload_id,
                    capability_id=capability_id,
                    version=str(entry["version"]),
                    adapter=entry["manifest"],
                ),
            )
        return registry


__all__ = ["WorkloadRegistration", "WorkloadRegistry"]
