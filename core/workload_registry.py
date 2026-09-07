"""Deterministic discovery registry for AIOS workload adapters.

The registry is metadata-only. It never grants capabilities, issues permits,
changes policy, decides promotion, or defines terminal states.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping


@dataclass(frozen=True)
class WorkloadRegistration:
    """Immutable registration metadata for one workload capability version."""

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
        capability_ref = (registration.capability_id, registration.version)
        if any((item.capability_id, item.version) == capability_ref for item in self._items.values()):
            raise ValueError(
                f"capability version already registered: {registration.capability_id}@{registration.version}"
            )
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
        """Build discovery metadata from normative capability entries only."""
        registry = cls()
        for entry in entries:
            required = {"capability_id", "version", "owner", "manifest"}
            missing = required - set(entry)
            if missing:
                raise ValueError(f"capability entry missing fields: {sorted(missing)}")
            capability_id = entry["capability_id"]
            version = entry["version"]
            owner = entry["owner"]
            manifest = entry["manifest"]
            if not all(isinstance(v, str) and v.strip() for v in (capability_id, version, owner, manifest)):
                raise ValueError("capability entry metadata must be non-empty strings")
            workload_id = f"{owner}@{version}"
            registry.register(
                workload_id,
                WorkloadRegistration(
                    workload_id=workload_id,
                    capability_id=capability_id,
                    version=version,
                    adapter=manifest,
                ),
            )
        return registry


__all__ = ["WorkloadRegistration", "WorkloadRegistry"]
