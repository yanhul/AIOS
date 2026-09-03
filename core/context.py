"""First-class execution context used for governed capability matching."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True)
class ExecutionContext:
    task_id: str
    agent_id: str | None = None
    device_id: str | None = None
    software: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    network: str | None = None
    location: str | None = None
    time_context: str | None = None
    resources: Mapping[str, str] = field(default_factory=dict)
    physical_state: Mapping[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "device_id": self.device_id,
            "software": list(self.software),
            "permissions": list(self.permissions),
            "network": self.network,
            "location": self.location,
            "time_context": self.time_context,
            "resources": dict(sorted(self.resources.items())),
            "physical_state": dict(sorted(self.physical_state.items())),
        }
