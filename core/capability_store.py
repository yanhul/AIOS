"""Durable, deterministic capability state for AIOS.

The store is intentionally separate from the in-memory registry. Registration,
relationship changes, and promotion remain governed operations; this module
only persists a registry snapshot through an atomic replace.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .capabilities import Capability, CapabilityEdge, CapabilityRegistry


class CapabilityStore:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def save(self, registry: CapabilityRegistry) -> None:
        payload = registry.snapshot()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, sort_keys=True, indent=2)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def load(self) -> CapabilityRegistry:
        registry = CapabilityRegistry()
        if not self.path.exists():
            return registry
        with self.path.open("r", encoding="utf-8") as fh:
            payload: dict[str, Any] = json.load(fh)
        for raw in payload.get("capabilities", []):
            registry.register(Capability(
                capability_id=raw["capability_id"], version=raw["version"],
                owner=raw["owner"], kind=raw["kind"],
                inputs=tuple(raw.get("inputs", ())), outputs=tuple(raw.get("outputs", ())),
                permissions=tuple(raw.get("permissions", ())), environments=tuple(raw.get("environments", ())),
                verification_methods=tuple(raw.get("verification_methods", ())),
                evidence_requirements=tuple(raw.get("evidence_requirements", ())),
                provenance=tuple(raw.get("provenance", ())), dependencies=tuple(raw.get("dependencies", ())),
                status=raw.get("status", "CANDIDATE"), metadata=tuple(tuple(x) for x in raw.get("metadata", ())),
            ))
        for raw in payload.get("edges", []):
            registry.add_edge(CapabilityEdge(
                source=raw["source"], relation=raw["relation"], target=raw["target"],
                evidence_refs=tuple(raw.get("evidence_refs", ())),
                verification_level=raw.get("verification_level", "OBSERVED"),
            ))
        return registry
