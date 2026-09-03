"""Load and validate the declarative AIOS capability catalog."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from .capabilities import Capability, CapabilityEdge, CapabilityRegistry


def _tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError("catalog list fields must be YAML lists")
    return tuple(str(item) for item in value)


def load_catalog(path: str | Path) -> CapabilityRegistry:
    """Load registry.yaml and fail closed on malformed catalog data."""
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required to load the capability catalog") from exc
    with Path(path).open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    registry = CapabilityRegistry()
    for raw in data.get("capabilities", []):
        registry.register(Capability(
            capability_id=str(raw["capability_id"]), version=str(raw["version"]),
            owner=str(raw["owner"]), kind=str(raw["kind"]),
            inputs=_tuple(raw.get("inputs")), outputs=_tuple(raw.get("outputs")),
            verification_methods=_tuple(raw.get("verification")),
            environments=_tuple(raw.get("context")),
            provenance=(str(raw.get("source", "")),),
            status="ACTIVE" if str(data.get("status")) == "normative" else "CANDIDATE",
        ))
    for raw in data.get("relationships", []):
        registry.add_edge(CapabilityEdge(
            source=str(raw["source"]), relation=str(raw["relation"]), target=str(raw["target"]),
            evidence_refs=_tuple(raw.get("evidence_refs")),
            verification_level=str(raw.get("verification_level", "OBSERVED")),
        ))
    return registry
