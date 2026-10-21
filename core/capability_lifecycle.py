"""Rome-adapted capability lifecycle with AIOS hard gates.

This module adapts the useful Rome primitive—persistent, composable,
versioned capabilities—without weakening AIOS authority/evidence/lineage.
Capability definitions remain immutable registry entries. Promotion is an
attestation over an exact capability revision; composition records exact
dependency revisions and a deterministic dependency snapshot digest.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Iterable

from .capabilities import CapabilityError, CapabilityRegistry


def _digest(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class CapabilityAttestation:
    capability_key: str
    source_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    verification_level: str
    authority: str
    predecessor_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.capability_key or "@" not in self.capability_key:
            raise CapabilityError("attestation requires an exact versioned capability key")
        if not self.source_refs or any(not x.strip() for x in self.source_refs):
            raise CapabilityError("attestation requires source provenance")
        if not self.evidence_refs or any(not x.strip() for x in self.evidence_refs):
            raise CapabilityError("attestation requires evidence")
        if self.verification_level not in {"VERIFIED_DIGITAL", "VERIFIED_PHYSICAL"}:
            raise CapabilityError("promotion requires verified evidence")
        if not self.authority.strip():
            raise CapabilityError("promotion authority is required")

    @property
    def digest(self) -> str:
        return _digest({
            "capability_key": self.capability_key,
            "source_refs": self.source_refs,
            "evidence_refs": self.evidence_refs,
            "verification_level": self.verification_level,
            "authority": self.authority,
            "predecessor_keys": self.predecessor_keys,
        })


@dataclass(frozen=True)
class CapabilityComposition:
    composition_key: str
    dependency_keys: tuple[str, ...]
    dependency_snapshot_digest: str
    evidence_refs: tuple[str, ...]
    authority: str

    def __post_init__(self) -> None:
        if not self.composition_key or "@" not in self.composition_key:
            raise CapabilityError("composition requires an exact versioned key")
        if not self.dependency_keys:
            raise CapabilityError("composition requires exact dependency revisions")
        if not self.dependency_snapshot_digest:
            raise CapabilityError("composition requires dependency snapshot digest")
        if not self.evidence_refs or any(not x.strip() for x in self.evidence_refs):
            raise CapabilityError("composition requires evidence")
        if not self.authority.strip():
            raise CapabilityError("composition authority is required")


class CapabilityLifecycle:
    """Fail-closed discovery, attestation and composition facade."""

    def __init__(self, registry: CapabilityRegistry) -> None:
        self.registry = registry

    def discover(self, **filters):
        return self.registry.discover(**filters)

    def attest(
        self,
        capability_key: str,
        *,
        source_refs: Iterable[str],
        evidence_refs: Iterable[str],
        verification_level: str,
        authority: str,
        predecessor_keys: Iterable[str] = (),
    ) -> CapabilityAttestation:
        self.registry.require(capability_key)
        return CapabilityAttestation(
            capability_key=capability_key,
            source_refs=tuple(source_refs),
            evidence_refs=tuple(evidence_refs),
            verification_level=verification_level,
            authority=authority,
            predecessor_keys=tuple(predecessor_keys),
        )

    def dependency_snapshot(self, dependency_keys: Iterable[str]) -> tuple[tuple[str, str], ...]:
        keys = tuple(sorted(set(dependency_keys)))
        if not keys:
            raise CapabilityError("dependency snapshot cannot be empty")
        resolved = []
        for key in keys:
            capability = self.registry.require(key)
            resolved.append((capability.key, _digest(capability.as_dict())))
        return tuple(resolved)

    def compose(
        self,
        composition_key: str,
        dependency_keys: Iterable[str],
        *,
        evidence_refs: Iterable[str],
        authority: str,
    ) -> CapabilityComposition:
        dependencies = tuple(sorted(set(dependency_keys)))
        snapshot = self.dependency_snapshot(dependencies)
        return CapabilityComposition(
            composition_key=composition_key,
            dependency_keys=dependencies,
            dependency_snapshot_digest=_digest(snapshot),
            evidence_refs=tuple(evidence_refs),
            authority=authority,
        )

    def verify_composition_current(self, composition: CapabilityComposition) -> bool:
        current = self.dependency_snapshot(composition.dependency_keys)
        return _digest(current) == composition.dependency_snapshot_digest


__all__ = ["CapabilityAttestation", "CapabilityComposition", "CapabilityLifecycle"]
