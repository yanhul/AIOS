"""AIOS-native implementations/conformance surface for absorbed research primitives.

This module maps absorbed primitive classes to existing AIOS-owned runtime
surfaces. It never imports or executes external repository code.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from core.capabilities import Capability, CapabilityRegistry
from core.durable_loop import MemoryStateStore
from core.durable_runtime import RuntimeSubmission, validate_submission
from core.evidence import EvidenceRecord, verify_evidence
from core.evidence_gate import gate_promotion
from core.research_worker import ResearchFinding, ResearchRequest, reconcile_research


@dataclass(frozen=True)
class PrimitiveImplementation:
    primitive: str
    capability_id: str
    implementation: str
    conformance: Callable[[], None]


def _durable_execution() -> None:
    store = MemoryStateStore()
    store.save({"step": 1, "status": "RUNNING", "history": [], "checkpoint": "c1"})
    loaded = store.load()
    assert loaded and loaded["checkpoint"] == "c1"


def _research_harness() -> None:
    request = ResearchRequest("absorb-proof", "verify research primitive", max_steps=1)
    finding = ResearchFinding("f1", "aios://proof", "claim", "evidence://f1")
    result = reconcile_research(request, (finding,))
    assert result["requires_aios_verification"] is True


def _evidence_provenance() -> None:
    record = EvidenceRecord("ev-proof", "VERIFIED_DIGITAL", "aios://source",
                            "claim", "run-proof", "aios-test")
    serialized = record.as_record()
    assert verify_evidence(serialized) is True


def _governance() -> None:
    decision = gate_promotion({
        "level": "VERIFIED_DIGITAL",
        "run_id": "run-proof",
        "source_ref": "aios://source",
        "claim": "claim",
    })
    assert decision.allowed is True
    blocked = gate_promotion({
        "level": "UNKNOWN",
        "run_id": "run-proof",
        "source_ref": "aios://source",
        "claim": "claim",
    })
    assert blocked.allowed is False


def _retry() -> None:
    effect = {"effect_id": "effect-proof"}
    submission = RuntimeSubmission("effect-proof", "attempt-1", "provider-proof")
    validate_submission(effect, submission, "attempt-1", "provider-proof")
    try:
        validate_submission(effect, submission, "attempt-wrong", "provider-proof")
    except ValueError:
        return
    raise AssertionError("mismatched attempt must fail closed")


def _memory() -> None:
    store = MemoryStateStore()
    store.save({"step": 2, "status": "RUNNING", "history": [{"step": 1}]})
    first = store.load()
    assert first is not None
    first["step"] = 999
    second = store.load()
    assert second and second["step"] == 2


def _harness() -> None:
    _durable_execution()
    _research_harness()
    _retry()


IMPLEMENTATIONS = (
    PrimitiveImplementation("durable_execution", "runtime.background_worker",
                            "core.durable_loop.MemoryStateStore + core.durable_runtime", _durable_execution),
    PrimitiveImplementation("research_harness", "research.deep",
                            "core.research_worker", _research_harness),
    PrimitiveImplementation("evidence_provenance", "research.deep",
                            "core.evidence.EvidenceRecord", _evidence_provenance),
    PrimitiveImplementation("governance", "software.audit",
                            "core.evidence_gate", _governance),
    PrimitiveImplementation("retry", "runtime.background_worker",
                            "core.durable_runtime.validate_submission", _retry),
    PrimitiveImplementation("memory", "runtime.background_worker",
                            "core.durable_loop.MemoryStateStore", _memory),
    PrimitiveImplementation("harness", "runtime.background_worker",
                            "core.durable_loop", _harness),
)


def run_conformance() -> dict[str, Any]:
    results = []
    for item in IMPLEMENTATIONS:
        try:
            item.conformance()
            results.append({
                "primitive": item.primitive,
                "capability_id": item.capability_id,
                "implementation": item.implementation,
                "status": "IMPLEMENTED_AND_CONFORMANT",
            })
        except Exception as exc:
            results.append({
                "primitive": item.primitive,
                "capability_id": item.capability_id,
                "implementation": item.implementation,
                "status": "BLOCKED",
                "error_type": type(exc).__name__,
            })
    return {
        "schema_version": 1,
        "kind": "AIOS_ABSORBED_CAPABILITY_IMPLEMENTATION_PROOF",
        "results": results,
        "implemented_count": sum(r["status"] == "IMPLEMENTED_AND_CONFORMANT" for r in results),
        "total_count": len(results),
        "overall": "PASS" if all(r["status"] == "IMPLEMENTED_AND_CONFORMANT" for r in results) else "BLOCKED",
    }


__all__ = ["PrimitiveImplementation", "IMPLEMENTATIONS", "run_conformance"]
