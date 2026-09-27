# AIOS-CONTRACT: Rome-adapted capability lifecycle cannot bypass exact revision, evidence, or authority gates
# AIOS-REGRESSION: capability promotion/composition must remain fail-closed
# AIOS-OWNER: AIOS control-plane capability authority
# AIOS-COVERAGE-GAP: Rome's mutable/self-building semantics are intentionally replaced by immutable revision attestation
# AIOS-BASELINE: capability registry already provides immutable versioned registration

import pytest

from core.capabilities import Capability, CapabilityRegistry, CapabilityError
from core.capability_lifecycle import CapabilityLifecycle


def registry():
    r = CapabilityRegistry()
    r.register(Capability("a", "1", "test", "action", status="CANDIDATE"))
    r.register(Capability("b", "1", "test", "validator", status="CANDIDATE"))
    return r


def test_attestation_requires_exact_revision_and_evidence():
    life = CapabilityLifecycle(registry())
    with pytest.raises(CapabilityError):
        life.attest("a", source_refs=("rome",), evidence_refs=(),
                    verification_level="VERIFIED_DIGITAL", authority="control")
    att = life.attest(
        "a@1",
        source_refs=("rome",),
        evidence_refs=("receipt:1",),
        verification_level="VERIFIED_DIGITAL",
        authority="AIOS_CONTROL_PLANE",
    )
    assert att.capability_key == "a@1"
    assert att.digest


def test_unknown_or_unversioned_revision_fails_closed():
    life = CapabilityLifecycle(registry())
    with pytest.raises(CapabilityError):
        life.attest("a", source_refs=("rome",), evidence_refs=("e",),
                    verification_level="VERIFIED_DIGITAL", authority="control")
    with pytest.raises(CapabilityError):
        life.attest("a@2", source_refs=("rome",), evidence_refs=("e",),
                    verification_level="VERIFIED_DIGITAL", authority="control")


def test_composition_records_exact_dependency_revisions():
    life = CapabilityLifecycle(registry())
    c = life.compose(
        "composed@1",
        ("b@1", "a@1"),
        evidence_refs=("receipt:compose",),
        authority="AIOS_CONTROL_PLANE",
    )
    assert c.dependency_keys == ("a@1", "b@1")
    assert life.verify_composition_current(c)


def test_new_revision_does_not_mutate_old_composition():
    life = CapabilityLifecycle(registry())
    c = life.compose(
        "composed@1",
        ("a@1",),
        evidence_refs=("receipt:compose",),
        authority="AIOS_CONTROL_PLANE",
    )
    life.registry.register(Capability("a", "2", "test", "action", status="CANDIDATE"))
    assert life.verify_composition_current(c)
    assert c.dependency_keys == ("a@1",)


def test_composition_rejects_unknown_dependency_revision():
    life = CapabilityLifecycle(registry())
    with pytest.raises(CapabilityError):
        life.compose(
            "composed@2",
            ("a@3",),
            evidence_refs=("receipt:new",),
            authority="AIOS_CONTROL_PLANE",
        )


def test_promotion_cannot_be_inferred_from_registry_status():
    life = CapabilityLifecycle(registry())
    att = life.attest(
        "a@1",
        source_refs=("rome",),
        evidence_refs=("evidence:verified",),
        verification_level="VERIFIED_DIGITAL",
        authority="AIOS_CONTROL_PLANE",
    )
    assert att.capability_key == "a@1"
    assert life.registry.require("a@1").status == "CANDIDATE"
