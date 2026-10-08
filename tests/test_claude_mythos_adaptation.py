# AIOS-CONTRACT: epistemic discovery, observation, and capability-routing boundaries
# AIOS-REGRESSION: Claude Mythos 5.1 adaptation must not promote guesses/tool success
# AIOS-OWNER: AIOS control-plane epistemic boundary
# AIOS-COVERAGE-GAP: full repository integration and provider-specific execution remain covered elsewhere
# AIOS-BASELINE: main

from __future__ import annotations

import json
import pytest

from core.capabilities import Capability
from core.epistemic import (
    ClaimStatus, ToolResult, Volatility, assert_authoritative_claim, classify_claim,
    observe_tool_result, promote_observation, requires_discovery,
    route_capabilities,
)


def test_volatile_claims_require_discovery() -> None:
    assert requires_discovery(Volatility.STABLE) is False
    assert requires_discovery(Volatility.CURRENT) is True
    assert requires_discovery(Volatility.RECENT) is True
    assert requires_discovery(Volatility.UNKNOWN) is True


def test_model_guess_never_becomes_fact_or_verified() -> None:
    assert classify_claim(source_kind="model_guess") == ClaimStatus.ASSUMPTION
    assert classify_claim(source_kind="unknown") == ClaimStatus.UNKNOWN
    with pytest.raises(TypeError):
        classify_claim(source_kind="model_guess", verified=True)  # type: ignore[call-arg]


def test_classification_is_not_authority(tmp_path) -> None:
    assert classify_claim(source_kind="authoritative_record") == ClaimStatus.FACT
    with pytest.raises(PermissionError):
        assert_authoritative_claim(
            claim_id="claim-authority", status=ClaimStatus.FACT, volatility=Volatility.STABLE,
            verification_evidence=[], aios_dir=str(tmp_path), verifier="test-verifier",
        )


def test_current_claim_requires_discovery_evidence(tmp_path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "EV-discovery.json").write_text(json.dumps({
        "entity_type": "EVIDENCE", "entity_id": "EV-discovery",
    }), encoding="utf-8")
    assert_authoritative_claim(
        claim_id="claim-current", status=ClaimStatus.FACT, volatility=Volatility.CURRENT,
        verification_evidence=[("EVIDENCE", "EV-discovery")],
        aios_dir=str(tmp_path), verifier="test-verifier",
    )


def test_current_claim_without_discovery_is_blocked(tmp_path) -> None:
    with pytest.raises(PermissionError):
        assert_authoritative_claim(
            claim_id="claim-current-blocked", status=ClaimStatus.FACT, volatility=Volatility.CURRENT,
            verification_evidence=[], aios_dir=str(tmp_path), verifier="test-verifier",
        )


def test_tool_success_is_not_world_state_verification(tmp_path) -> None:
    result = ToolResult("provider-a", "inv-1", {"success": True})
    observation = observe_tool_result(
        result, observation_id="obs-1",
        source_ref="provider-a:inv-1", claim="requested effect is present",
    )
    assert observation.verified is False
    with pytest.raises(PermissionError):
        promote_observation(
            observation, aios_dir=str(tmp_path),
            verification_evidence=[], verifier="test-verifier",
        )


def test_independent_evidence_is_required_for_promotion(tmp_path) -> None:
    result = ToolResult("provider-a", "inv-2", {"status": "ok"})
    observation = observe_tool_result(
        result, observation_id="obs-2",
        source_ref="provider-a:inv-2", claim="effect is observed",
    )
    with pytest.raises(PermissionError):
        promote_observation(
            observation, aios_dir=str(tmp_path),
            verification_evidence=[("EVIDENCE", "EV-missing")], verifier="test-verifier",
        )
    evidence_dir = tmp_path / "evidence"
    # Native verification may materialize the evidence directory while rejecting
    # an unresolved reference; the test must assert verification semantics, not
    # an incidental filesystem precondition.
    evidence_dir.mkdir(exist_ok=True)
    (evidence_dir / "EV-test.json").write_text(json.dumps({
        "entity_type": "EVIDENCE", "entity_id": "EV-test",
    }), encoding="utf-8")
    promoted = promote_observation(
        observation, aios_dir=str(tmp_path),
        verification_evidence=[("EVIDENCE", "EV-test")], verifier="test-verifier",
    )
    assert promoted.verified is True


def test_failed_tool_result_cannot_be_observation() -> None:
    with pytest.raises(ValueError):
        observe_tool_result(
            ToolResult("provider-a", "inv-3", {"error": "timeout"}, success=False),
            observation_id="obs-3", source_ref="provider-a:inv-3", claim="effect exists",
        )


def test_observation_verification_uses_observation_namespace(tmp_path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "EV-test.json").write_text(json.dumps({
        "entity_type": "EVIDENCE", "entity_id": "EV-test",
    }), encoding="utf-8")
    result = ToolResult("provider-a", "inv-namespace", {"status": "ok"})
    observation = observe_tool_result(
        result, observation_id="obs-namespace",
        source_ref="provider-a:inv-namespace", claim="effect is observed",
    )
    promote_observation(
        observation, aios_dir=str(tmp_path),
        verification_evidence=[("EVIDENCE", "EV-test")], verifier="test-verifier",
    )
    records = list((tmp_path / "verifications").glob("*.json"))
    assert records
    record = json.loads(records[0].read_text(encoding="utf-8"))
    assert record["subject_type"] == "OBSERVATION"
    assert record["subject_id"] == "obs-namespace"


def test_capability_routing_is_descriptive_not_authoritative() -> None:
    a = Capability(
        capability_id="web-search", version="1", owner="provider-a", kind="discovery",
        outputs=("current-fact",), environments=("network",), status="ACTIVE",
    )
    b = Capability(
        capability_id="local-search", version="1", owner="provider-b", kind="discovery",
        outputs=("current-fact",), environments=("local",), status="ACTIVE",
    )
    selected = route_capabilities(
        [b, a], required_outputs=["current-fact"], environment="network"
    )
    assert [x.key for x in selected] == ["web-search@1"]
    assert selected[0].status == "ACTIVE"
