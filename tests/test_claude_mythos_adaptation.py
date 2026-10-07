from __future__ import annotations

import pytest

from core.capabilities import Capability
from core.epistemic import (
    ClaimStatus, ToolResult, Volatility, classify_claim,
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
    assert classify_claim(source_kind="model_guess", verified=False) != ClaimStatus.VERIFIED


def test_tool_success_is_not_world_state_verification() -> None:
    result = ToolResult("provider-a", "inv-1", {"success": True})
    observation = observe_tool_result(
        result, observation_id="obs-1",
        source_ref="provider-a:inv-1", claim="requested effect is present",
    )
    assert observation.verified is False
    with pytest.raises(PermissionError):
        promote_observation(observation, verification_evidence=[])


def test_independent_evidence_is_required_for_promotion() -> None:
    result = ToolResult("provider-a", "inv-2", {"status": "ok"})
    observation = observe_tool_result(
        result, observation_id="obs-2",
        source_ref="provider-a:inv-2", claim="effect is observed",
    )
    promoted = promote_observation(observation, verification_evidence=["verify-run-7"])
    assert promoted.verified is True


def test_failed_tool_result_cannot_be_observation() -> None:
    with pytest.raises(ValueError):
        observe_tool_result(
            ToolResult("provider-a", "inv-3", {"error": "timeout"}, success=False),
            observation_id="obs-3", source_ref="provider-a:inv-3", claim="effect exists",
        )


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
