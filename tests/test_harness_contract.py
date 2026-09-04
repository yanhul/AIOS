from __future__ import annotations

import pytest

from core.harness_contract import (
    TERMINAL,
    EvidenceRef,
    HarnessPolicy,
    HarnessState,
    authorize_effect,
    terminal_from_control_plane,
)


def policy(**overrides):
    values = dict(
        execution_id="exec-1",
        contract_id="contract-1",
        contract_version="1",
        policy_digest="sha256:policy",
        capability_id="cap.research",
        capability_version="1.0.0",
        max_steps=5,
        max_retries=2,
        allowed_effects=frozenset({"filesystem.write", "process.exec"}),
    )
    values.update(overrides)
    return HarnessPolicy(**values)


def test_policy_terminal_states_are_immutable():
    assert policy().terminal_states == TERMINAL
    with pytest.raises(ValueError):
        policy(terminal_states=frozenset({"PASS", "BLOCKED", "AGENT_DECIDES"}))


def test_resume_rejects_stale_policy():
    p = policy()
    state = HarnessState(
        execution_id="exec-1",
        policy_digest="sha256:old",
        capability_id="cap.research",
        capability_version="1.0.0",
        budget_remaining=4,
        retry_budget_remaining=2,
    )
    with pytest.raises(ValueError, match="policy digest"):
        state.validate(p)


def test_resume_rejects_stale_capability_version():
    p = policy()
    state = HarnessState(
        execution_id="exec-1",
        policy_digest="sha256:policy",
        capability_id="cap.research",
        capability_version="0.9.0",
        budget_remaining=4,
        retry_budget_remaining=2,
    )
    with pytest.raises(ValueError, match="capability version"):
        state.validate(p)


def test_effect_must_be_declared_and_have_id():
    p = policy()
    with pytest.raises(PermissionError):
        authorize_effect(p, {"effect_type": "network.write", "effect_id": "e1"})
    with pytest.raises(ValueError, match="effect_id"):
        authorize_effect(p, {"effect_type": "process.exec"})
    authorize_effect(p, {"effect_type": "process.exec", "effect_id": "e1"})


def test_terminal_decision_is_control_plane_bounded():
    p = policy()
    assert terminal_from_control_plane(p, None) is None
    assert terminal_from_control_plane(p, "PASS") == "PASS"
    with pytest.raises(ValueError):
        terminal_from_control_plane(p, "DONE")


def test_terminal_state_requires_reason():
    p = policy()
    state = HarnessState(
        execution_id="exec-1",
        policy_digest="sha256:policy",
        capability_id="cap.research",
        capability_version="1.0.0",
        status="PASS",
        budget_remaining=4,
        retry_budget_remaining=2,
    )
    with pytest.raises(ValueError, match="reason"):
        state.validate(p)


def test_evidence_is_provenance_bearing():
    evidence = EvidenceRef(
        ref="artifact://run/1",
        source="pytest",
        claim="contract accepted",
        verification_level="VERIFIED_DIGITAL",
        digest="sha256:abc",
    )
    assert evidence.digest == "sha256:abc"
