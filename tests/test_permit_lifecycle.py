import tempfile

import pytest

from core.authority import (
    authorize,
    load_permit_lifecycle,
    persist_attestation,
    persist_contract,
    persist_permit,
    revoke_permit,
)
from core.capabilities import Capability, CapabilityRegistry
from core.mutation import TransitionError
from core.policy_registry import persist_policy


def make_contract(policy_digest, task_id="RESEARCH_BC7"):
    return {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": task_id,
        "scope": "research",
        "actor": "bc-controller",
        "capabilities": ["research_is_validation@1"],
        "input_digest": "sha256:input-" + task_id,
        "allowed_effects": ["persist_evidence"],
        "evidence_required": ["is_validation_report"],
        "max_attempts": 3,
        "terminal_states": ["PROMOTED", "REJECTED", "HOLD"],
        "policy_digest": policy_digest,
    }


def setup_authority(td):
    registry = CapabilityRegistry()
    registry.register(Capability("research_is_validation", "1", "test-fixture", "research", status="ACTIVE"))
    registry.persist(td, "test-fixture")
    policy = persist_policy(td, {"policy_type": "GOVERNING_POLICY", "name": "research-fixture"})
    contract = make_contract(policy)
    persist_contract(td, contract)
    permit = persist_permit(td, contract, "AIOS_AUTHORITY")
    return contract, permit


def test_new_permit_is_active_and_authorizes():
    with tempfile.TemporaryDirectory() as td:
        contract, permit = setup_authority(td)
        assert authorize(td, permit["contract_id"], permit["permit_id"]) is True
        lifecycle = load_permit_lifecycle(td, permit["permit_id"])
        assert lifecycle["status"] == "ACTIVE"
        assert lifecycle["lifecycle_sequence"] == 1


def test_revoked_permit_is_rejected_and_stays_terminal():
    with tempfile.TemporaryDirectory() as td:
        contract, permit = setup_authority(td)
        revoked = revoke_permit(td, permit["permit_id"], revoked_by="AIOS_AUTHORITY", reason_code="TEST_REVOKE")
        assert revoked["status"] == "REVOKED"
        assert revoked["lifecycle_sequence"] == 2
        with pytest.raises(TransitionError, match="permit lifecycle is REVOKED"):
            authorize(td, contract["task_id"] and permit["contract_id"], permit["permit_id"])
        with pytest.raises(TransitionError, match="permit lifecycle is REVOKED"):
            revoke_permit(td, permit["permit_id"], revoked_by="AIOS_AUTHORITY", reason_code="DOUBLE_REVOKE")


def test_valid_attestation_does_not_bypass_revocation():
    with tempfile.TemporaryDirectory() as td:
        contract, permit = setup_authority(td)
        attestation = persist_attestation(td, contract, permit, "test-secret")
        assert attestation["permit_id"] == permit["permit_id"]
        revoke_permit(td, permit["permit_id"], revoked_by="AIOS_AUTHORITY", reason_code="TEST_REVOKE")
        with pytest.raises(TransitionError):
            authorize(td, permit["contract_id"], permit["permit_id"])


def test_revocation_survives_restart_and_does_not_affect_other_permit():
    with tempfile.TemporaryDirectory() as td:
        contract_a, permit_a = setup_authority(td)
        policy = contract_a["policy_digest"]
        contract_b = make_contract(policy, task_id="RESEARCH_BC8")
        persist_contract(td, contract_b)
        permit_b = persist_permit(td, contract_b, "AIOS_AUTHORITY")
        revoke_permit(td, permit_a["permit_id"], revoked_by="AIOS_AUTHORITY", reason_code="TEST_REVOKE")
        assert load_permit_lifecycle(td, permit_a["permit_id"])["status"] == "REVOKED"
        assert authorize(td, permit_b["contract_id"], permit_b["permit_id"]) is True


def test_stale_lifecycle_sequence_cannot_replace_newer_state():
    with tempfile.TemporaryDirectory() as td:
        _, permit = setup_authority(td)
        revoke_permit(td, permit["permit_id"], revoked_by="AIOS_AUTHORITY", reason_code="TEST_REVOKE")
        with pytest.raises(TransitionError, match="lifecycle sequence"):
            revoke_permit(td, permit["permit_id"], revoked_by="AIOS_AUTHORITY", reason_code="STALE", expected_sequence=1)
