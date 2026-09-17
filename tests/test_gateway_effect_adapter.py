import json

import pytest

from core.attestation import issue_attestation
from core.authority import persist_attestation, persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity, issue_permit
from core.effect_authority import create_effect
from core.gateway_effect_adapter import build_gateway_effect_contract
from core.policy_registry import persist_policy

SECRET = "test-secret"


def _authority(tmp_path):
    registry = CapabilityRegistry()
    registry.register(Capability("try.research", "1", "test", "research", status="ACTIVE"))
    registry.persist(str(tmp_path), "test")
    policy = persist_policy(str(tmp_path), {"policy_type": "GOVERNING_POLICY", "name": "gateway-test"})
    contract = {
        "contract_type": "EXECUTION_CONTRACT", "task_id": "task-1", "scope": "try",
        "actor": "aios", "capabilities": ["try.research@1"],
        "input_digest": "sha256:input", "allowed_effects": ["run_research"],
        "evidence_required": ["experiment_ledger"], "max_attempts": 2,
        "terminal_states": ["PASS", "BLOCKED", "INCONCLUSIVE"], "policy_digest": policy,
    }
    stored = persist_contract(str(tmp_path), contract)
    permit = persist_permit(str(tmp_path), stored, "AIOS_AUTHORITY")
    attestation = persist_attestation(str(tmp_path), stored, permit, SECRET)
    effect = create_effect(str(tmp_path), contract_identity(contract), "op-1", "aios", permit["permit_id"], "run_research")
    return contract, permit, attestation, effect


def _build(tmp_path, contract, permit, attestation, effect, **overrides):
    args = {
        "aios_dir": str(tmp_path), "persisted_effect": effect,
        "effect_id": effect["effect_id"], "action": "run_research",
        "capability_ref": "try.research@1", "authority_ref": permit["permit_id"],
        "authority_permit": permit, "authority_attestation": attestation,
        "attestation_secret": SECRET, "evidence_ref": "EV-1",
        "lineage_ref": "LIN-1", "idempotency_key": "idem-1",
    }
    args.update(overrides)
    return build_gateway_effect_contract(contract, **args)


def test_builds_gateway_v3_contract_from_current_persisted_authority(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    result = _build(tmp_path, contract, permit, attestation, effect)
    assert result["protocol_version"] == 3
    assert result["effect_id"] == effect["effect_id"]
    assert result["authority_ref"] == permit["permit_id"]


def test_stale_permit_is_rejected(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    stale = dict(permit, permit_id="PT-stale")
    with pytest.raises(ValueError):
        _build(tmp_path, contract, stale, attestation, effect, authority_ref="PT-stale")


def test_stale_attestation_is_rejected(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    stale = issue_attestation(contract, issue_permit(contract, "OLD_AUTHORITY"), SECRET)
    with pytest.raises(ValueError, match="attestation"):
        _build(tmp_path, contract, permit, stale, effect)


def test_revoked_capability_is_rejected_at_gateway_crossing(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    registry = CapabilityRegistry()
    registry.register(Capability("try.research", "1", "test", "research", status="DEPRECATED"))
    registry.persist(str(tmp_path), "revoker")
    with pytest.raises(Exception):
        _build(tmp_path, contract, permit, attestation, effect)


def test_changed_policy_artifact_is_rejected_fail_closed(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    path = tmp_path / "policies" / f"{contract['policy_digest']}.json"
    data = json.loads(path.read_text())
    data["name"] = "changed-policy"
    path.write_text(json.dumps(data))
    with pytest.raises(Exception):
        _build(tmp_path, contract, permit, attestation, effect)


def test_permit_a_cannot_cross_effect_b(tmp_path):
    contract, permit_a, attestation_a, _effect_a = _authority(tmp_path)
    permit_b = persist_permit(str(tmp_path), contract, "SECOND_AUTHORITY")
    attestation_b = persist_attestation(str(tmp_path), contract, permit_b, SECRET)
    effect_b = create_effect(str(tmp_path), contract_identity(contract), "op-2", "aios", permit_b["permit_id"], "run_research")
    with pytest.raises(ValueError, match="persisted effect permit"):
        _build(tmp_path, contract, permit_a, attestation_a, effect_b)
    assert attestation_b["permit_id"] == permit_b["permit_id"]


def test_contract_a_cannot_cross_effect_b(tmp_path):
    contract_a, _permit_a, _attestation_a, _effect_a = _authority(tmp_path)
    contract_b = dict(contract_a, task_id="task-2", input_digest="sha256:other")
    stored_b = persist_contract(str(tmp_path), contract_b)
    permit_b = persist_permit(str(tmp_path), stored_b, "AIOS_AUTHORITY")
    attestation_b = persist_attestation(str(tmp_path), stored_b, permit_b, SECRET)
    effect_b = create_effect(str(tmp_path), contract_identity(contract_b), "op-2", "aios", permit_b["permit_id"], "run_research")
    with pytest.raises(ValueError, match="workload contract"):
        _build(tmp_path, contract_a, permit_b, attestation_b, effect_b)


def test_forged_authority_ref_and_effect_binding_are_rejected(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    with pytest.raises(ValueError, match="persisted effect permit"):
        _build(tmp_path, contract, permit, attestation, effect, authority_ref="PT-forged")
    forged = dict(effect, effect_id="effect-forged")
    with pytest.raises(ValueError, match="effect_id"):
        _build(tmp_path, contract, permit, attestation, forged)


def test_missing_or_undeclared_capability_and_effect_remain_fail_closed(tmp_path):
    contract, permit, attestation, effect = _authority(tmp_path)
    with pytest.raises(ValueError, match="not granted"):
        _build(tmp_path, contract, permit, attestation, effect, capability_ref="try.research@2")
    with pytest.raises(ValueError, match="not allowed"):
        _build(tmp_path, contract, permit, attestation, effect, action="push_to_github")
