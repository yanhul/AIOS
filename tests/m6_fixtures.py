"""Shared fixtures for governed M6 effect tests."""
from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.policy_registry import persist_policy
from core.effect_authority import create_effect


def make_effect(tmp_path, provider="provider-1", actor="agent-1", effect_type="external_effect", max_attempts=2):
    registry = CapabilityRegistry()
    registry.register(Capability(provider, "1", "test-fixture", "test", status="ACTIVE"))
    registry.persist(str(tmp_path), "m6-shared-fixture")
    policy_digest = persist_policy(
        str(tmp_path), {"policy_type": "GOVERNING_POLICY", "name": "m6-shared-fixture"}
    )
    contract = {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": "m6-effect-test",
        "scope": "m6-test",
        "actor": actor,
        "capabilities": [f"{provider}@1"],
        "input_digest": "sha256:m6-test-input",
        "allowed_effects": [effect_type],
        "evidence_required": ["provider_receipt"],
        "max_attempts": max_attempts,
        "terminal_states": ["PASS", "FAILURE", "INCONCLUSIVE"],
        "policy_digest": policy_digest,
    }
    contract_id = contract_identity(contract)
    persist_contract(tmp_path, contract)
    permit = persist_permit(tmp_path, contract, "aios:test")
    return create_effect(
        str(tmp_path), contract_id, "m6-effect-operation", actor,
        permit["permit_id"], effect_type
    )
