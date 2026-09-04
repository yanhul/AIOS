import pytest

from core.authority import authorize, persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity


WORKLOAD_CAPABILITIES = (
    "try.research@1",
    "android.assistant@1",
    "rx50.engineering@1",
)


def _contract(capability: str) -> dict:
    return {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": f"admission-{capability.replace('.', '-').replace('@', '-')}",
        "scope": "cross-workload-admission",
        "actor": "aios:conformance",
        "capabilities": [capability],
        "input_digest": "fixture-input",
        "allowed_effects": [],
        "evidence_required": ["workload_manifest", "verification_result"],
        "max_attempts": 1,
        "terminal_states": ["PASS", "BLOCKED", "INCONCLUSIVE"],
        "policy_digest": "cross-workload-policy-v1",
    }


def test_all_registered_workloads_are_centrally_admissible(tmp_path):
    registry = CapabilityRegistry()
    for key in WORKLOAD_CAPABILITIES:
        capability_id, version = key.rsplit("@", 1)
        registry.register(
            Capability(
                capability_id,
                version,
                "registry-fixture",
                "workload",
                status="ACTIVE",
            )
        )
    registry.persist(str(tmp_path), "aios:conformance")

    for capability in WORKLOAD_CAPABILITIES:
        contract = _contract(capability)
        contract_id = contract_identity(contract)
        persist_contract(str(tmp_path), contract)
        permit = persist_permit(str(tmp_path), contract, "aios:conformance")
        assert authorize(str(tmp_path), contract_id, permit["permit_id"]) is True


def test_unregistered_workload_is_rejected_before_permit_issue(tmp_path):
    registry = CapabilityRegistry()
    registry.register(
        Capability("registered.workload", "1", "registry-fixture", "workload", status="ACTIVE")
    )
    registry.persist(str(tmp_path), "aios:conformance")

    contract = _contract("unregistered.workload@1")
    with pytest.raises(ValueError, match="not registered"):
        persist_contract(str(tmp_path), contract)
