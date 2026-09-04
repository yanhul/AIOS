import pytest

from core.authority import persist_contract, persist_permit
from core.capability_catalog import load_catalog
from core.contract import contract_identity
from core.durable_loop import LoopPolicy, MemoryStateStore
from core.orchestrator import GovernedRuntimeExecutor, run_governed_execution
from core.runtime import ProviderReceipt

WORKLOADS = (
    ("try.research", "yanhul/try", "research"),
    ("android.assistant", "yanhul/android-ai-assistant", "software"),
    ("rx50.engineering", "yanhul/RX50", "hardware"),
)


class WorkloadAdapter:
    def __init__(self, name):
        self.name = name
        self.calls = 0

    def execute(self, *, contract, effect, attempt_id):
        self.calls += 1
        return ProviderReceipt(
            self.name,
            effect["effect_id"],
            attempt_id,
            f"{self.name}:operation:{self.calls}",
            "OBSERVED_SUCCESS",
            {"workload": self.name, "effect": effect["effect_id"]},
        )


def _contract(capability):
    return {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": f"v1-{capability.replace('.', '-')}",
        "scope": "v1-central-orchestrator-smoke",
        "actor": "agent:v1-conformance",
        "capabilities": [f"{capability}@1"],
        "input_digest": "conformance-input-v1",
        "allowed_effects": ["external_effect"],
        "evidence_required": ["provider_receipt"],
        "max_attempts": 1,
        "terminal_states": ["PASS", "BLOCKED", "INCONCLUSIVE"],
        "policy_digest": "v1-central-policy",
    }


@pytest.mark.parametrize("capability,owner,kind", WORKLOADS)
def test_registered_workload_executes_through_central_aios(tmp_path, capability, owner, kind):
    registry = load_catalog("capabilities/registry.yaml")
    registered = registry.require(f"{capability}@1")
    assert registered.owner == owner
    assert registered.kind == kind
    registry.persist(tmp_path, "test:v1-conformance")

    contract = _contract(capability)
    stored = persist_contract(tmp_path, contract)
    permit = persist_permit(tmp_path, stored, "aios:root")
    adapter = WorkloadAdapter(capability)

    executor = GovernedRuntimeExecutor(
        aios_dir=str(tmp_path),
        contract_id=contract_identity(contract),
        permit_id=permit["permit_id"],
        actor=contract["actor"],
        adapter=adapter,
        observer=lambda state: {"workload": capability, "phase": "OBSERVE"},
        decider=lambda observation, state: {
            "logical_operation_id": f"{capability}:smoke:{state['step'] + 1}"
        },
        verifier=lambda result, state: {
            "verified": result["state"] == "OBSERVED_SUCCESS",
            "evidence": result["evidence"],
        },
    )
    policy = LoopPolicy(
        max_steps=1,
        terminal_evaluator=lambda verification, state: "PASS" if verification["verified"] else "INCONCLUSIVE",
        action_authorizer=lambda decision, state: None,
        policy_digest=contract["policy_digest"],
    )

    result = run_governed_execution(
        executor=executor,
        store=MemoryStateStore(),
        policy=policy,
    )

    assert result["status"] == "PASS"
    assert result["step"] == 1
    assert result["history"][0]["decision"]["logical_operation_id"].startswith(capability)
    assert adapter.calls == 1
