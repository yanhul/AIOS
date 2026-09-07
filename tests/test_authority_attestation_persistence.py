import tempfile

from core.authority import persist_attestation, persist_contract, persist_permit, load_attestation
from core.capabilities import Capability, CapabilityRegistry
from core.policy_registry import persist_policy


def make_contract(policy_digest):
    return {
        "contract_type":"EXECUTION_CONTRACT","task_id":"RESEARCH_BC7","scope":"research","actor":"bc-controller",
        "capabilities":["research_is_validation@1"],"input_digest":"sha256:input","allowed_effects":["persist_evidence"],
        "evidence_required":["is_validation_report"],"max_attempts":3,"terminal_states":["PROMOTED","REJECTED","HOLD"],"policy_digest":policy_digest
    }

def test_persist_and_reload_attestation():
    with tempfile.TemporaryDirectory() as td:
        registry = CapabilityRegistry()
        registry.register(Capability("research_is_validation", "1", "test-fixture", "research", status="ACTIVE"))
        registry.persist(td, "test-fixture")
        policy = persist_policy(td, {"policy_type":"GOVERNING_POLICY","name":"research-fixture"})
        c=make_contract(policy); persist_contract(td,c); from core.contract import contract_identity
        p=persist_permit(td,c,"AIOS_AUTHORITY")
        a=persist_attestation(td,c,p,"test-secret")
        assert load_attestation(td,p["permit_id"]) == a
        assert a["contract_id"] == contract_identity(c)
