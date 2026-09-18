import os
import tempfile
import unittest

from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.evidence import EvidenceRecord
from core.policy_registry import persist_policy
from core.external_effect import ExternalEffectError, create_effect, load_effects, record_dispatch, record_observation, record_unknown
from core.mutation import TransitionError


def evidence(provider="provider:test"):
    return EvidenceRecord(
        evidence_id="EV-1",
        level="OBSERVED",
        source_ref="provider://receipt/1",
        claim="provider completed operation",
        run_id="run-1",
        provider=provider,
    ).as_record()


class TestExternalEffect(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.aios = os.path.join(self.tmp, ".aios")

    def setUp(self):
        super().setUp()
        registry = CapabilityRegistry()
        registry.register(Capability("provider:test", "1", "test-fixture", "test", status="ACTIVE"))
        registry.persist(self.aios, "m6-external-fixture")
        policy = persist_policy(self.aios, {"policy_type": "GOVERNING_POLICY", "name": "m6-external-fixture"})
        self.contract = {
            "contract_type": "EXECUTION_CONTRACT", "task_id": "m6-external",
            "scope": "m6-external-test", "actor": "agent:a",
            "capabilities": ["provider:test@1"], "input_digest": "input-1",
            "allowed_effects": ["external_effect"], "evidence_required": ["provider_receipt"],
            "max_attempts": 2, "terminal_states": ["SUCCESS", "FAILURE"],
            "policy_digest": policy,
        }
        self.contract_id = contract_identity(self.contract)
        persist_contract(self.aios, self.contract)
        self.permit_id = persist_permit(self.aios, self.contract, "root")["permit_id"]

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_requires_observation_for_success(self):
        e = create_effect(self.aios, self.contract_id, "LO-1", "agent:a", self.permit_id, "external_effect")
        attempt = f"{e['effect_id']}:attempt:1"
        record_dispatch(self.aios, e["effect_id"], "agent:a", attempt, "provider:test")
        with self.assertRaises(ExternalEffectError):
            record_observation(self.aios, e["effect_id"], "agent:a", "OBSERVED_SUCCESS", {})

    def test_unknown_is_durable_and_needs_verified_observation(self):
        e = create_effect(self.aios, "CT-1", "LO-1", "agent:a")
        attempt = f"{e['effect_id']}:attempt:1"
        record_dispatch(self.aios, e["effect_id"], attempt, "provider:test")
        record_unknown(self.aios, e["effect_id"], "agent:a", "provider timeout")
        self.assertEqual(load_effects(self.aios)[e["effect_id"]]["state"], "UNKNOWN")
        record_observation(self.aios, e["effect_id"], "agent:a", "OBSERVED_SUCCESS", {
            "attempt_id": attempt, "provider": "provider:test", "evidence": evidence()
        })
        self.assertEqual(load_effects(self.aios)[e["effect_id"]]["state"], "OBSERVED_SUCCESS")

    def test_attempt_mismatch_is_rejected(self):
        e = create_effect(self.aios, "CT-1", "LO-1", "agent:a")
        attempt = f"{e['effect_id']}:attempt:1"
        record_dispatch(self.aios, e["effect_id"], attempt, "provider:test")
        with self.assertRaises(ExternalEffectError):
            record_observation(self.aios, e["effect_id"], "OBSERVED_SUCCESS", {
                "attempt_id": "different", "provider": "provider:test", "evidence": evidence()
            })

    def test_illegal_transition_rejected(self):
        e = create_effect(self.aios, "CT-1", "LO-1", "agent:a")
        with self.assertRaises(ExternalEffectError):
            record_observation(self.aios, e["effect_id"], "OBSERVED_SUCCESS", {"receipt_id": "R-1"})

    def test_effect_identity_is_replayable(self):
        a = create_effect(self.aios, self.contract_id, "LO-1", "agent:a", self.permit_id, "external_effect")
        b = create_effect(self.aios, self.contract_id, "LO-1", "agent:a", self.permit_id, "external_effect")
        self.assertEqual(a["effect_id"], b["effect_id"])


if __name__ == "__main__":
    unittest.main()
