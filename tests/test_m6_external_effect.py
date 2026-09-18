import os
import tempfile
import unittest

from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.evidence import EvidenceRecord
from core.external_effect import ExternalEffectError, create_effect, load_effects, record_dispatch, record_observation, record_unknown
from core.policy_registry import persist_policy
from core.receipt import persist_receipt

class TestExternalEffect(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.aios = os.path.join(self.tmp, ".aios")
        registry = CapabilityRegistry()
        registry.register(Capability("provider:test", "1", "test-fixture", "test", status="ACTIVE"))
        registry.persist(self.aios, "test-fixture")
        policy = persist_policy(self.aios, {"policy_type":"GOVERNING_POLICY","name":"external-effect-fixture"})
        self.contract = {
            "contract_type":"EXECUTION_CONTRACT", "task_id":"task-external", "scope":"test",
            "actor":"agent:a", "capabilities":["provider:test@1"], "input_digest":"input",
            "allowed_effects":["external_effect"], "evidence_required":["provider_receipt"],
            "max_attempts":2, "terminal_states":["SUCCESS","FAILURE"], "policy_digest":policy,
        }
        self.cid = contract_identity(self.contract)
        persist_contract(self.aios, self.contract)
        self.permit = persist_permit(self.aios, self.contract, "root")
        self.pid = self.permit["permit_id"]

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def effect(self):
        return create_effect(self.aios, self.cid, "LO-1", "agent:a", self.pid, "external_effect")

    def dispatch(self, e):
        attempt = f"{e['effect_id']}:attempt:1"
        return record_dispatch(self.aios, e["effect_id"], "agent:a", attempt, "provider:test")

    def evidence(self, effect):
        attempt_id = f"{effect['effect_id']}:attempt:1"
        receipt = persist_receipt(
            self.aios, {"effect_id": effect["effect_id"], "attempt_id": attempt_id,
                         "provider": "provider:test"},
            attempt_id, "provider:test", "provider-op-1",
            "OBSERVED_SUCCESS", {"status": "ok"},
        )
        return EvidenceRecord(
            evidence_id="EV-1", level="OBSERVED", source_ref="provider://receipt/1",
            claim="provider completed operation", run_id="run-1", provider="provider:test",
            artifact_ref="provider-op-1", receipt_id=receipt["receipt_id"],
            effect_id=effect["effect_id"], attempt_id=attempt_id,
        ).as_record(), receipt["receipt_id"]

    def test_requires_observation_for_success(self):
        e = self.effect()
        self.dispatch(e)
        with self.assertRaises(ExternalEffectError):
            record_observation(self.aios, e["effect_id"], "agent:a", "OBSERVED_SUCCESS", {})

    def test_unknown_is_durable_and_needs_verified_observation(self):
        e = self.effect()
        self.dispatch(e)
        record_unknown(self.aios, e["effect_id"], "agent:a", "provider timeout")
        self.assertEqual(load_effects(self.aios)[e["effect_id"]]["state"], "UNKNOWN")
        record_observation(self.aios, e["effect_id"], "agent:a", "OBSERVED_SUCCESS", {
            "attempt_id": f"{e['effect_id']}:attempt:1", "provider":"provider:test",
            "receipt_id": self.evidence(e)[1], "evidence":self.evidence(e)[0]
        })
        self.assertEqual(load_effects(self.aios)[e["effect_id"]]["state"], "OBSERVED_SUCCESS")

    def test_attempt_mismatch_is_rejected(self):
        e = self.effect()
        self.dispatch(e)
        with self.assertRaises(ExternalEffectError):
            record_observation(self.aios, e["effect_id"], "agent:a", "OBSERVED_SUCCESS", {
                "attempt_id":"different", "provider":"provider:test", "evidence":self.evidence(e)[0]
            })

    def test_illegal_transition_rejected(self):
        e = self.effect()
        with self.assertRaises(ExternalEffectError):
            record_observation(self.aios, e["effect_id"], "agent:a", "OBSERVED_SUCCESS", {"receipt_id":"R-1"})

    def test_effect_identity_is_replayable(self):
        a = self.effect()
        b = self.effect()
        self.assertEqual(a["effect_id"], b["effect_id"])

if __name__ == "__main__":
    unittest.main()
