import os
import tempfile
import unittest

from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.effect_authority import create_effect, dispatch, observe, transition, unknown
from core.evidence import EvidenceRecord
from core.policy_registry import persist_policy
from core.mutation import TransitionError


def contract(policy_digest):
    return {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": "task-external-effect",
        "scope": "external-effect-test",
        "actor": "agent:a",
        "capabilities": ["provider:test@1"],
        "input_digest": "input-1",
        "allowed_effects": ["external_effect"],
        "evidence_required": ["provider_receipt"],
        "max_attempts": 2,
        "terminal_states": ["SUCCESS", "FAILURE"],
        "policy_digest": policy_digest,
    }


def evidence():
    return EvidenceRecord(
        evidence_id="EV-1",
        level="OBSERVED",
        source_ref="provider://receipt/1",
        claim="provider completed operation",
        run_id="run-1",
        provider="provider:test",
    ).as_record()


class TestExternalEffect(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.aios = os.path.join(self.tmp, ".aios")
        registry = CapabilityRegistry()
        registry.register(Capability("provider:test", "1", "test-fixture", "test", status="ACTIVE"))
        registry.persist(self.tmp, "test-fixture")
        policy = persist_policy(self.tmp, {"policy_type": "GOVERNING_POLICY", "name": "external-effect-fixture"})
        c = contract(policy)
        self.cid = contract_identity(c)
        persist_contract(self.tmp, c)
        permit = persist_permit(self.tmp, c, "root")
        self.pid = permit["permit_id"]

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def effect(self):
        return create_effect(self.tmp, self.cid, "LO-1", "agent:a", self.pid, "external_effect")

    def test_requires_observation_for_success(self):
        e = self.effect()
        attempt = f"{e['effect_id']}:attempt:1"
        dispatch(self.tmp, e["effect_id"], "agent:a", attempt, "provider:test")
        with self.assertRaises(Exception):
            observe(self.tmp, e["effect_id"], "agent:a", "OBSERVED_SUCCESS", {"attempt_id": attempt, "provider": "provider:test"})

    def test_unknown_is_durable_and_needs_verified_observation(self):
        e = self.effect()
        attempt = f"{e['effect_id']}:attempt:1"
        dispatch(self.tmp, e["effect_id"], "agent:a", attempt, "provider:test")
        unknown(self.tmp, e["effect_id"], "agent:a", "provider timeout")
        from core.external_effect import load_effects
        self.assertEqual(load_effects(self.aios)[e["effect_id"]]["state"], "UNKNOWN")
        observe(self.tmp, e["effect_id"], "agent:a", "OBSERVED_SUCCESS", {
            "attempt_id": attempt, "provider": "provider:test", "evidence": evidence()
        })
        self.assertEqual(load_effects(self.aios)[e["effect_id"]]["state"], "OBSERVED_SUCCESS")

    def test_attempt_mismatch_is_rejected(self):
        e = self.effect()
        attempt = f"{e['effect_id']}:attempt:1"
        dispatch(self.tmp, e["effect_id"], "agent:a", attempt, "provider:test")
        with self.assertRaises(Exception):
            observe(self.tmp, e["effect_id"], "agent:a", "OBSERVED_SUCCESS", {
                "attempt_id": "different", "provider": "provider:test", "evidence": evidence()
            })

    def test_illegal_transition_rejected(self):
        e = self.effect()
        with self.assertRaises(Exception):
            observe(self.tmp, e["effect_id"], "agent:a", "OBSERVED_SUCCESS", {"receipt_id": "R-1"})

    def test_effect_identity_is_replayable(self):
        a = self.effect()
        b = self.effect()
        self.assertEqual(a["effect_id"], b["effect_id"])


if __name__ == "__main__":
    unittest.main()
