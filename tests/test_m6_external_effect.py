import os
import tempfile
import unittest

from core.evidence import EvidenceRecord
from core.authority import persist_contract, persist_permit
from core.contract import contract_identity
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

    def _setup_authority(self):
        policy = persist_policy(self.aios, {"policy_type":"GOVERNING_POLICY","name":"legacy-effect-test"})
        contract = {
            "contract_type":"EXECUTION_CONTRACT","task_id":"legacy-effect","scope":"test",
            "actor":"agent:a","capabilities":["provider:test@1"],"input_digest":"input",
            "allowed_effects":["external_effect"],"evidence_required":["provider_receipt"],
            "max_attempts":2,"terminal_states":["OBSERVED_SUCCESS","OBSERVED_FAILURE","UNKNOWN"],
            "policy_digest":policy,
        }
        persist_contract(self.aios, contract)
        permit = persist_permit(self.aios, contract, "agent:a")
        return contract_identity(contract), permit["permit_id"]

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_requires_observation_for_success(self):
        cid, pid = self._setup_authority()
        e = create_effect(self.aios, cid, "LO-1", "agent:a", pid, "external_effect")
        attempt = f"{e['effect_id']}:attempt:1"
        record_dispatch(self.aios, e["effect_id"], attempt, "provider:test")
        with self.assertRaises(ExternalEffectError):
            record_observation(self.aios, e["effect_id"], "OBSERVED_SUCCESS", {})

    def test_unknown_is_durable_and_needs_verified_observation(self):
        e = create_effect(self.aios, "CT-1", "LO-1", "agent:a")
        attempt = f"{e['effect_id']}:attempt:1"
        record_dispatch(self.aios, e["effect_id"], attempt, "provider:test")
        record_unknown(self.aios, e["effect_id"], "provider timeout")
        self.assertEqual(load_effects(self.aios)[e["effect_id"]]["state"], "UNKNOWN")
        record_observation(self.aios, e["effect_id"], "OBSERVED_SUCCESS", {
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
        a = create_effect(self.aios, "CT-1", "LO-1", "agent:a")
        b = create_effect(self.aios, "CT-1", "LO-1", "agent:a")
        self.assertEqual(a["effect_id"], b["effect_id"])


if __name__ == "__main__":
    unittest.main()
