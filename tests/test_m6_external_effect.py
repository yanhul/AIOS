import os
import tempfile
import unittest

from core.authority import persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.evidence import EvidenceRecord
from core.external_effect import ExternalEffectError, create_effect, load_effects, record_dispatch, record_observation, record_unknown
from core.policy_registry import persist_policy

BINDING = {"target_sha": "sha256:worker-v1", "evidence_ref": "EV-1", "lineage_ref": "LIN-1", "idempotency_key": "idem-1", "attempt_fence": 1}


def evidence(provider="provider:test"):
    return EvidenceRecord(evidence_id="EV-1", level="OBSERVED", source_ref="provider://receipt/1", claim="provider completed operation", run_id="run-1", provider=provider).as_record()


class TestExternalEffect(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.aios = os.path.join(self.tmp, ".aios")
        registry = CapabilityRegistry()
        registry.register(Capability("provider", "1", "test-fixture", "test", status="ACTIVE"))
        registry.persist(self.aios, "test-fixture")
        policy = persist_policy(self.aios, {"policy_type": "GOVERNING_POLICY", "name": "external-effect-fixture"})
        self.contract = {"contract_type": "EXECUTION_CONTRACT", "task_id": "task-1", "scope": "test", "actor": "agent:a", "capabilities": ["provider@1"], "input_digest": "input", "allowed_effects": ["external_effect"], "evidence_required": ["provider_receipt"], "max_attempts": 2, "terminal_states": ["SUCCESS", "FAILURE"], "policy_digest": policy}
        persist_contract(self.aios, self.contract)
        permit = persist_permit(self.aios, self.contract, "root")
        self.pid = permit["permit_id"]
        self.cid = contract_identity(self.contract)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _effect(self):
        return create_effect(self.aios, self.cid, "LO-1", "agent:a", self.pid, "external_effect")

    def _dispatch(self, e, attempt=1, fence=1):
        binding = dict(BINDING, attempt_fence=fence)
        return record_dispatch(self.aios, e["effect_id"], "agent:a", f"{e['effect_id']}:attempt:{attempt}", "provider", **binding)

    def _observation(self, effect, attempt):
        return {
            "attempt_id": attempt["attempt_id"],
            "provider": attempt["provider"],
            "target_sha": attempt["target_sha"],
            "evidence_ref": attempt["evidence_ref"],
            "lineage_ref": attempt["lineage_ref"],
            "idempotency_key": attempt["idempotency_key"],
            "attempt_fence": attempt["attempt_fence"],
            "evidence": evidence("provider"),
        }

    def test_requires_observation_for_success(self):
        e = self._effect()
        self._dispatch(e)
        with self.assertRaises(ExternalEffectError):
            record_observation(self.aios, e["effect_id"], "agent:a", "OBSERVED_SUCCESS", {})

    def test_unknown_is_durable_and_needs_verified_observation(self):
        e = self._effect()
        self._dispatch(e)
        record_unknown(self.aios, e["effect_id"], "agent:a", "provider timeout")
        self.assertEqual(load_effects(self.aios)[e["effect_id"]]["state"], "UNKNOWN")
        from core.effect_authority import retry_dispatch
        retried = retry_dispatch(self.aios, e["effect_id"], "agent:a", f"{e['effect_id']}:attempt:2", "provider", 2, target_sha=BINDING["target_sha"], attempt_fence=2)
        record_observation(self.aios, e["effect_id"], "agent:a", "OBSERVED_SUCCESS", self._observation(e, retried))
        self.assertEqual(load_effects(self.aios)[e["effect_id"]]["state"], "OBSERVED_SUCCESS")

    def test_attempt_mismatch_is_rejected(self):
        e = self._effect()
        self._dispatch(e)
        observation = self._observation(e, load_effects(self.aios)[e["effect_id"]])
        observation["attempt_id"] = "different"
        with self.assertRaises(ExternalEffectError):
            record_observation(self.aios, e["effect_id"], "agent:a", "OBSERVED_SUCCESS", observation)

    def test_illegal_transition_rejected(self):
        e = self._effect()
        with self.assertRaises(ExternalEffectError):
            record_observation(self.aios, e["effect_id"], "agent:a", "OBSERVED_SUCCESS", {"receipt_id": "R-1"})

    def test_effect_identity_is_replayable(self):
        a = self._effect()
        b = self._effect()
        self.assertEqual(a["effect_id"], b["effect_id"])


if __name__ == "__main__":
    unittest.main()
