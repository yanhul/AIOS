import os
import tempfile
import unittest

from core.external_effect import ExternalEffectError, create_effect, load_effects, record_dispatch, record_observation, record_unknown
from core.mutation import TransitionError


class TestExternalEffect(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.aios = os.path.join(self.tmp, ".aios")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_requires_observation_for_success(self):
        e = create_effect(self.aios, "CT-1", "LO-1", "agent:a")
        record_dispatch(self.aios, e["effect_id"], "AT-1", "provider:test")
        with self.assertRaises(ExternalEffectError):
            record_observation(self.aios, e["effect_id"], "OBSERVED_SUCCESS", {})

    def test_unknown_is_durable_and_needs_observation(self):
        e = create_effect(self.aios, "CT-1", "LO-1", "agent:a")
        record_dispatch(self.aios, e["effect_id"], "AT-1", "provider:test")
        record_unknown(self.aios, e["effect_id"], "provider timeout")
        self.assertEqual(load_effects(self.aios)[e["effect_id"]]["state"], "UNKNOWN")
        record_observation(self.aios, e["effect_id"], "OBSERVED_SUCCESS", {"receipt_id": "R-1"})
        self.assertEqual(load_effects(self.aios)[e["effect_id"]]["state"], "OBSERVED_SUCCESS")

    def test_illegal_transition_rejected(self):
        e = create_effect(self.aios, "CT-1", "LO-1", "agent:a")
        with self.assertRaises(TransitionError):
            record_observation(self.aios, e["effect_id"], "OBSERVED_SUCCESS", {"receipt_id": "R-1"})

    def test_effect_identity_is_replayable(self):
        a = create_effect(self.aios, "CT-1", "LO-1", "agent:a")
        b = create_effect(self.aios, "CT-1", "LO-1", "agent:a")
        self.assertEqual(a["effect_id"], b["effect_id"])


if __name__ == "__main__":
    unittest.main()
