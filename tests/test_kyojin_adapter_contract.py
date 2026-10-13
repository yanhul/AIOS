# AIOS-CONTRACT: Capability-granted adapter returns an effect/attempt-bound ProviderReceipt.
# AIOS-REGRESSION: Ambiguous transport, malformed response, and HTTP errors must not become success.
# AIOS-OWNER: AIOS runtime owns authorization, durable state, retries, and semantic verification.
# AIOS-COVERAGE-GAP: Fake transport only; live Kyojin, hardware performance, and restart recovery are untested.
# AIOS-BASELINE: core/runtime.py ProviderReceipt contract and scripts/test_audit_gate.py authoring requirements.
import json
import unittest

from adapters.kyojin import KyojinAdapter


class KyojinAdapterContractTests(unittest.TestCase):
    def test_valid_response_is_bound_to_effect(self):
        def transport(url, body, headers, timeout, limit):
            self.assertTrue(url.endswith("/chat/completions"))
            self.assertEqual(json.loads(body)["model"], "test-model")
            return 200, b'{"choices":[{"message":{"content":"OK"}}],"usage":{"total_tokens":1}}'

        adapter = KyojinAdapter(model="test-model", transport=transport)
        receipt = adapter.execute(
            contract={
                "scope": "Reply OK",
                "capabilities": ["kyojin.inference@1"],
            },
            effect={"effect_id": "effect-1", "attempt_id": "attempt-1"},
            attempt_id="attempt-1",
        )
        self.assertEqual(receipt.outcome, "OBSERVED_SUCCESS")
        self.assertEqual(receipt.effect_id, "effect-1")
        self.assertEqual(receipt.observation["kyojin_receipt"]["output"], "OK")

    def test_missing_capability_fails_before_transport(self):
        calls = []
        adapter = KyojinAdapter(model="test-model", transport=lambda *args: calls.append(args))
        with self.assertRaises(PermissionError):
            adapter.execute(
                contract={"scope": "prompt", "capabilities": []},
                effect={"effect_id": "effect-1", "attempt_id": "attempt-1"},
                attempt_id="attempt-1",
            )
        self.assertEqual(calls, [])

    def test_non_success_status_is_not_reported_as_success(self):
        adapter = KyojinAdapter(model="test-model", transport=lambda *args: (503, b"error"))
        with self.assertRaises(RuntimeError):
            adapter.execute(
                contract={"scope": "prompt", "capabilities": ["kyojin.inference@1"]},
                effect={"effect_id": "effect-1", "attempt_id": "attempt-1"},
                attempt_id="attempt-1",
            )


    def test_transport_ambiguity_propagates_without_retry(self):
        calls = []
        def transport(*args):
            calls.append(args)
            raise TimeoutError("ambiguous provider result")
        adapter = KyojinAdapter(model="test-model", transport=transport)
        with self.assertRaises(TimeoutError):
            adapter.execute(
                contract={"scope": "prompt", "capabilities": ["kyojin.inference@1"]},
                effect={"effect_id": "effect-2", "attempt_id": "attempt-2"},
                attempt_id="attempt-2",
            )
        self.assertEqual(len(calls), 1)

    def test_malformed_response_is_rejected(self):
        adapter = KyojinAdapter(model="test-model", transport=lambda *args: (200, b'{"choices":[]}'))
        with self.assertRaises(ValueError):
            adapter.execute(
                contract={"scope": "prompt", "capabilities": ["kyojin.inference@1"]},
                effect={"effect_id": "effect-3", "attempt_id": "attempt-3"},
                attempt_id="attempt-3",
            )


if __name__ == "__main__":
    unittest.main()
