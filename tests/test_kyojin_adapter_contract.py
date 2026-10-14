# AIOS-CONTRACT: Capability-granted adapter returns an effect/attempt-bound ProviderReceipt.
# AIOS-REGRESSION: Ambiguous transport, malformed response, and HTTP errors must not become success.
# AIOS-OWNER: AIOS runtime owns authorization, durable state, retries, and semantic verification.
# AIOS-COVERAGE-GAP: Fake transport only; live Kyojin, hardware performance, and restart recovery are untested.
# AIOS-BASELINE: core/runtime.py ProviderReceipt contract and scripts/test_audit_gate.py authoring requirements.
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from adapters.kyojin import KyojinAdapter


class KyojinAdapterContractTests(unittest.TestCase):
    def test_valid_response_is_bound_to_effect(self):
        def transport(url, body, headers, timeout, limit):
            self.assertTrue(url.endswith("/chat/completions"))
            self.assertEqual(json.loads(body)["model"], "test-model")
            return 200, b'{"choices":[{"message":{"content":"OK"}}],"usage":{"total_tokens":1}}'

        adapter = KyojinAdapter(model="test-model", transport=transport)
        receipt = adapter.execute(
            contract={"scope": "Reply OK", "capabilities": ["kyojin.inference@1"]},
            effect={"effect_id": "effect-1", "attempt_id": "attempt-1"},
            attempt_id="attempt-1",
        )
        assert receipt.outcome == "OBSERVED_SUCCESS"
        self.assertEqual(receipt.outcome, "OBSERVED_SUCCESS")
        self.assertEqual(receipt.effect_id, "effect-1")
        self.assertEqual(receipt.attempt_id, "attempt-1")
        self.assertEqual(receipt.observation["kyojin_receipt"]["output"], "OK")
        self.assertEqual(receipt.observation["kyojin_receipt"]["usage"]["total_tokens"], 1)
        self.assertEqual(len(receipt.observation["kyojin_receipt"]["output_sha256"]), 64)

    def test_real_http_transport_round_trip_without_gpu_or_kyojin(self):
        response_body = b'{"choices":[{"message":{"content":"wire-ok"}}],"usage":{"total_tokens":2}}'

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.server.seen_path = self.path
                self.server.seen_body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response_body)))
                self.end_headers()
                self.wfile.write(response_body)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            adapter = KyojinAdapter(
                model="test-model",
                base_url=f"http://127.0.0.1:{server.server_port}/v1",
            )
            receipt = adapter.execute(
                contract={"scope": "wire test", "capabilities": ["kyojin.inference@1"]},
                effect={"effect_id": "effect-wire", "attempt_id": "attempt-wire"},
                attempt_id="attempt-wire",
            )
            self.assertEqual(server.seen_path, "/v1/chat/completions")
            self.assertEqual(json.loads(server.seen_body)["messages"][0]["content"], "wire test")
            self.assertEqual(receipt.observation["kyojin_receipt"]["output"], "wire-ok")
            self.assertEqual(receipt.attempt_id, "attempt-wire")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

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

    def test_malformed_json_is_rejected(self):
        adapter = KyojinAdapter(model="test-model", transport=lambda *args: (200, b"not-json"))
        with self.assertRaisesRegex(ValueError, "malformed JSON"):
            adapter.execute(
                contract={"scope": "prompt", "capabilities": ["kyojin.inference@1"]},
                effect={"effect_id": "effect-4", "attempt_id": "attempt-4"},
                attempt_id="attempt-4",
            )

    def test_attempt_mismatch_fails_before_transport(self):
        calls = []
        adapter = KyojinAdapter(model="test-model", transport=lambda *args: calls.append(args))
        with self.assertRaisesRegex(ValueError, "attempt binding mismatch"):
            adapter.execute(
                contract={"scope": "prompt", "capabilities": ["kyojin.inference@1"]},
                effect={"effect_id": "effect-5", "attempt_id": "different-attempt"},
                attempt_id="attempt-5",
            )
        self.assertEqual(calls, [])

    def test_invalid_base_url_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "absolute HTTP"):
            KyojinAdapter(model="test-model", base_url="file:///tmp/kyojin")

    def test_response_size_limit_is_enforced_even_with_custom_transport(self):
        adapter = KyojinAdapter(
            model="test-model",
            max_response_bytes=8,
            transport=lambda *args: (200, b'{"choices": []}'),
        )
        with self.assertRaisesRegex(ValueError, "response exceeds"):
            adapter.execute(
                contract={"scope": "prompt", "capabilities": ["kyojin.inference@1"]},
                effect={"effect_id": "effect-6", "attempt_id": "attempt-6"},
                attempt_id="attempt-6",
            )

    def test_non_bytes_transport_response_is_rejected(self):
        adapter = KyojinAdapter(model="test-model", transport=lambda *args: (200, "not bytes"))
        with self.assertRaisesRegex(ValueError, "response bytes"):
            adapter.execute(
                contract={"scope": "prompt", "capabilities": ["kyojin.inference@1"]},
                effect={"effect_id": "effect-7", "attempt_id": "attempt-7"},
                attempt_id="attempt-7",
            )


if __name__ == "__main__":
    unittest.main()
