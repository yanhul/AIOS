# AIOS-CONTRACT: Kyojin provider must execute through core.runtime.execute/execute_attempt.\n# AIOS-REGRESSION: Ambiguous timeout is UNKNOWN and must not trigger implicit retry.\n# AIOS-OWNER: Authority/effect storage is isolated; durable crash/restart is a separate gate.\n# AIOS-COVERAGE-GAP: These tests do not prove persistence or process-restart recovery.\n# AIOS-BASELINE: core/runtime.py provider receipt and effect-state transition contract.\n"""Kyojin through the authoritative AIOS runtime boundary.

These tests isolate the authority/effect storage boundary but exercise the real
core.runtime.execute -> execute_attempt orchestration and real localhost HTTP
transport. They do NOT claim durable-store crash/restart recovery.
"""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from adapters.kyojin import KyojinAdapter
from core import runtime


class KyojinRuntimeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.contract = {
            "actor": "test-actor",
            "capabilities": ["kyojin.inference@1"],
            "allowed_effects": ["external_effect"],
            "scope": "integration prompt",
        }
        self.permit = {"actor": "test-actor"}
        self.effect = {
            "effect_id": "effect-kyojin-test",
            "actor": "test-actor",
            "state": "PLANNED",
            "attempt": 0,
        }

    def _authority_patches(self, observed, unknown):
        def create_effect(*args):
            return dict(self.effect)

        def dispatch(_aios_dir, effect_id, actor, attempt_id, provider):
            effect = dict(self.effect)
            effect.update({
                "effect_id": effect_id,
                "actor": actor,
                "attempt_id": attempt_id,
                "provider": provider,
                "state": "DISPATCHED",
                "attempt": 1,
            })
            return effect

        return (
            patch.object(runtime, "authorize"),
            patch.object(runtime, "load_contract", return_value=self.contract),
            patch.object(runtime, "load_permit", return_value=self.permit),
            patch.object(runtime, "create_effect", side_effect=create_effect),
            patch.object(runtime, "dispatch", side_effect=dispatch),
            patch.object(runtime, "observe", side_effect=observed),
            patch.object(runtime, "unknown", side_effect=unknown),
        )

    def test_execute_uses_runtime_and_real_local_http(self):
        response_body = b'{"choices":[{"message":{"content":"runtime-ok"}}]}'

        class Handler(BaseHTTPRequestHandler):
            def do_POST(inner_self):
                inner_self.server.seen_path = inner_self.path
                inner_self.server.seen_body = inner_self.rfile.read(
                    int(inner_self.headers.get("Content-Length", "0"))
                )
                inner_self.send_response(200)
                inner_self.send_header("Content-Type", "application/json")
                inner_self.send_header("Content-Length", str(len(response_body)))
                inner_self.end_headers()
                inner_self.wfile.write(response_body)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        observed_calls = []
        unknown_calls = []

        def observed(*args):
            observed_calls.append(args)
            return {"state": "OBSERVED_SUCCESS", "effect_id": args[1]}

        def unknown(*args):
            unknown_calls.append(args)
            return {"state": "UNKNOWN", "effect_id": args[1]}

        patches = self._authority_patches(observed, unknown)
        try:
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                adapter = KyojinAdapter(
                    model="test-model",
                    base_url=f"http://127.0.0.1:{server.server_port}/v1",
                )
                result = runtime.execute(
                    "/tmp/aios-kyojin-test",
                    "contract-test",
                    "permit-test",
                    "logical-op-test",
                    "test-actor",
                    adapter,
                )
            self.assertEqual(server.seen_path, "/v1/chat/completions")
            self.assertEqual(
                json.loads(server.seen_body)["messages"][0]["content"],
                "integration prompt",
            )
            self.assertEqual(result["state"], "OBSERVED_SUCCESS")\n            assert result["state"] == "OBSERVED_SUCCESS"
            self.assertEqual(len(observed_calls), 1)
            self.assertEqual(observed_calls[0][1], "effect-kyojin-test")
            self.assertEqual(unknown_calls, [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_ambiguous_provider_timeout_routes_to_unknown_without_retry(self):
        observed_calls = []
        unknown_calls = []

        def observed(*args):
            observed_calls.append(args)
            return {"state": "OBSERVED_SUCCESS"}

        def unknown(*args):
            unknown_calls.append(args)
            return {"state": "UNKNOWN", "effect_id": args[1]}

        transport_calls = []

        def ambiguous_transport(*args):
            transport_calls.append(args)
            raise TimeoutError("simulated ambiguous provider outcome")

        patches = self._authority_patches(observed, unknown)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
            adapter = KyojinAdapter(model="test-model", transport=ambiguous_transport)
            result = runtime.execute(
                "/tmp/aios-kyojin-test",
                "contract-test",
                "permit-test",
                "logical-op-timeout",
                "test-actor",
                adapter,
            )

        self.assertEqual(result["state"], "UNKNOWN")\n        assert result["state"] == "UNKNOWN"
        self.assertEqual(len(transport_calls), 1, "adapter/runtime must not auto-retry")
        self.assertEqual(len(unknown_calls), 1)
        self.assertEqual(observed_calls, [])


if __name__ == "__main__":
    unittest.main()
