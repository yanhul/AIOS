"""Contract -> durable-loop acceptance integration tests."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.acceptance import AcceptancePredicate
from core.durable_loop import LoopPolicy, MemoryStateStore, run_durable_loop


class _Executor:
    def __init__(self, verification):
        self.verification = verification

    def observe(self, state):
        return {"ok": True}

    def decide(self, observation, state):
        return {"action": "verify"}

    def act(self, decision, state):
        return {"changed": True}

    def verify(self, action_result, state):
        return self.verification


class TestAcceptanceContractIntegration(unittest.TestCase):
    def _policy(self, verification):
        return LoopPolicy(
            max_steps=1,
            terminal_evaluator=lambda verification, state: "PASS",
            action_authorizer=lambda decision, state: None,
            acceptance_predicates=(
                AcceptancePredicate("status-pass", "verification.status", "eq", "FIXED"),
            ),
        )

    def test_pass_requires_acceptance_predicates(self):
        result = run_durable_loop(
            _Executor({"status": "FIXED"}),
            MemoryStateStore(),
            self._policy({"status": "FIXED"}),
        )
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["terminal_evidence"]["status"], "PASS")

    def test_failed_acceptance_cannot_promote_pass(self):
        result = run_durable_loop(
            _Executor({"status": "NOT_FIXED"}),
            MemoryStateStore(),
            self._policy({"status": "NOT_FIXED"}),
        )
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("acceptance predicates failed", result["block_reason"])

    def test_acceptance_can_read_nested_verification(self):
        policy = LoopPolicy(
            max_steps=1,
            terminal_evaluator=lambda verification, state: "PASS",
            action_authorizer=lambda decision, state: None,
            acceptance_predicates=(
                AcceptancePredicate("evidence", "verification.receipt.status", "eq", "OBSERVED"),
            ),
        )
        result = run_durable_loop(
            _Executor({"receipt": {"status": "OBSERVED"}}),
            MemoryStateStore(),
            policy,
        )
        self.assertEqual(result["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
