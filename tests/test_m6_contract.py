"""M6 contract-boundary tests.

These tests exercise only pure contract/permit logic.  They intentionally do
not mock a runtime or claim external-effect atomicity.
"""

import copy
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.contract import contract_identity, issue_permit, validate_contract, verify_permit


class TestM6Contract(unittest.TestCase):
    def setUp(self):
        self.contract = {
            "contract_type": "EXECUTION_CONTRACT",
            "task_id": "TASK-1",
            "scope": "AIOS test project",
            "actor": "agent:test",
            "capabilities": ["read_repo", "write_patch"],
            "input_digest": "sha256:input",
            "allowed_effects": ["git_commit"],
            "evidence_required": ["tests_pass"],
            "max_attempts": 3,
            "terminal_states": ["DONE", "HOLD", "BLOCKED"],
            "policy_digest": "sha256:policy",
        }

    def test_contract_identity_is_deterministic(self):
        validate_contract(self.contract)
        self.assertEqual(contract_identity(self.contract), contract_identity(copy.deepcopy(self.contract)))

    def test_permit_binds_to_contract(self):
        permit = issue_permit(self.contract, "authority:test")
        self.assertTrue(verify_permit(self.contract, permit))

    def test_capability_escalation_fails(self):
        permit = issue_permit(self.contract, "authority:test")
        permit["capabilities"].append("shell_unrestricted")
        with self.assertRaises(ValueError):
            verify_permit(self.contract, permit)

    def test_policy_change_invalidates_permit(self):
        permit = issue_permit(self.contract, "authority:test")
        changed = copy.deepcopy(self.contract)
        changed["policy_digest"] = "sha256:different-policy"
        with self.assertRaises(ValueError):
            verify_permit(changed, permit)

    def test_terminal_conditions_are_contract_data(self):
        changed = copy.deepcopy(self.contract)
        changed["terminal_states"] = ["DONE"]
        self.assertNotEqual(contract_identity(self.contract), contract_identity(changed))


if __name__ == "__main__":
    unittest.main()
