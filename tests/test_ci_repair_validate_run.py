import unittest

from scripts.ci_repair_validate_run import validate_run


class ValidateRunTests(unittest.TestCase):
    def setUp(self):
        self.payload = {
            "id": 12345,
            "repository": {"full_name": "yanhul/AIOS"},
            "head_repository": {"full_name": "yanhul/AIOS"},
            "status": "completed",
            "conclusion": "failure",
            "head_sha": "a" * 40,
            "head_branch": "main",
            "path": ".github/workflows/ci.yml",
            "event": "push",
        }
        self.expected = dict(repository="yanhul/AIOS", run_id=12345,
                             expected_sha="a" * 40, expected_branch="main")

    def test_accepts_exact_failed_ci_run(self):
        validate_run(self.payload, **self.expected)

    def test_rejects_wrong_repository(self):
        self.payload["repository"]["full_name"] = "attacker/AIOS"
        with self.assertRaisesRegex(ValueError, "repository mismatch"):
            validate_run(self.payload, **self.expected)

    def test_rejects_fork_head(self):
        self.payload["head_repository"]["full_name"] = "attacker/AIOS"
        with self.assertRaisesRegex(ValueError, "head repository mismatch"):
            validate_run(self.payload, **self.expected)

    def test_rejects_non_failure_or_incomplete_run(self):
        self.payload["conclusion"] = "success"
        with self.assertRaisesRegex(ValueError, "completed failure"):
            validate_run(self.payload, **self.expected)

    def test_rejects_sha_or_branch_mismatch(self):
        self.payload["head_sha"] = "b" * 40
        with self.assertRaisesRegex(ValueError, "head SHA mismatch"):
            validate_run(self.payload, **self.expected)

    def test_rejects_unapproved_workflow(self):
        self.payload["path"] = ".github/workflows/ci-autonomous-repair.yml"
        with self.assertRaisesRegex(ValueError, "workflow path"):
            validate_run(self.payload, **self.expected)

    def test_rejects_unapproved_branch(self):
        self.payload["head_branch"] = "feature/untrusted"
        self.expected["expected_branch"] = "feature/untrusted"
        with self.assertRaisesRegex(ValueError, "branch is outside"):
            validate_run(self.payload, **self.expected)


