import unittest

from core.skill_router import DEFAULT_SKILLS, SkillSpec, plan_report, route


class SkillRouterTests(unittest.TestCase):
    def test_deterministic_research_route(self):
        plan = route("run a BTC backtest and validation", DEFAULT_SKILLS)
        self.assertEqual(plan.skill_id, "research")
        self.assertEqual(plan.capability_id, "try.research")
        self.assertTrue(plan.dry_run)

    def test_dry_run_never_grants_authority(self):
        plan = route("security audit of an artifact", DEFAULT_SKILLS)
        report = plan_report("security audit of an artifact", plan)
        self.assertEqual(plan.skill_id, "authorized-artifact-auditor")
        self.assertFalse(report["authority_granted"])
        self.assertTrue(report["evidence_required"])

    def test_unknown_problem_has_no_route(self):
        plan = route("make something completely unrelated", DEFAULT_SKILLS)
        self.assertIsNone(plan.skill_id)
        self.assertIsNone(plan.capability_id)

    def test_tie_break_is_stable(self):
        skills = (
            SkillSpec("b", "b", ("x",), "cap.b"),
            SkillSpec("a", "a", ("x",), "cap.a"),
        )
        self.assertEqual(route("x", skills).skill_id, "a")


if __name__ == "__main__":
    unittest.main()
