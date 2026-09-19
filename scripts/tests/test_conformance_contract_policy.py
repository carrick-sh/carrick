import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ConformanceContractPolicyTest(unittest.TestCase):
    def test_agents_rule_requires_contract_skill(self):
        text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("guest-visible correctness includes Linux semantics", text)
        self.assertIn(".agents/skills/carrick-conformance-contract", text)
        self.assertIn("A semantic pass cannot excuse", text)

    def test_guide_names_every_fail_closed_result(self):
        text = (ROOT / "docs/conformance-contracts.md").read_text(encoding="utf-8")
        for name in (
            "SemanticMismatch",
            "WorkBudgetExceeded",
            "ScalingViolation",
            "IncompleteMeasurement",
            "FixtureMismatch",
            "RuntimeRatioExceeded",
            "UnsupportedLayer",
        ):
            self.assertIn(name, text)

    def test_skill_requires_red_first_and_signed_promotion(self):
        text = (ROOT / ".agents/skills/carrick-conformance-contract/SKILL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("red-first", text)
        self.assertIn("just conformance-probes", text)
        self.assertIn("just conformance smoke", text)
        self.assertIn("just conformance", text)
        self.assertIn("Do not weaken", text)


if __name__ == "__main__":
    unittest.main()
