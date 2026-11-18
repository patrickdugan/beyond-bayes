"""Regression tests for paired synthetic theorem-audit allocation policies."""
import unittest
from fractions import Fraction as Q
from audit_allocation import (
    AUDITS, ARMS, CREDAL_SET, HYPOTHESES, NOMINAL, Audit,
    check_prior, expected_loss, posterior_risk, simulate, single_case,
    terminal_risk, update_prior, value_of_information,
)


class TestAuditAllocation(unittest.TestCase):
    def test_priors_normalized(self):
        for p in CREDAL_SET:
            check_prior(p)
        with self.assertRaises(ValueError):
            check_prior({"clean": Q(1)})

    def test_conditioning_preserves_mass(self):
        for a in AUDITS:
            for observation in (False, True):
                p = update_prior(NOMINAL, a, observation)
                self.assertEqual(sum(p.values()), 1)
                self.assertTrue(all(v > 0 for v in p.values()))

    def test_preposterior_information_nonnegative(self):
        for a in AUDITS:
            self.assertGreaterEqual(value_of_information((NOMINAL,), a), 0)
            self.assertGreaterEqual(value_of_information(CREDAL_SET, a), 0)
            self.assertLessEqual(posterior_risk(CREDAL_SET, a), terminal_risk(CREDAL_SET))

    def test_no_information_audit_has_zero_voi(self):
        neutral = Audit("noise", 1, (), Q(9, 10), Q(1, 10))
        self.assertEqual(value_of_information((NOMINAL,), neutral), 0)
        self.assertEqual(value_of_information(CREDAL_SET, neutral), 0)

    def test_shared_decision_and_budget(self):
        outcomes = {a.name: False for a in AUDITS}
        for arm in ARMS:
            result = single_case(arm, "clean", outcomes, budget=5, seed=17)
            self.assertLessEqual(result["spent"], 5)
            self.assertEqual(len(set(result["selected"])), len(result["selected"]))
            point_mass = {"clean": Q(1), **{h: Q(0) for h in HYPOTHESES if h != "clean"}}
            self.assertEqual(result["loss"], expected_loss(point_mass, result["verdict"]))

    def test_bayesian_robust_single_prior_equivalence(self):
        for a in AUDITS:
            self.assertEqual(value_of_information((NOMINAL,), a),
                             terminal_risk((NOMINAL,)) - posterior_risk((NOMINAL,), a))

    def test_seeded_reproducibility(self):
        self.assertEqual(simulate(20, seed=19), simulate(20, seed=19))

    def test_committed_benchmark_receipt(self):
        import json
        from pathlib import Path
        fixture = Path(__file__).resolve().parent / "results/theorem_audit_allocation_250.json"
        observed = simulate(250, seed=10227, budget=5)
        expected = json.loads(fixture.read_text(encoding="utf-8"))
        self.assertEqual(observed, expected)

    def test_falsifiers(self):
        with self.assertRaises(ValueError):
            simulate(trials=0)
        with self.assertRaises(ValueError):
            single_case("unsupported", "clean", {}, budget=1)


if __name__ == "__main__":
    unittest.main()
