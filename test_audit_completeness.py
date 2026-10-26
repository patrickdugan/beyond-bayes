"""Exact adversarial missingness checks independent of probabilistic sources."""

from fractions import Fraction
from itertools import product
import unittest

from audit_completeness import bound_omitted_traces


class AuditCompletenessTests(unittest.TestCase):
    def test_every_missing_receipt_could_hide_an_adverse_event(self):
        ids = [f"evt-{i:03}" for i in range(100)]
        reviewed = {i: i in ("evt-000", "evt-001") for i in ids[:80]}
        result = bound_omitted_traces(ids, reviewed)
        self.assertEqual((result.total, result.reviewed, result.omitted, result.observed_adverse),
                         (100, 80, 20, 2))
        self.assertEqual(result.coverage, Fraction(4, 5))
        self.assertEqual((result.lower, result.upper), (Fraction(1, 50), Fraction(11, 50)))
        self.assertFalse(result.certifies_at_most("0.20"))
        self.assertTrue(result.certifies_at_most(Fraction(11, 50)))

    def test_complete_and_absent_audit(self):
        ids = ["a", "b", "c"]
        full = bound_omitted_traces(ids, {i: False for i in ids})
        self.assertEqual((full.lower, full.upper), (0, 0))
        self.assertTrue(full.certifies_at_most(0))
        empty = bound_omitted_traces(ids, {})
        self.assertEqual((empty.lower, empty.upper, empty.coverage), (0, 1, 0))
        self.assertFalse(empty.certifies_at_most(Fraction(99, 100)))

    def test_exhaustive_sharp_bound_small_populations(self):
        for n in range(1, 6):
            ids = tuple(f"id-{i}" for i in range(n))
            for verdicts in product((False, True), repeat=n):
                actual = Fraction(sum(verdicts), n)
                for mask in product((False, True), repeat=n):
                    observed = {ids[i]: verdicts[i] for i in range(n) if mask[i]}
                    bound = bound_omitted_traces(ids, observed)
                    self.assertLessEqual(bound.lower, actual)
                    self.assertLessEqual(actual, bound.upper)
                    self.assertEqual(bound.lower, Fraction(sum(observed.values()), n))
                    self.assertEqual(bound.upper, Fraction(sum(observed.values()) + mask.count(False), n))

    def test_universe_hash_order_independent_and_content_sensitive(self):
        a = bound_omitted_traces(["z", "b", "a"], {"z": True})
        b = bound_omitted_traces(["a", "z", "b"], {"z": True})
        c = bound_omitted_traces(["a", "z", "c"], {"z": True})
        self.assertEqual(a.universe_hash, b.universe_hash)
        self.assertNotEqual(a.universe_hash, c.universe_hash)

    def test_invalid_universe_and_verdicts_rejected(self):
        for ids, reviewed, kind in [
            ([], {}, ValueError),
            (["a", "a"], {}, ValueError),
            (["a"], {"b": False}, ValueError),
            (["a"], {"a": 1}, TypeError),
            (["a"], [("a", True)], TypeError),
        ]:
            with self.assertRaises(kind):
                bound_omitted_traces(ids, reviewed)

    def test_budget_policy_uses_exact_arithmetic(self):
        ids = ["a", "b", "c", "d"]
        none = bound_omitted_traces(ids, {"a": False})
        more = bound_omitted_traces(ids, {"a": False, "b": False})
        self.assertLess(more.upper, none.upper)
        self.assertFalse(more.certifies_at_most(Fraction(1, 4)))
        for budget in (0.1, True):
            with self.assertRaises(TypeError):
                more.certifies_at_most(budget)
        with self.assertRaises(ValueError):
            more.certifies_at_most("1.1")


if __name__ == "__main__":
    unittest.main()
