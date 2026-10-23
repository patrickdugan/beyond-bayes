import unittest
from benchmark_scope import simulate

class ScopeBenchmarkTests(unittest.TestCase):
    def test_reset_and_peek_theory(self):
        r=simulate(trials=10000, seed=9209)
        self.assertGreater(r['unscoped_theory'], .64)
        self.assertLess(r['root_spending_theory'], .05)
        self.assertAlmostEqual(r['peek_theory'], r['unscoped_theory'])
        self.assertAlmostEqual(r['unscoped_observed'], r['unscoped_theory'],delta=.018)
        self.assertAlmostEqual(r['root_spending_observed'], r['root_spending_theory'],delta=.008)
        self.assertAlmostEqual(r['peek_observed'], r['peek_theory'],delta=.018)

    def test_reject_invalid_benchmark(self):
        for kwargs in ({'children':0},{'children':1001},{'trials':0},{'root_alpha':0.0}):
            with self.assertRaises(ValueError):simulate(**kwargs)

if __name__ == '__main__':unittest.main()
