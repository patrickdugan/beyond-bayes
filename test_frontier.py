import unittest
from alpha_frontier import run_frontier, wilson

class TestAlphaFrontier(unittest.TestCase):
    def test_wilson_bounds(self):
        lo, hi = wilson(0, 100)
        self.assertEqual(lo, 0)
        self.assertTrue(0 < hi < .05)
        lo, hi = wilson(100, 100)
        self.assertAlmostEqual(hi, 1)
        self.assertTrue(.95 < lo < 1)

    def test_alpha_frontier_is_monotonic_tradeoff(self):
        rows = run_frontier(n=12, k=2, trials_per_truth=300, alphas=(.01,.05,.2), seed=12)
        unsafe = [r['unsafe_open_rate'] for r in rows]
        false_locks = [r['false_lock_rate'] for r in rows]
        self.assertEqual(unsafe, sorted(unsafe))
        self.assertEqual(false_locks, sorted(false_locks, reverse=True))

if __name__ == '__main__':
    unittest.main()
