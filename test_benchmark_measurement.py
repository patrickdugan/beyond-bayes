"""Deterministic prestart-peeking counterexample with exact probability check."""
import math
import unittest
from benchmark_measurement import run

class TimingBenchmarkTests(unittest.TestCase):
    def test_exact_selection_math(self):
        b=run(20000,1010)
        self.assertAlmostEqual(b['exact_prepeek'],1-.95**20)
        self.assertAlmostEqual(b['exact_poststart'],.05)
        self.assertGreater(b['prepeek_software_reporter'],.60)
        self.assertLess(b['honest_poststart_single_reading'],.06)
    def test_reproducible_and_invalid_parameters(self):
        self.assertEqual(run(500,8),run(500,8))
        for args in ((0,1,20,.05),(10,1,0,.05),(10,1,20,1.0)):
            with self.assertRaises(ValueError):run(*args)

if __name__=='__main__':unittest.main()
