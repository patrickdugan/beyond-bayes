import math
from itertools import combinations, product
import unittest

from adversarial_benchmark import (
    P_RISK, P_SAFE, apply_attack, bayes_action, credal_action,
    credal_posterior_interval, dedup_with_verified_origins, live_binary_models,
    posterior_given_clean_ones, random_attack_bayes_posterior, sample_corruption,
    targeted_attack_likelihood, targeted_policy_aware_bayes
)
from robust import (RobustBernoulliEProcess, exact_worst_case_false_exclusion,
                    hamming, robust_log_e, simple_log_e)


class TestEnvelope(unittest.TestCase):
    def test_analytic_lower_envelope_matches_bruteforce(self):
        for n in range(0, 8):
            for obs in product((0, 1), repeat=n):
                for k in range(0, 3):
                    for p, q in ((.2, .8), (.8, .2), (.5, .7)):
                        lowest = min(simple_log_e(clean, p, q)
                                     for clean in product((0, 1), repeat=n)
                                     if hamming(clean, obs) <= k)
                        calc = robust_log_e(sum(obs), n, k, p, q)
                        self.assertAlmostEqual(calc, lowest, places=11)

    def test_pathwise_domination_with_all_corruptions(self):
        for n in range(0, 8):
            for clean in product((0, 1), repeat=n):
                for k in range(0, 3):
                    for j in range(min(k, n) + 1):
                        for change in combinations(range(n), j):
                            observed = [1 - x if i in change else x for i, x in enumerate(clean)]
                            for p, q in ((.2, .8), (.8, .2)):
                                self.assertLessEqual(
                                    robust_log_e(sum(observed), n, k, p, q),
                                    simple_log_e(clean, p, q) + 1e-10)

    def test_optional_stopping_false_exclusion_exact_bound(self):
        for p, q in ((.2, .8), (.8, .2), (.5, .7)):
            for k in (0, 1, 2):
                error = exact_worst_case_false_exclusion(9, k, p, q)
                self.assertLessEqual(error, .05 + 1e-10)

    def test_false_exclusion_persists(self):
        ep = RobustBernoulliEProcess(.2, .8, 1)
        for _ in range(20):
            ep.observe(1)
        self.assertTrue(ep.rejected)
        for _ in range(20):
            ep.observe(0)
        self.assertTrue(ep.rejected)

    def test_prefix_increasing_e_not_necessary(self):
        ep = RobustBernoulliEProcess(.2, .8, 2)
        ep.observe(1); v = ep.log_e
        ep.observe(0)
        self.assertNotEqual(v, ep.log_e)


class TestMatchedComparators(unittest.TestCase):
    def test_clean_bayes_matches_simple_likelihood_ratio(self):
        for n in range(1, 25):
            for ones in range(n + 1):
                self.assertAlmostEqual(random_attack_bayes_posterior(ones, n, 0, 0),
                                       posterior_given_clean_ones(ones, n), places=12)

    def test_random_corruption_exact_brute_force_likelihood(self):
        for n in range(1, 6):
            for k in range(0, min(n, 2) + 1):
                eps = .11
                for observed in product((0, 1), repeat=n):
                    posterior = random_attack_bayes_posterior(sum(observed), n, k, eps)
                    terms = []
                    for p in (P_SAFE, P_RISK):
                        L = 0.0
                        for clean in product((0, 1), repeat=n):
                            j = hamming(clean, observed)
                            if j <= k:
                                L += (p ** sum(clean) * (1-p) ** (n-sum(clean))
                                      * eps ** j * (1-eps) ** (n-j))
                        terms.append(L)
                    self.assertAlmostEqual(posterior, terms[1] / sum(terms), places=12)

    def test_targeted_policy_likelihood_equals_exhaustive_preimage_sum(self):
        for n in range(1, 9):
            for k in range(0, min(n, 3) + 1):
                for truth, p in [('safe', P_SAFE), ('risky', P_RISK)]:
                    distribution = {}
                    for clean in product((0, 1), repeat=n):
                        rng = __import__('random').Random(1)
                        obs = tuple(apply_attack(clean, truth, 'targeted', k, 0, rng))
                        distribution[obs] = distribution.get(obs, 0) + (
                            p ** sum(clean) * (1-p) ** (n-sum(clean)))
                    for obs in product((0, 1), repeat=n):
                        self.assertAlmostEqual(targeted_attack_likelihood(obs, truth, k),
                                               distribution.get(obs, 0), places=11)

    def test_credal_bounds_include_all_clean_reconstructions(self):
        for n in range(1, 9):
            for obs in product((0, 1), repeat=n):
                for k in (0, 1, 2):
                    lo, hi = credal_posterior_interval(sum(obs), n, k)
                    for clean in product((0, 1), repeat=n):
                        if hamming(obs, clean) <= k:
                            p = posterior_given_clean_ones(sum(clean), n)
                            self.assertLessEqual(lo - 1e-12, p)
                            self.assertGreaterEqual(hi + 1e-12, p)

    def test_dedup_keeps_root_observations(self):
        bits = [1, 0, 1, 0, 0, 1]
        self.assertEqual(bits, dedup_with_verified_origins(bits, 11))

    def test_attack_budget(self):
        import random
        rng = random.Random(17)
        for n in (8, 24):
            for k in (0, 1, 3):
                for truth, p in [('safe', P_SAFE), ('risky', P_RISK)]:
                    for scenario in ('targeted', 'random', 'clean'):
                        for _ in range(20):
                            clean = [int(rng.random() < p) for _ in range(n)]
                            obs = apply_attack(clean, truth, scenario, k, .04, rng)
                            self.assertLessEqual(hamming(clean, obs), k)

    def test_robust_decision_is_conservative_when_ambiguous(self):
        from adversarial_benchmark import ace_action
        self.assertEqual(ace_action(('safe', 'risky')), 'lock')
        self.assertEqual(ace_action(('safe',)), 'open')
        self.assertEqual(ace_action(('risky',)), 'lock')
        self.assertEqual(ace_action(()), 'lock')


if __name__ == '__main__':
    unittest.main()
