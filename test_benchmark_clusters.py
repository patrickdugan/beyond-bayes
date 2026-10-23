from itertools import product
import math
import unittest

from benchmark_clusters import (ALPHA, P_RISKY, P_SAFE, ace_authorize,
                                check_matched_identity, matched_bayes_authorize,
                                naive_bayes_as_clean_authorize, credal_bayes_authorize,
                                run, targeted_attack)
from conditional import ConditionalNull


class MatchedBayesianTests(unittest.TestCase):
    def test_exact_equivalence_with_equal_budget(self):
        self.assertTrue(check_matched_identity())

    def test_single_shared_latent_falsifier(self):
        iid=ConditionalNull.iid(.8,.2)
        self.assertTrue(ace_authorize([0]*24,0,iid))
        self.assertFalse(ace_authorize([0],0,iid))
        self.assertTrue(naive_bayes_as_clean_authorize([0]*24))
        self.assertFalse(matched_bayes_authorize([0],k=0))

    def test_credal_matches_exact_null_bayes(self):
        iid=ConditionalNull.iid(.8,.2)
        for bits in product((0,1,None),repeat=6):
            for k in (0,1):
                self.assertEqual(credal_bayes_authorize(bits,k=k,model=iid),
                                 matched_bayes_authorize(bits,k=k))

    def test_bayes_same_alpha_threshold(self):
        iid=ConditionalNull.iid(.8,.2)
        for bits in product((0,1),repeat=10):
            self.assertEqual(ace_authorize(bits,0,iid),matched_bayes_authorize(list(bits),k=0))

    def test_corruption_known_to_robust_bayes_and_ace(self):
        bits=[1]*3+[0]*15
        poisoned=targeted_attack(bits,k=2,erasures=3,truth='risky')
        self.assertEqual(ace_authorize(poisoned,2,ConditionalNull.iid(.8,.2)),
                         matched_bayes_authorize(poisoned,k=2))

    def test_invalid_attack_budget(self):
        with self.assertRaises(ValueError):
            matched_bayes_authorize([0],k=-2)

    def test_seed_reproducibility_and_exact_rows(self):
        a=run(40,seed=1001)
        b=run(40,seed=1001)
        self.assertEqual(a,b)
        exact=[r for r in a['rows'] if r['scenario'].endswith('_EXACT')]
        self.assertEqual(len(exact),4)
        self.assertEqual({r['method']:r['unsafe_rate'] for r in exact}['ACE-one-cluster'],0)
        self.assertAlmostEqual({r['method']:r['unsafe_rate'] for r in exact}['Sensor-naive-Bayes'],.2)


if __name__=='__main__':
    unittest.main()
