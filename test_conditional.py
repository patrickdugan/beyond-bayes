"""v0.6 conditional process: exact numeric and adversarial tests."""
from __future__ import annotations

from itertools import product
import math
import random
import unittest

from conditional import (ConditionalNull, ConditionalRow, anytime_robust_max_log_e,
                         clean_log_e, compatible, null_trace_probability, credal_log_e_prefixes,
                         robust_log_e_prefixes)
from robust import robust_log_e_with_erasures


class ConditionalModelTests(unittest.TestCase):
    def setUp(self):
        self.model = ConditionalNull.markov(initial=(.70, .85),
                                            after_zero=(.60, .75),
                                            after_one=(.80, .95), bet_q=.2)

    def test_invalid_bounds(self):
        for lo, hi in [(0, 1), (.9, .8), (-.2, .8)]:
            with self.assertRaises(ValueError):
                ConditionalRow('x', lo, hi, .2, 'x', 'x')

    def test_invalid_bet(self):
        with self.assertRaises(ValueError):
            ConditionalRow('x', .1, .8, float('nan'), 'x', 'x')

    def test_bad_state_references(self):
        with self.assertRaises(ValueError):
            ConditionalNull('first', (ConditionalRow('first', .8, .8, .2, 'missing', 'first'),))

    def test_unused_state(self):
        with self.assertRaises(ValueError):
            ConditionalNull('first', (ConditionalRow('first', .8, .8, .2, 'first', 'first'),
                                      ConditionalRow('unused', .8, .8, .2, 'unused', 'unused')))

    def test_duplicate_state(self):
        with self.assertRaises(ValueError):
            ConditionalNull('same', (ConditionalRow('same', .8, .8, .2, 'same', 'same'),
                                     ConditionalRow('same', .7, .7, .2, 'same', 'same')))

    def test_submartingale_not_permitted_at_any_endpoint(self):
        for row in self.model.rows:
            for p in (row.low, (row.low+row.high)/2, row.high):
                self.assertLessEqual(row.expected_factor(p), 1 + 1e-12)

    def test_credal_factors_are_more_conservative(self):
        for row in self.model.rows:
            for bit in (0,1):
                self.assertLessEqual(row.credal_log_factor(bit),row.log_factor(bit)+1e-12)
        for bits in product((0,1,None),repeat=4):
            for budget in (0,1):
                c=credal_log_e_prefixes(bits,budget,self.model)[-1]
                e=robust_log_e_prefixes(bits,budget,self.model)[-1]
                self.assertLessEqual(c,e+1e-12)

    def test_credal_equal_to_eprocess_for_exact_null(self):
        model=ConditionalNull.iid(.8,.2)
        for bits in product((0,1,None),repeat=4):
            self.assertAlmostEqual(credal_log_e_prefixes(bits,1,model)[-1],
                                   robust_log_e_prefixes(bits,1,model)[-1])

    def test_upper_bet_chooses_high_endpoint(self):
        row = ConditionalRow('s', .2, .5, .9, 's', 's')
        self.assertAlmostEqual(row.expected_factor(.5), 1.)
        self.assertLess(row.expected_factor(.2), 1.)

    def test_inside_envelope_bet_is_neutral(self):
        row = ConditionalRow('s', .2, .8, .5, 's', 's')
        self.assertEqual(row.log_factor(0), 0)
        self.assertEqual(row.log_factor(1), 0)

    def test_model_commitment_pins_bet_and_null(self):
        model2 = ConditionalNull.markov(initial=(.70, .85),
                                        after_zero=(.60, .75),
                                        after_one=(.80, .94), bet_q=.2)
        self.assertNotEqual(self.model.commitment, model2.commitment)

    def test_iid_backwards_compat_no_corruption(self):
        model = ConditionalNull.iid(.8, .2)
        for data in product((0,1,None), repeat=5):
            result = robust_log_e_prefixes(data, 0, model)
            self.assertAlmostEqual(result[-1], robust_log_e_with_erasures(data,0,.8,.2))

    def test_iid_backwards_compat_corrupted(self):
        model = ConditionalNull.iid(.8, .2)
        for data in product((0,1,None), repeat=5):
            for k in range(3):
                result = robust_log_e_prefixes(data, k, model)
                self.assertAlmostEqual(result[-1], robust_log_e_with_erasures(data,k,.8,.2))

    def test_dp_matches_exhaustive_clean_paths(self):
        for reported in product((0,1,None), repeat=5):
            for k in (0,1,2):
                scores = []
                for clean in product((0,1), repeat=5):
                    if compatible(clean,reported,k):
                        scores.append(clean_log_e(clean, self.model))
                self.assertAlmostEqual(robust_log_e_prefixes(reported,k,self.model)[-1],
                                       min(scores),places=11)

    def test_pathwise_bound_holds_for_all_adversarial_sequences(self):
        for clean in product((0,1), repeat=5):
            for observed in product((0,1,None), repeat=5):
                if compatible(clean,observed,1):
                    scores = robust_log_e_prefixes(observed,1,self.model)
                    self.assertTrue(all(r<=clean_log_e(clean[:t],self.model)+1e-10
                                        for t,r in enumerate(scores,1)))

    def test_optional_erasure_cannot_increase_evidence(self):
        for obs in product((0,1), repeat=5):
            complete = robust_log_e_prefixes(obs,1,self.model)[-1]
            for i in range(5):
                erased=list(obs);erased[i]=None
                self.assertLessEqual(robust_log_e_prefixes(erased,1,self.model)[-1],complete+1e-11)

    def test_increased_corruption_budget_cannot_increase_evidence(self):
        for observed in product((0,1,None), repeat=5):
            a=robust_log_e_prefixes(observed,0,self.model)[-1]
            b=robust_log_e_prefixes(observed,1,self.model)[-1]
            self.assertLessEqual(b,a+1e-11)

    def test_null_markov_probabilities_sum_to_one(self):
        for horizon in (0,2,5,8):
            total=sum(null_trace_probability(x,self.model) for x in product((0,1),repeat=horizon))
            self.assertAlmostEqual(total,1)

    def test_exact_null_all_attacks_stay_inside_alpha(self):
        n=7;k=1;alpha=.05
        # Worst-case clairvoyant attacks: every 0/1/None reporting trace.
        # Each possible observed trace is scored once, then matched to clean
        # traces under the Hamming reconstruction limit.
        crossing=[]
        for observed in product((0,1,None),repeat=n):
            if anytime_robust_max_log_e(observed,k,self.model)>=math.log(1/alpha)-1e-11:
                crossing.append(observed)
        for endpoint in ('low','mid','high'):
            risk=0.0
            for clean in product((0,1),repeat=n):
                if any(compatible(clean,reported,k) for reported in crossing):
                    risk+=null_trace_probability(clean,self.model,endpoint=endpoint)
            self.assertLessEqual(risk,alpha+1e-11, (endpoint,risk))

    def test_bad_observations_rejected(self):
        for value in (True,2,'0',-1,0.0):
            with self.assertRaises(ValueError):
                robust_log_e_prefixes([value],0,self.model)

    def test_conditional_null_misspecification_breaks_guarantee(self):
        # True risky probability is .2, while the declared null is .8.
        # Out-of-model behaviour can make false opens approach certainty.
        from itertools import product
        iid=ConditionalNull.iid(.8,.2)
        risk=0.0
        for bits in product((0,1),repeat=10):
            if anytime_robust_max_log_e(bits,0,iid)>=math.log(20)-1e-12:
                risk+=(.2**sum(bits))*(.8**(10-sum(bits)))
        self.assertGreater(risk,.5)

    def test_invalid_budget_rejected(self):
        for k in (-1,1.0,True):
            with self.assertRaises(ValueError):
                robust_log_e_prefixes([1],k,self.model)

    def test_true_path_even_when_multiple_missing_and_corrupt(self):
        model=ConditionalNull.iid(.8,.2)
        observed=[0,None,1,None,0,1]
        true=[0,1,1,0,1,1]
        self.assertTrue(compatible(true, observed, 1))
        for t,score in enumerate(robust_log_e_prefixes(observed,1,model),1):
            self.assertLessEqual(score,clean_log_e(true[:t],model)+1e-12)


if __name__=='__main__':
    unittest.main()
