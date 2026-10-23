"""Brute-force validation of attacker DP and conditional-dependence counterexample."""
from itertools import product
import math
import unittest

from provenance import SignedEvidenceLedger, SignedObservation
from robust import robust_log_e_with_erasures
from source_attack_benchmark import adversary_can_trigger, exact_adaptive_error_with_erasures
from test_provenance import fixture, emit


class ExhaustiveAdversaryTests(unittest.TestCase):
    def test_full_ternary_attack_space_matches_reachable_state_dp(self):
        alpha=.2  # Smaller threshold yields positive and negative fixtures.
        for n in range(0,7):
            for clean in product((0,1),repeat=n):
                for k in (0,1,2):
                    oracle=False
                    for observed in product((0,1,None),repeat=n):
                        if sum(y is not None and y != x for x,y in zip(clean,observed)) > k:
                            continue
                        if max([0.] + [robust_log_e_with_erasures(
                                observed[:i],k,.8,.2) for i in range(1,n+1)]) >= math.log(1/alpha)-1e-12:
                            oracle=True
                            break
                    self.assertEqual(adversary_can_trigger(clean,k,.8,.2,alpha),oracle)

    def test_false_exclusion_exactly_obeys_alpha(self):
        for n in (6,8):
            for k in (0,1,2):
                r=exact_adaptive_error_with_erasures(n,k,.8,.2,.05)
                self.assertLessEqual(r,.05+1e-12)

    def test_correlated_signatures_can_still_break_iid_null(self):
        p, keys=fixture(n=24,k=0, null_p=.8,bet_q=.2)
        ledger=SignedEvidenceLedger(p,expected_commitment=p.commitment)
        emit(p,keys,ledger,[0]*24)  # One common latent draw Z=0 copied to 24 keys.
        self.assertTrue(ledger.decide().authorized)
        p_one, keys_one=fixture(n=1,k=0,null_p=.8,bet_q=.2)
        grouped=SignedEvidenceLedger(p_one,expected_commitment=p_one.commitment)
        emit(p_one,keys_one,grouped,[0])
        self.assertFalse(grouped.decide().authorized)


if __name__=='__main__':unittest.main()
