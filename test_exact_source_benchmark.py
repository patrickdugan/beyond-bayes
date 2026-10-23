"""Cross-check exact DP probabilities with exhaustive 2^n traces."""
import unittest
from itertools import product

from exact_source_benchmark import exact_policy_rates
from source_attack_benchmark import attack_sample, naive_e_process_open
from robust import robust_log_e_with_erasures
import math


def score_roster(bits,k,alpha=.05):
    return max([0.] + [robust_log_e_with_erasures(bits[:t],k,.8,.2)
                        for t in range(1,len(bits)+1)])>=math.log(1/alpha)


class ExactDPTests(unittest.TestCase):
    def test_every_clean_sequence_small_horizons(self):
        for n in range(2,9):
            for k,erase,forged in [(0,0,0),(0,2,5),(1,2,3),(2,3,0)]:
                for truth,p in [('safe',.2),('risky',.8)]:
                    expected_naive=expected_roster=0.
                    for clean in product((0,1),repeat=n):
                        obs, fake=attack_sample(clean,truth,k,erase,forged)
                        naive=naive_e_process_open([x for x in obs if x is not None]+fake,k)
                        ace=score_roster(obs,k)
                        mass=p**sum(clean)*(1-p)**(n-sum(clean))
                        expected_naive+=mass*naive
                        expected_roster+=mass*ace
                    naive,ace=exact_policy_rates(truth,n=n,k=k,erasures=erase,forged=forged)
                    self.assertAlmostEqual(naive,expected_naive,places=11)
                    self.assertAlmostEqual(ace,expected_roster,places=11)


if __name__ == '__main__': unittest.main()
