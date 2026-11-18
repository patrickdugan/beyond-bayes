"""BB-CQ-04 independent exact source-model, revision and policy tests."""
from dataclasses import replace
from fractions import Fraction as Q
from hashlib import sha256
from itertools import product
from math import comb
import unittest

from amendment_memory import EvidenceArchive, verify_archive_delta
from bb_cq04_core import (
    ARMS, CALIBRATION_ROOTS, CASE_PRIORS, DOMAIN, N, PILOT_ROOTS,
    PRACTICAL_FLOOR, binom_mass, brier, coarse_posterior,
    expected_authorization_cost, exact_population, make_root, policy_action,
    source_only_receipt, verified_replacement,
)
from revocable_bayes import MATCH_PROBS, PRIORS, posterior_counts


def independent_aggregate_oracle(old_m: int, new_q: int, j: int, n: int):
    """Enumerate all 2^n valid patterns and 2^j provisional bit patterns.

    Does not call binom_mass, coarse_posterior or combinatorial expected-risk
    code. Each true match vector is generated under the original mixture.
    """
    mass = [Q(0)] * len(PRIORS)
    for regime, (prior, t) in enumerate(zip(PRIORS, MATCH_PROBS)):
        for true_bits in product((0,1), repeat=n):
            matches = sum(true_bits)
            prior_mass = prior * t**matches * (1-t)**(n-matches)
            for old_bits in product((0,1), repeat=j):
                provisional_m = sum(true_bits[j:]) + sum(old_bits)
                q = sum(true_bits[:j])
                if provisional_m == old_m and q == new_q:
                    mass[regime] += prior_mass * Q(1,2**j)
    total = sum(mass,Q(0))
    return tuple(x/total for x in mass) if total else None


class BB04ExactTests(unittest.TestCase):
    def test_independent_coarse_posterior_oracle(self):
        for n in range(2,6):
            for j in range(1,n+1):
                for m in range(n+1):
                    for q in range(j+1):
                        oracle = independent_aggregate_oracle(m,q,j,n)
                        if oracle is None:
                            with self.assertRaises(ValueError):
                                coarse_posterior(m,q,j,n)
                        else:
                            self.assertEqual(coarse_posterior(m,q,j,n),oracle)

    def test_original_exact_counts_recover_with_verified_delta(self):
        for role, count in (("calibration",CALIBRATION_ROOTS),):
            roots = [make_root(role,i) for i in range(count)]
            self.assertEqual(len({x.id for x in roots}),len(roots))
            for root in roots:
                self.assertEqual(sum(a for a,_ in root.accepted),6)
                self.assertEqual(len(root.replacement_order),6)
                self.assertEqual(len(set(root.replacement_order)),6)
                for j in ARMS:
                    d = verified_replacement(root,j)
                    self.assertEqual(d["fine_posterior"],d["delta_posterior"])
                    self.assertEqual(sum(d["fine_posterior"],Q(0)),Q(1))
                    self.assertEqual(sum(d["coarse_posterior"],Q(0)),Q(1))
                    original, current, chosen = root.frames(j)
                    self.assertEqual(len(chosen),j)
                    self.assertEqual(set(i for i in range(N) if original[i]!=current[i])
                                     <=set(chosen),True)
                    self.assertEqual(sum(int(x==y) for x,y in current),
                                     d["old_match_count"] - sum(
                                         int(original[i][0]==original[i][1]) for i in chosen
                                     ) + d["new_amended_match_count"])

    def test_full_archive_can_reject_a_false_old_bit(self):
        archive = EvidenceArchive((0,1,1,0), (0,0,0,0))
        amended, delta = archive.change(0,1)
        self.assertTrue(verify_archive_delta(archive,amended,delta))
        self.assertFalse(verify_archive_delta(archive,amended,
                         replace(delta, old_match=1)))

    def test_error_budget_and_expected_case_loss(self):
        self.assertEqual(N,12)
        self.assertEqual(ARMS,(1,3,6))
        self.assertEqual(PRACTICAL_FLOOR,Q(1,50))
        self.assertEqual(len(CASE_PRIORS),5)
        for k in range(3):
            self.assertGreaterEqual(expected_authorization_cost(PRIORS,k),0)
            for p in CASE_PRIORS:
                for report in (0,1):
                    self.assertIsInstance(policy_action(PRIORS,p,report),bool)
        with self.assertRaises(ValueError):
            policy_action(PRIORS,CASE_PRIORS[0],True)
        with self.assertRaises(ValueError):
            coarse_posterior(12,1,0)

    def test_exact_population_mass_and_information_ordering(self):
        for j in ARMS:
            result=exact_population(j)
            self.assertEqual(result["total_probability"],Q(1))
            self.assertGreaterEqual(result["risk"]["coarse"],
                                    result["risk"]["fine"])
            self.assertGreaterEqual(result["risk"]["pooled"],
                                    result["risk"]["coarse"])
            self.assertGreaterEqual(result["regime_brier"]["coarse"],
                                    result["regime_brier"]["fine"])
            self.assertGreater(result["squared_l2_fine_coarse"],0)
            self.assertTrue(0 <= result["decision_disagreement_fraction"] <= 1)
        receipt=source_only_receipt()
        self.assertFalse(receipt["authorizes_action"])
        self.assertFalse(receipt["native_weights_loaded"])
        self.assertEqual(receipt["scientific_confirmation_roots"],0)
        self.assertTrue(all(v["independent_full_vs_delta_parity"]
                            for v in receipt["source_only_archive_fixtures"].values()))

    def test_root_types_reject_reuse_or_unregistered_roles(self):
        self.assertNotEqual(make_root("calibration",0).id,make_root("pilot",0).id)
        self.assertEqual(make_root("calibration",0),make_root("calibration",0))
        for role,idx in (("sealed",0),("pilot",-1),
                         ("pilot",PILOT_ROOTS),("calibration",CALIBRATION_ROOTS)):
            with self.assertRaises(ValueError):
                make_root(role,idx)

    def test_analytic_posterior_tower_small_domain(self):
        n,j=4,2
        numerators={}
        masses={}
        for regime,(prior,t) in enumerate(zip(PRIORS,MATCH_PROBS)):
            for true_bits in product((0,1),repeat=n):
                p=prior*t**sum(true_bits)*(1-t)**(n-sum(true_bits))
                full=posterior_counts(sum(true_bits),n)
                for old_bits in product((0,1),repeat=j):
                    coarse_key=(sum(old_bits)+sum(true_bits[j:]),sum(true_bits[:j]))
                    q=p*Q(1,2**j)
                    masses[coarse_key]=masses.get(coarse_key,Q(0))+q
                    vector=numerators.setdefault(coarse_key,[Q(0),Q(0),Q(0)])
                    for k in range(3):
                        vector[k]+=q*full[k]
        for (m,q),total in masses.items():
            expected=tuple(v/total for v in numerators[(m,q)])
            self.assertEqual(expected,coarse_posterior(m,q,j,n))


if __name__=="__main__":
    unittest.main()
