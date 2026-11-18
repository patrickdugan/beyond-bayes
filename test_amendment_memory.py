"""BB-CQ-03 exhaustive finite amendment and independent risk-oracle checks."""
from dataclasses import replace
from fractions import Fraction as Q
from itertools import combinations
from math import comb
import unittest

from amendment_memory import (
    EvidenceArchive, EvidenceDelta, aggregate_only_optimum, amendment_memory,
    apply_externally_verified_delta, corrected_count, count_mass,
    expected_aggregate_only_error, overwrite_match, source_aware_revised_posterior,
    verify_archive_delta,
)
from revocable_bayes import MATCH_PROBS, PRIORS, posterior_counts


class AmendmentMemoryTests(unittest.TestCase):
    def test_all_98304_n12_source_aware_amendments(self):
        checked = 0
        for mask in range(1 << 12):
            m = mask.bit_count()
            for slot in range(12):
                old = (mask >> slot) & 1
                for new in (0, 1):
                    amended = overwrite_match(mask, slot, new)
                    updated = corrected_count(m, old, new)
                    self.assertEqual(amended.bit_count(), updated)
                    self.assertEqual(source_aware_revised_posterior(mask, slot, new),
                                     posterior_counts(updated, 12))
                    checked += 1
        self.assertEqual(checked, 98304)

    def test_original_twelve_slot_memory_lower_bound(self):
        self.assertEqual(amendment_memory(12), {
            "slots": 12, "initial_histories": 4096,
            "current_posterior_count": 13,
            "max_same_posterior_histories": 924,
            "minimum_total_bits": 12,
            "extra_fixed_tag_bits_given_current_posterior": 10,
        })
        for n in range(1, 13):
            result = amendment_memory(n)
            self.assertEqual(result["max_same_posterior_histories"],
                             comb(n, n // 2))
            self.assertEqual(result["minimum_total_bits"], n)
        self.assertEqual(len({posterior_counts(i, 12) for i in range(13)}), 13)

    def test_every_same_posterior_pair_has_one_event_witness(self):
        # Exhaustive over every pair of histories sharing a match-count label
        # for n=6; n=12 follows from the same bitwise argument, with all
        # individual 12-slot amendments checked in test_all_98304...
        count = 0
        n = 6
        for a, b in combinations(range(1 << n), 2):
            if a.bit_count() != b.bit_count():
                continue
            slot = ((a ^ b) & -(a ^ b)).bit_length() - 1
            self.assertNotEqual(
                source_aware_revised_posterior(a, slot, 0, n),
                source_aware_revised_posterior(b, slot, 0, n),
            )
            count += 1
        self.assertEqual(count, 430)

    def test_exact_conditional_brier_floor_independent_oracle(self):
        for n in range(1, 7):
            for m in range(n + 1):
                masks = [v for v in range(1 << n) if v.bit_count() == m]
                for new in (0, 1):
                    result = aggregate_only_optimum(m, new, n)
                    targets = [source_aware_revised_posterior(mask, 0, new, n)
                               for mask in masks]
                    mean = tuple(sum((p[k] for p in targets), Q(0)) / len(targets)
                                 for k in range(3))
                    self.assertEqual(mean, result["optimal_aggregate_only_posterior"])
                    loss = sum((sum(((p[k] - mean[k])**2 for k in range(3)), Q(0))
                                for p in targets), Q(0)) / len(targets)
                    self.assertEqual(loss, result["squared_l2_error_floor"])
                    self.assertGreaterEqual(loss, 0)

    def test_original_model_probability_mass_and_expected_floor(self):
        for n in (1, 3, 6, 12):
            self.assertEqual(sum((count_mass(m, n) for m in range(n + 1)), Q(0)), Q(1))
            floor = expected_aggregate_only_error(n)
            if n == 1:
                self.assertEqual(floor, 0)
            else:
                self.assertGreater(floor, 0)
        # Independent original-data likelihood enumeration at n=6.
        n = 6
        avg_risk = Q(0)
        for mask in range(1 << n):
            m = mask.bit_count()
            prior_mass = sum((prior * t**m * (1-t)**(n-m)
                              for prior, t in zip(PRIORS, MATCH_PROBS)), Q(0))
            for new in (0, 1):
                mean = aggregate_only_optimum(m, new, n)["optimal_aggregate_only_posterior"]
                target = source_aware_revised_posterior(mask, 0, new, n)
                err = sum(((x-y)**2 for x,y in zip(target, mean)), Q(0))
                avg_risk += prior_mass * Q(1, 2) * err
        self.assertEqual(avg_risk, expected_aggregate_only_error(n))

    def test_local_archive_validator_and_external_delta_boundary(self):
        original = EvidenceArchive((0,1,0,1,1), (0,0,0,0,0))
        count, pin = original.count, original.digest
        for slot, new in ((0,1), (3,0), (3,1), (1,1), (4,0)):
            updated, delta = original.change(slot, new)
            self.assertTrue(verify_archive_delta(original, updated, delta))
            count, next_pin = apply_externally_verified_delta(count, delta, pin, 5)
            self.assertEqual(count, updated.count)
            self.assertEqual(next_pin, updated.digest)
            self.assertEqual(posterior_counts(count,5),
                             posterior_counts(updated.count, 5))
            self.assertFalse(verify_archive_delta(original, updated,
                                                   replace(delta, old_match=1-delta.old_match)))
            with self.assertRaises(ValueError):
                apply_externally_verified_delta(count, delta, "wrong-head", 5)
            original, pin = updated, next_pin

    def test_unverified_delta_can_deceive_numeric_only_consumer(self):
        # Only the archive-backed verifier can certify the old stored bit.
        archive = EvidenceArchive((0, 1), (0, 0))
        edited, correct_delta = archive.change(0, 1)
        forged = replace(correct_delta, old_match=1)
        self.assertFalse(verify_archive_delta(archive, edited, forged))
        numeric_only_count, _ = apply_externally_verified_delta(
            archive.count, forged, archive.digest, 2)
        self.assertNotEqual(numeric_only_count, edited.count)

    def test_reject_malformed_amendments(self):
        for fn in (
            lambda: overwrite_match(True, 0, 1),
            lambda: overwrite_match(0, True, 1),
            lambda: overwrite_match(0, 12, 1),
            lambda: corrected_count(2, 0, 1, 2),
            lambda: corrected_count(0, 1, 0, 2),
            lambda: aggregate_only_optimum(True, 0),
            lambda: count_mass(-1),
            lambda: amendment_memory(13),
            lambda: EvidenceArchive((0,2), (0,0)),
            lambda: EvidenceArchive((0,1), (0,-1)),
        ):
            with self.assertRaises(ValueError):
                fn()


if __name__ == "__main__":
    unittest.main()
