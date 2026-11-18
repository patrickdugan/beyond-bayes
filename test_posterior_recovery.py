"""Independent raw-history checks for BB-CQ-05's information contracts.

The oracle enumerates vectors and uniformly selected named schedules. It uses
neither the production binomial likelihood nor its population enumerator.
All scoring tests here use small domains; the twelve-slot receipt is a separate
registered run and CI replay.
"""
from collections import defaultdict
from dataclasses import replace
from fractions import Fraction as Q
from functools import lru_cache
from itertools import combinations, product
from math import comb, prod
import unittest

from amendment_memory import EvidenceArchive, apply_externally_verified_delta
from posterior_recovery import (
    CalibratedCount, apply_checked_delta, correction_witness, disclosure_curve,
    early_count_state, initial_posterior, memory_certificate, population_point,
    recovery_posterior,
)


# Declared independently from the protocol, without importing scorer constants.
PRIOR = (Q(9, 20), Q(7, 20), Q(1, 5))
CHANNEL = (Q(19, 20), Q(13, 20), Q(3, 20))


def _likelihood(bits, probability):
    return prod((probability if bit else 1 - probability for bit in bits),
                start=Q(1))


def _normalize(weights):
    total = sum(weights, Q(0))
    return tuple(weight / total for weight in weights)


@lru_cache(maxsize=None)
def _iid_posterior(bits):
    return _normalize(tuple(prior * _likelihood(bits, probability)
                            for prior, probability in zip(PRIOR, CHANNEL)))


def _score(posterior, regime):
    return sum(((p - int(k == regime)) ** 2
                for k, p in enumerate(posterior)), Q(0))


@lru_cache(maxsize=None)
def _worlds(n, j):
    """Every named schedule, raw old vector and accepted replacement vector."""
    rows = []
    schedule_mass = Q(1, comb(n, j))
    for slots in combinations(range(n), j):
        for old in product((0, 1), repeat=n):
            valid = tuple(old[i] for i in range(n) if i not in slots)
            for new in product((0, 1), repeat=j):
                accepted = valid + new
                weights = tuple(
                    prior * schedule_mass * Q(1, 2) ** j
                    * _likelihood(accepted, probability)
                    for prior, probability in zip(PRIOR, CHANNEL)
                )
                rows.append((slots, old, new, weights, _iid_posterior(accepted)))
    return tuple(rows)


def _observation(row, revealed):
    slots, old, new, _, _ = row
    # Preserve all named new bits and disclosed old bits, not just their sums.
    return slots, sum(old), new, tuple(old[i] for i in slots[:revealed])


@lru_cache(maxsize=None)
def _revision_oracle(n, j, revealed):
    groups = defaultdict(lambda: [Q(0)] * 3)
    fine_means = defaultdict(lambda: [Q(0)] * 3)
    for row in _worlds(n, j):
        key = _observation(row, revealed)
        weights, fine = row[3:]
        mass = sum(weights, Q(0))
        for k in range(3):
            groups[key][k] += weights[k]
            fine_means[key][k] += mass * fine[k]
    posteriors = {key: _normalize(weights) for key, weights in groups.items()}
    total_mass = full_brier = recovery_brier = squared_gap = Q(0)
    for row in _worlds(n, j):
        weights, fine = row[3:]
        recovered = posteriors[_observation(row, revealed)]
        mass = sum(weights, Q(0))
        total_mass += mass
        full_brier += sum((weights[k] * _score(fine, k)
                           for k in range(3)), Q(0))
        recovery_brier += sum((weights[k] * _score(recovered, k)
                               for k in range(3)), Q(0))
        squared_gap += mass * sum(((a - b) ** 2
                                   for a, b in zip(fine, recovered)), Q(0))
    return {
        "posteriors": posteriors,
        "groups": dict(groups),
        "fine_means": dict(fine_means),
        "mass": total_mass,
        "full_brier": full_brier,
        "recovery_brier": recovery_brier,
        "regret": recovery_brier - full_brier,
        "squared_gap": squared_gap,
    }


class PosteriorRecoveryTests(unittest.TestCase):
    def test_initial_posterior_averages_hidden_uniform_schedules(self):
        """Old vector likelihood has count sufficiency only after averaging S."""
        for n in range(2, 5):
            for j in range(n + 1):
                for old in product((0, 1), repeat=n):
                    weights = [Q(0)] * 3
                    for slots in combinations(range(n), j):
                        valid = tuple(old[i] for i in range(n) if i not in slots)
                        for k in range(3):
                            weights[k] += (PRIOR[k] * Q(1, comb(n, j))
                                           * Q(1, 2) ** j
                                           * _likelihood(valid, CHANNEL[k]))
                    self.assertEqual(initial_posterior(sum(old), j, n),
                                     _normalize(weights), (n, j, old))

    def test_recovery_posterior_from_raw_named_observations(self):
        for n in range(2, 5):
            for j in range(n + 1):
                for revealed in range(j + 1):
                    oracle = _revision_oracle(n, j, revealed)
                    for key, posterior in oracle["posteriors"].items():
                        slots, old_m, new, old_revealed = key
                        actual = recovery_posterior(
                            old_m, sum(new), sum(old_revealed), revealed, j, n)
                        self.assertEqual(actual, posterior,
                                         (n, j, revealed, key))
                        # Independently establish the conditional-expectation
                        # tower using full raw-history posterior vectors.
                        group_mass = sum(oracle["groups"][key], Q(0))
                        self.assertEqual(
                            tuple(v / group_mass
                                  for v in oracle["fine_means"][key]),
                            posterior,
                        )

    def test_population_score_and_tower_against_raw_worlds(self):
        for n in range(2, 5):
            for j in range(n + 1):
                for revealed in range(j + 1):
                    expected = _revision_oracle(n, j, revealed)
                    actual = population_point(j, revealed, n)
                    self.assertEqual(expected["mass"], Q(1))
                    for key in ("mass", "full_brier", "recovery_brier",
                                "regret", "squared_gap"):
                        self.assertEqual(actual[key], expected[key],
                                         (n, j, revealed, key))
                    self.assertEqual(expected["regret"], expected["squared_gap"])

    def test_complete_small_domain_curves_and_zero_headroom_edges(self):
        for n in range(2, 5):
            for j in range(n + 1):
                curve = disclosure_curve(j, n)
                self.assertEqual([point["revealed"] for point in curve],
                                 list(range(j + 1)))
                self.assertEqual(curve[-1]["regret"], Q(0))
                for before, after in zip(curve, curve[1:]):
                    self.assertGreaterEqual(before["recovery_brier"],
                                            after["recovery_brier"])
                if j in (0, n):
                    self.assertTrue(all(point["regret"] == 0 for point in curve))
                    self.assertTrue(all(point["recovery_fraction"] is None
                                        for point in curve))
                else:
                    self.assertGreater(curve[0]["regret"], 0)
                    self.assertEqual(curve[0]["recovery_fraction"], Q(0))
                    self.assertEqual(curve[-1]["recovery_fraction"], Q(1))
                    for point in curve:
                        self.assertEqual(point["recovery_fraction"],
                                         1 - point["regret"] / curve[0]["regret"])

    def test_early_schedule_count_is_calibrated_at_every_step(self):
        n, j = 4, 2
        for slots, old, new, _, _ in _worlds(n, j):
            accepted = tuple(old[i] for i in range(n) if i not in slots)
            state = early_count_state(old, slots)
            self.assertEqual((state.matches, state.total),
                             (sum(accepted), len(accepted)))
            self.assertEqual(state.posterior, _iid_posterior(accepted))
            for bit in new:
                prior_state = state
                state = state.accept(bit)
                self.assertEqual((prior_state.matches, prior_state.total),
                                 (sum(accepted), len(accepted)))
                accepted += (bit,)
                self.assertEqual(state.posterior, _iid_posterior(accepted))
        self.assertEqual(early_count_state((0, 1), (0, 1)), CalibratedCount(0, 0))
        self.assertEqual(CalibratedCount(0, 0).posterior, PRIOR)

    def test_independent_continuation_signatures_and_witnesses(self):
        for n in range(2, 7):
            for j in range(1, n):
                slots_list = tuple(combinations(range(n), j))
                signatures = []
                for mask in range(1 << n):
                    signature = []
                    for slots in slots_list:
                        accepted = tuple((mask >> i) & 1
                                         for i in range(n) if i not in slots)
                        accepted += (0,) * j
                        signature.append(_iid_posterior(accepted))
                    signatures.append(tuple(signature))
                self.assertEqual(len(set(signatures)), 1 << n, (n, j))
                for left, right in combinations(range(1 << n), 2):
                    if left.bit_count() != right.bit_count():
                        continue
                    slots = correction_witness(left, right, j, n)
                    self.assertEqual(len(slots), j)
                    self.assertEqual(len(set(slots)), j)
                    self.assertTrue(all(type(i) is int and 0 <= i < n for i in slots))
                    a = sum((left >> i) & 1 for i in range(n) if i not in slots)
                    b = sum((right >> i) & 1 for i in range(n) if i not in slots)
                    self.assertNotEqual(a, b, (n, j, left, right, slots))

    def test_registered_initial_labels_and_memory_accounting(self):
        # Checks labels and bounds only, never evaluates the twelve-slot curve.
        for j in range(1, 12):
            labels = {initial_posterior(m, j, 12) for m in range(13)}
            self.assertEqual(len(labels), 13, j)
        for j in (1, 3, 6):
            certificate = memory_certificate(j, 12)
            expected = {
                "n": 12, "j": j, "initial_histories": 4096,
                "initial_posterior_count": 13,
                "max_same_posterior_histories": 924,
                "minimum_total_bits": 12,
                "extra_fixed_tag_bits_given_current_posterior": 10,
                "early_initial_count_states": 13 - j,
                "early_max_count_states": 13,
                "early_max_count_bits": 4,
                "old_total_message_values": j + 1,
                "old_total_message_bits": j.bit_length(),
            }
            for key, value in expected.items():
                self.assertEqual(certificate[key], value, (j, key))

    def test_trusted_old_total_recovers_exact_posterior(self):
        for slots, old, new, _, full in _worlds(4, 2):
            old_total = sum(old[i] for i in slots)
            final_count = sum(old) - old_total + sum(new)
            self.assertEqual(CalibratedCount(final_count, 4).posterior, full)
            self.assertEqual(recovery_posterior(sum(old), sum(new),
                                                old_total, 2, 2, 4), full)

    def test_checked_archive_delta_and_forged_old_value(self):
        before = EvidenceArchive((1, 0, 1, 0), (0, 0, 0, 0))
        after, delta = before.change(0, 0)
        result = apply_checked_delta(before.count, before.digest,
                                     before, after, delta)
        self.assertEqual(result, (after.count, after.digest))
        forged = replace(delta, old_match=0)
        # The numeric-only primitive has an explicit external-verifier premise.
        unchecked = apply_externally_verified_delta(
            before.count, forged, before.digest, 4)
        self.assertNotEqual(unchecked[0], after.count)
        with self.assertRaises(ValueError):
            apply_checked_delta(before.count, before.digest,
                                before, after, forged)

    def test_checked_archive_rejects_stale_inconsistent_and_replayed_inputs(self):
        before = EvidenceArchive((1, 0, 1, 0), (0, 0, 0, 0))
        after, delta = before.change(0, 0)
        wrong_after = EvidenceArchive((0, 1, 1, 0), after.versions)
        invalid_calls = [
            (before.count, "f" * 64, before, after, delta),
            (before.count + 1, before.digest, before, after, delta),
            (after.count, after.digest, after, after, delta),
            (before.count, before.digest, before, wrong_after, delta),
            (before.count, before.digest, before, after,
             replace(delta, old_version=1, new_version=2)),
            (before.count, before.digest, before, after,
             replace(delta, new_archive_digest="f" * 64)),
            (before.count, before.digest, before, after,
             replace(delta, new_version=True)),
            (before.count, before.digest, before, after,
             replace(delta, new_version=1.0)),
            (before.count, before.digest, before, after, None),
        ]
        for index, args in enumerate(invalid_calls):
            with self.subTest(case_index=index):
                with self.assertRaises(ValueError):
                    apply_checked_delta(*args)

    def test_validation_rejects_invalid_or_impossible_observations(self):
        # Prime valid calls so strict input checks also survive cache hits.
        initial_posterior(1, 1, 4)
        recovery_posterior(2, 0, 1, 1, 2, 4)
        bad_calls = [
            lambda: initial_posterior(True, 1, 4),
            lambda: initial_posterior(0, -1, 4),
            lambda: initial_posterior(0, 5, 4),
            lambda: initial_posterior(0, 0, 13),
            lambda: recovery_posterior(0, 0, 1, 1, 2, 4),
            lambda: recovery_posterior(4, 0, 0, 1, 2, 4),
            lambda: recovery_posterior(2, 3, 0, 0, 2, 4),
            lambda: recovery_posterior(2, 0, 0, 3, 2, 4),
            lambda: recovery_posterior(2, 0, True, 1, 2, 4),
            lambda: population_point(2, 3, 4),
            lambda: CalibratedCount(2, 1),
            lambda: CalibratedCount(0, -1),
            lambda: CalibratedCount(0, 13),
            lambda: CalibratedCount(0, 0).accept(True),
            lambda: CalibratedCount(3, 12).accept(0),
            lambda: early_count_state((0, 1), (0, 0)),
            lambda: early_count_state((0, 1), (2,)),
            lambda: early_count_state((0, True), (0,)),
            lambda: correction_witness(1, 1, 1, 4),
            lambda: correction_witness(0, 1, 1, 4),
            lambda: correction_witness(1, 2, 0, 4),
            lambda: correction_witness(1, 2, 4, 4),
            lambda: memory_certificate(0, 4),
        ]
        for index, call in enumerate(bad_calls):
            with self.subTest(case_index=index):
                with self.assertRaises(ValueError):
                    call()


if __name__ == "__main__":
    unittest.main()
