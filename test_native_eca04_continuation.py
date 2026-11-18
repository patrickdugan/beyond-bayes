"""Source-only tests for BB-CQ-02 frozen ECA-04 native development assay.

These do not load PyTorch, model weights, or any protected evaluation roots.
"""
from hashlib import sha256
import random
import unittest

from native_eca04_continuation import (
    COUNT, DOMAIN, PREFIX, generate, pairs, sign, valid,
)
from revocable_bayes import posterior_full_replay


class NativeECA04ContinuationSourceTests(unittest.TestCase):
    def test_public_root_cohort_and_eligibility_are_frozen(self):
        fixtures = [generate(i) for i in range(COUNT)]
        selected = [f for f in fixtures if f is not None]
        self.assertEqual((len(selected), len(fixtures) - len(selected)), (152, 104))
        self.assertEqual(len({f.root_sha256 for f in selected}), len(selected))
        first = selected[0]
        self.assertEqual(first.root_sha256,
                         "bd4dfecbe41121d2f7047295da956cbecb3d453c5f20025292cfc64e6f1cf00b")
        self.assertEqual(first.positions, (1, 5))

    def test_compensating_reissues_preserve_exact_bayes_and_suffix(self):
        for i in range(COUNT):
            f = generate(i)
            if f is None:
                continue
            self.assertEqual(len(f.original), 12)
            self.assertEqual(sum(r.known_label for r in f.original), 6)
            self.assertEqual([r.slot for r in f.original], [r.slot for r in f.corrected])
            original, changed = pairs(f.original), pairs(f.corrected)
            self.assertEqual(original[PREFIX:], changed[PREFIX:])
            self.assertEqual(posterior_full_replay(original), posterior_full_replay(changed))
            self.assertEqual(posterior_full_replay(original[:PREFIX]),
                             posterior_full_replay(changed[:PREFIX]))
            switched = [j for j in range(12) if original[j] != changed[j]]
            self.assertEqual(switched, list(f.positions))
            self.assertNotEqual(posterior_full_replay(original),
                                posterior_full_replay(original[:PREFIX]))

    def test_toy_host_resigns_only_changed_reports(self):
        f = generate(0)
        seed = bytes.fromhex(f.root_sha256)
        key = sha256(seed + b"/hypothetical-signer").digest()
        for before, after in zip(f.original, f.corrected):
            self.assertTrue(valid(before, key))
            self.assertTrue(valid(after, key))
            if before.report != after.report:
                self.assertNotEqual(before.mac, after.mac)
            else:
                self.assertEqual(before.mac, after.mac)
        mutated = f.corrected[0]
        self.assertFalse(valid(type(mutated)(mutated.slot, mutated.known_label,
                                             1 - mutated.report, mutated.mac), key))

    def test_roster_is_public_deterministic_and_bounded(self):
        rng = random.Random(20261118)
        for i in (0, 1, 7, 15, 64, 127, 255):
            self.assertEqual(generate(i), generate(i))
        for bad in (True, -1, COUNT):
            with self.assertRaises(ValueError):
                generate(bad)
        self.assertEqual(PREFIX, 6)
        self.assertTrue(DOMAIN.startswith("bb-cq02-public-development-"))


if __name__ == "__main__":
    unittest.main()
