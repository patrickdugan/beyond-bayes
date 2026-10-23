"""Protocol contracts, cryptographic admission, and adversarial invariants."""
from dataclasses import replace
from itertools import combinations, product
import hashlib
import math
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from provenance import (Protocol, Slot, SignedObservation, SignedEvidenceLedger,
                        Receipt)
from robust import robust_log_e_with_erasures, robust_log_e, simple_log_e


def seed_key(identity: str) -> Ed25519PrivateKey:
    # Fixed PRIVATE TEST KEYS ONLY. Do not use deterministic secrets in deployments.
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(identity.encode()).digest())


def pub(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()


def fixture(n=12, k=2, alpha=.05, null_p=.8, bet_q=.2):
    keys = [seed_key(f'test-only-key-{i}') for i in range(n)]
    slots = tuple(Slot(f'unit-{i}', f'source-{i}', f'domain-{i}', pub(keys[i]))
                  for i in range(n))
    protocol = Protocol('experiment-2026-10-23', '8c7b7b5f1f44d9e32e493f85a6a5fddb',
                        slots, null_p, bet_q, alpha, k)
    return protocol, keys


def emit(protocol, keys, ledger, bits):
    for slot, key, bit in zip(protocol.slots, keys, bits):
        if bit is not None:
            ledger.offer(SignedObservation.issue(protocol, slot.slot_id, bit, key))


class TestAuthentication(unittest.TestCase):
    def test_commitment_changes_on_configuration_changes(self):
        p, _ = fixture()
        self.assertNotEqual(p.commitment, replace(p, alpha=.1).commitment)
        self.assertNotEqual(p.commitment, replace(p, corruption_budget=3).commitment)
        self.assertNotEqual(p.commitment, replace(p, bet_q=.1).commitment)
        self.assertNotEqual(p.commitment, replace(p, challenge='f' * 32).commitment)
        self.assertNotEqual(p.commitment, replace(p, slots=p.slots[::-1]).commitment)
        self.assertNotEqual(p.commitment, replace(p, experiment_id='other').commitment)

    def test_pinned_commitment_must_match(self):
        p, _ = fixture()
        with self.assertRaises(ValueError):
            SignedEvidenceLedger(p, expected_commitment='0' * 64)
        SignedEvidenceLedger(p, expected_commitment=p.commitment)

    def test_roster_rejects_duplicate_identity_domain_key(self):
        p, _ = fixture()
        for field in ('slot_id', 'source_id', 'dependence_domain', 'public_key_hex'):
            old = p.slots
            new_last = replace(old[-1], **{field: getattr(old[0], field)})
            with self.subTest(field=field), self.assertRaises(ValueError):
                replace(p, slots=old[:-1] + (new_last,))

    def test_retransmissions_idempotent_and_forks_fail_closed(self):
        p, keys = fixture(n=7, k=0)
        ledger = SignedEvidenceLedger(p, expected_commitment=p.commitment)
        for i in range(7):
            report = SignedObservation.issue(p, p.slots[i].slot_id, 0, keys[i])
            self.assertEqual(ledger.offer(report), Receipt.ACCEPTED)
            for j in range(15):
                self.assertEqual(ledger.offer(report), Receipt.DUPLICATE)
        self.assertTrue(ledger.decide().authorized)
        fork = SignedObservation.issue(p, p.slots[2].slot_id, 1, keys[2])
        self.assertEqual(ledger.offer(fork), Receipt.EQUIVOCATION)
        self.assertFalse(ledger.decide().authorized)
        self.assertEqual(ledger.equivocations, ('unit-2',))
        self.assertIsNone(ledger.observed[2])

    def test_extra_identity_signature_ignored(self):
        p, keys = fixture(n=4, k=0)
        ledger = SignedEvidenceLedger(p, expected_commitment=p.commitment)
        outsider = seed_key('forged-source')
        bad = SignedObservation.issue(p, 'not-in-roster', 0, outsider)
        before = ledger.decide()
        self.assertEqual(ledger.offer(bad), Receipt.QUARANTINED)
        after = ledger.decide()
        self.assertEqual(before.robust_max_log_e, after.robust_max_log_e)
        self.assertEqual(after.accepted_slots, 0)
        self.assertEqual(after.unauthorized_reports, 1)

    def test_wrong_key_and_tampering_rejected(self):
        p, keys = fixture(n=8, k=0)
        ledger = SignedEvidenceLedger(p, expected_commitment=p.commitment)
        report = SignedObservation.issue(p, p.slots[0].slot_id, 0, keys[0])
        self.assertEqual(ledger.offer(replace(report, bit=1)), Receipt.QUARANTINED)
        wrong = SignedObservation.issue(p, p.slots[0].slot_id, 0, keys[1])
        self.assertEqual(ledger.offer(wrong), Receipt.QUARANTINED)
        self.assertEqual(ledger.offer(report), Receipt.ACCEPTED)
        self.assertEqual(ledger.observed[0], 0)

    def test_replay_into_new_experiment_fails(self):
        p, keys = fixture(n=3, k=0)
        new = replace(p, challenge='b' * 32)
        ledger = SignedEvidenceLedger(new, expected_commitment=new.commitment)
        report = SignedObservation.issue(p, p.slots[0].slot_id, 0, keys[0])
        self.assertEqual(ledger.offer(report), Receipt.QUARANTINED)
        self.assertEqual(ledger.decide().accepted_slots, 0)

    def test_unknown_inputs_and_failing_construction(self):
        p, keys = fixture()
        with self.assertRaises(ValueError):
            SignedObservation.issue(p, p.slots[0].slot_id, True, keys[0])
        with self.assertRaises(ValueError):
            replace(p, alpha=math.nan)
        with self.assertRaises(ValueError):
            replace(p, slots=())
        ledger = SignedEvidenceLedger(p, expected_commitment=p.commitment)
        self.assertEqual(ledger.offer('not a signed observation'), Receipt.QUARANTINED)
        x = SignedObservation.issue(p, p.slots[0].slot_id, 0, keys[0])
        self.assertEqual(ledger.offer(replace(x, signature_hex='ff')), Receipt.QUARANTINED)
        self.assertEqual(ledger.offer(replace(x, bit=True)), Receipt.QUARANTINED)


class TestErasureEnvelope(unittest.TestCase):
    def test_erasure_bound_is_exact(self):
        for n in range(0, 7):
            for observed in product((0, 1, None), repeat=n):
                for k in (0, 1, 2):
                    for p, q in ((.8,.2),(.2,.8),(.5,.5)):
                        allowed = [clean for clean in product((0, 1), repeat=n)
                                   if sum(y is not None and y != x
                                          for x, y in zip(clean, observed)) <= k]
                        actual = min(simple_log_e(clean, p, q) for clean in allowed)
                        fast = robust_log_e_with_erasures(observed, k, p, q)
                        self.assertAlmostEqual(actual, fast, places=11)

    def test_matches_v02_when_there_are_no_erasures(self):
        for n in range(0, 9):
            for observed in product((0,1), repeat=n):
                for k in (0,1,2):
                    for p,q in ((.2,.8),(.8,.2)):
                        self.assertAlmostEqual(
                            robust_log_e_with_erasures(observed, k, p,q),
                            robust_log_e(sum(observed),n,k,p,q))

    def test_erasure_or_added_corruption_cannot_increase_evidence(self):
        for n in range(1, 8):
            for observed in product((0,1),repeat=n):
                for k in (0,1,2):
                    for p,q in ((.8,.2),(.2,.8)):
                        base = robust_log_e_with_erasures(observed,k,p,q)
                        for i in range(n):
                            erased = list(observed)
                            erased[i] = None
                            self.assertLessEqual(robust_log_e_with_erasures(erased,k,p,q),
                                                 base + 1e-12)
                        higher_budget = robust_log_e_with_erasures(observed,k+1,p,q)
                        self.assertLessEqual(higher_budget,base+1e-12)

    def test_all_admissible_clean_prefixes_dominate_reported_envelope(self):
        for n in range(0,7):
            for clean in product((0,1),repeat=n):
                for k in (0,1,2):
                    for erasures in product((0,1),repeat=n):
                        obs = tuple(None if erasures[i] else clean[i] for i in range(n))
                        v = robust_log_e_with_erasures(obs,k,.8,.2)
                        self.assertLessEqual(v,simple_log_e(clean,.8,.2)+1e-12)

    def test_admission_permutation_does_not_affect_score(self):
        p, keys = fixture(n=8, k=1)
        signed = [SignedObservation.issue(p, slot.slot_id, i % 2, keys[i])
                  for i, slot in enumerate(p.slots)]
        a = SignedEvidenceLedger(p, expected_commitment=p.commitment)
        b = SignedEvidenceLedger(p, expected_commitment=p.commitment)
        for r in signed:
            a.offer(r)
        for r in signed[::-1]:
            b.offer(r)
        self.assertEqual(a.observed,b.observed)
        self.assertEqual(a.decide(),b.decide())

    def test_missing_samples_still_take_schedule_positions(self):
        p, keys = fixture(n=12, k=0)
        ledger = SignedEvidenceLedger(p, expected_commitment=p.commitment)
        self.assertEqual(ledger.observed, (None,) * 12)
        emit(p, keys, ledger, [None]*6 + [0]*6)
        self.assertEqual(ledger.decide().missing_slots,6)
        self.assertFalse(ledger.decide().authorized)  # the early erased slots remain in the scheduled prefixes


if __name__ == '__main__':
    unittest.main()
