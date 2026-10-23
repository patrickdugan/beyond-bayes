from copy import deepcopy
from dataclasses import replace
import unittest

from certificates import (export_certificate, verify_certificate, InvalidCertificate)
from provenance import SignedEvidenceLedger, SignedObservation, Receipt
from test_provenance import fixture, emit, seed_key


class CertificateTests(unittest.TestCase):
    def test_valid_authorization_and_denial_reproducible(self):
        for k,bits,expected in [(0, [0]*10, True), (0,[1]*10,False),
                                (2,[0]*4+[1]*6,False)]:
            protocol,keys=fixture(n=10,k=k)
            ledger=SignedEvidenceLedger(protocol,expected_commitment=protocol.commitment)
            emit(protocol,keys,ledger,bits)
            cert=export_certificate(ledger)
            self.assertIs(verify_certificate(cert, expected_commitment=protocol.commitment),expected)

    def test_silent_edit_must_invalidate_bundle(self):
        p,keys=fixture(n=9,k=0)
        l=SignedEvidenceLedger(p, expected_commitment=p.commitment)
        emit(p, keys,l,[0]*9)
        cert=export_certificate(l)
        self.assertTrue(verify_certificate(cert, expected_commitment=p.commitment))
        def mutated(fn):
            c=deepcopy(cert)
            fn(c)
            with self.assertRaises(InvalidCertificate):
                verify_certificate(c, expected_commitment=p.commitment)
        mutated(lambda c:c['claimed_decision'].update(authorized=False))
        mutated(lambda c:c['claimed_decision'].update(robust_max_log_e=0))
        mutated(lambda c:c['valid_signed_reports'][0].update(bit=1))
        mutated(lambda c:c['protocol'].update(alpha=.5))
        mutated(lambda c:c.update(protocol_commitment='f'*64))
        mutated(lambda c:c.update(valid_signed_reports=[]))
        with self.assertRaises(InvalidCertificate):
            verify_certificate(cert,expected_commitment='1'*64)

    def test_signed_conflict_cannot_be_hidden_if_included(self):
        p,keys=fixture(n=6,k=0)
        l=SignedEvidenceLedger(p,expected_commitment=p.commitment)
        emit(p,keys,l,[0]*6)
        l.offer(SignedObservation.issue(p,'unit-1',1,keys[1]))
        self.assertFalse(l.decide().authorized)
        cert=export_certificate(l)
        self.assertFalse(verify_certificate(cert,expected_commitment=p.commitment))
        self.assertEqual(len(cert['valid_signed_reports']),7)
        self.assertEqual(cert['claimed_decision']['equivocations'],['unit-1'])

    def test_quarantined_outsiders_have_no_effect_on_replayable_decision(self):
        p, keys = fixture(n=6,k=0)
        l=SignedEvidenceLedger(p,expected_commitment=p.commitment)
        emit(p,keys,l,[0]*6)
        prior=export_certificate(l)
        self.assertEqual(l.offer(SignedObservation.issue(p,'outsider',0,seed_key('fake'))),
                         Receipt.QUARANTINED)
        self.assertEqual(prior,export_certificate(l))


if __name__ == '__main__': unittest.main()
