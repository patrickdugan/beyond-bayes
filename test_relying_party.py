import tempfile
from pathlib import Path
import unittest

from certificates import InvalidCertificate
from relying_party import ActionGate
from test_witnessed import build_baseline, setup, bit_reports
from witnessed import (GENESIS_DIGEST, export_witnessed_certificate)


class GateTests(unittest.TestCase):
    def test_single_use_authorization_persists_across_process_instances(self):
        p,keys,policy,logkey,wkeys,witnesses,log,reports,signed,cert=build_baseline()
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'gate.sqlite'
            first=ActionGate(path)
            d=first.verify_and_consume(cert,expected_protocol=p.commitment,
                                       expected_policy=policy.commitment,
                                       expected_challenge=p.challenge)
            self.assertTrue(d.authorized)
            self.assertEqual(first.anchor(policy.commitment),(0,signed.head.digest))
            reopened=ActionGate(path)
            with self.assertRaisesRegex(InvalidCertificate,'consumed'):
                reopened.verify_and_consume(cert,expected_protocol=p.commitment,
                                            expected_policy=policy.commitment,
                                            expected_challenge=p.challenge)

    def test_denied_epoch_can_advance_before_authorization(self):
        p,keys,policy,logkey,wkeys,ws,log=setup()
        # Empty checkpoint denies because no observations.
        head0,path=log.seal()
        endorse0=[w.endorse(head0,log.entries) for w in ws[:3]]
        cert0=export_witnessed_certificate(log,head0,endorse0,path)
        with tempfile.TemporaryDirectory() as tmp:
            gate=ActionGate(Path(tmp)/'store.sqlite')
            decision=gate.verify_and_consume(cert0,expected_protocol=p.commitment,
                                             expected_policy=policy.commitment,
                                             expected_challenge=p.challenge)
            self.assertFalse(decision.authorized)
            for r in bit_reports(p,keys,[0]*12):
                for w in ws[:3]: w.receive(r)
                log.append(r)
            head1,consistency=log.seal()
            endorse1=[w.endorse(head1,log.entries) for w in ws[:3]]
            cert1=export_witnessed_certificate(log,head1,endorse1,consistency,head0.head)
            d=gate.verify_and_consume(cert1,expected_protocol=p.commitment,
                                      expected_policy=policy.commitment,
                                      expected_challenge=p.challenge)
            self.assertTrue(d.authorized)
            self.assertEqual(d.epoch,1)
            with self.assertRaises(InvalidCertificate):
                gate.verify_and_consume(cert1,expected_protocol=p.commitment,
                                        expected_policy=policy.commitment,
                                        expected_challenge=p.challenge)

    def test_invalid_bundle_does_not_advance_anchor(self):
        p,keys,policy,logkey,wkeys,ws,log,reports,signed,cert=build_baseline()
        with tempfile.TemporaryDirectory() as tmp:
            gate=ActionGate(Path(tmp)/'store.sqlite')
            with self.assertRaises(InvalidCertificate):
                gate.verify_and_consume(cert,expected_protocol=p.commitment,
                                        expected_policy=policy.commitment,
                                        expected_challenge='wrong')
            self.assertIsNone(gate.anchor(policy.commitment))


if __name__ == '__main__': unittest.main()
