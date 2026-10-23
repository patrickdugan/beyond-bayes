"""Adversarial v0.4 checkpoint, receipt, replay and fork regression tests."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
from itertools import combinations
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from certificates import InvalidCertificate, export_certificate, verify_certificate
from provenance import SignedObservation, SignedEvidenceLedger
from test_provenance import fixture, seed_key, pub
from witnessed import (CheckpointEndorsement, GENESIS_DIGEST, Head, IntakeLog,
    ReportReceipt, SignedHead, Witness, WitnessError, WitnessIdentity, WitnessPolicy,
    export_witnessed_certificate, report_digest, verify_receipts,
    verify_witnessed_certificate, _encoding, snapshot_log_root)


def setup(n=12, corruption=0):
    protocol, keys = fixture(n=n,k=corruption)
    logkey=seed_key('research-log-key-v04')
    witnesskeys=[seed_key('witness-test-v04-'+str(i)) for i in range(4)]
    policy=WitnessPolicy(protocol.commitment,pub(logkey),
                         tuple(WitnessIdentity(f'notary-{i}',pub(k))
                               for i,k in enumerate(witnesskeys)),
                         max_faulty=1,checkpoint_quorum=3,receipt_quorum=3)
    witnesses=[Witness(policy,protocol,f'notary-{i}',witnesskeys[i])
               for i in range(4)]
    log=IntakeLog(protocol,policy,logkey)
    return protocol,keys,policy,logkey,witnesskeys,witnesses,log


def bit_reports(p,keys,bits):
    return [SignedObservation.issue(p,p.slots[i].slot_id,bit,keys[i])
            for i,bit in enumerate(bits) if bit is not None]


def verified(cert,p,policy,epoch=0,previous=GENESIS_DIGEST):
    return verify_witnessed_certificate(
        cert, expected_protocol=p.commitment,expected_policy=policy.commitment,
        expected_challenge=p.challenge,expected_epoch=epoch,
        expected_previous_digest=previous)


def build_baseline():
    p,keys,policy,logkey,wkeys,witnesses,log=setup()
    reports=bit_reports(p,keys,[0]*12)
    for r in reports:
        log.append(r)
        for w in witnesses[:3]:
            w.receive(r)
    signed,proof=log.seal()
    endorsements=[w.endorse(signed,log.entries) for w in witnesses[:3]]
    cert=export_witnessed_certificate(log,signed,endorsements,proof)
    return p,keys,policy,logkey,wkeys,witnesses,log,reports,signed,cert


class WitnessedTests(unittest.TestCase):
    def test_valid_witnessed_authorization_full_replay(self):
        p,keys,policy,logkey,wkeys,witnesses,log,reports,signed,cert=build_baseline()
        decision=verified(cert,p,policy)
        self.assertTrue(decision.authorized)
        self.assertEqual(decision.log_entries,12)
        self.assertEqual(decision.epoch,0)
        self.assertEqual(decision.checkpoint_digest,signed.head.digest)
        self.assertNotEqual(decision.checkpoint_digest,GENESIS_DIGEST)

    def test_signed_receipt_quorum_and_tampering(self):
        p,keys,policy,logkey,wkeys,ws,log=setup()
        report=bit_reports(p,keys,[0])[0]
        receipts=[w.receive(report) for w in ws[:3]]
        self.assertTrue(verify_receipts(report,receipts,policy,expected_epoch=0))
        self.assertFalse(verify_receipts(report,receipts[:2],policy,expected_epoch=0))
        self.assertFalse(verify_receipts(report,receipts+[receipts[0]],policy,expected_epoch=0))
        self.assertFalse(verify_receipts(report,[replace(receipts[0],report_digest='00'*32)]
                                         + receipts[1:],policy,expected_epoch=0))
        self.assertFalse(verify_receipts(report,[replace(receipts[0],signature_hex='ff'*64)]
                                         + receipts[1:],policy,expected_epoch=0))
        report2=SignedObservation.issue(p,report.slot_id,1,keys[0])
        self.assertFalse(verify_receipts(report2,receipts,policy,expected_epoch=0))

    def test_receipt_quorum_blocks_colluding_collector_omission(self):
        p,keys,policy,logkey,wkeys,ws,log=setup()
        base=bit_reports(p,keys,[0]*12)
        for r in base:
            log.append(r)
        fork=SignedObservation.issue(p,p.slots[0].slot_id,1,keys[0])
        receipt_set=[ws[i].receive(fork) for i in (0,1,2)]
        self.assertTrue(verify_receipts(fork,receipt_set,policy,expected_epoch=0))
        signed,_=log.seal()  # collector omits real fork from full list
        successful=[]
        for w in ws:
            try:
                successful.append(w.endorse(signed,log.entries))
            except WitnessError:
                pass
        self.assertEqual({s.witness_id for s in successful},{'notary-3'})
        for subset in combinations(ws,3):
            self.assertTrue(any(w.witness_id in {'notary-0','notary-1','notary-2'}
                                for w in subset))
        # Demonstrate v0.3's authenticated-bundle omission counterexample.
        ledger=SignedEvidenceLedger(p,expected_commitment=p.commitment)
        for r in base:
            ledger.offer(r)
        self.assertTrue(verify_certificate(export_certificate(ledger),
                                           expected_commitment=p.commitment))

    def test_one_corrupt_witness_cannot_cover_quorum_acknowledged_omission(self):
        p,keys,policy,logkey,wkeys,ws,log=setup()
        for r in bit_reports(p,keys,[0]*12): log.append(r)
        fork=SignedObservation.issue(p,p.slots[0].slot_id,1,keys[0])
        for w in ws[:3]: w.receive(fork)
        head,_=log.seal()
        # Corrupt notary-0 signs dishonestly, bypassing Witness.endorse safeguards.
        from witnessed import CheckpointEndorsement
        fabricated_body={'domain':'ACE:checkpoint-endorsement:v1',
                         'witness_id':'notary-0','head_digest':head.head.digest}
        forged_by_insider=CheckpointEndorsement(
            'notary-0',head.head.digest,wkeys[0].sign(_encoding(fabricated_body)).hex())
        endorsements=[forged_by_insider,ws[3].endorse(head,log.entries)]
        for w in ws[1:3]:
            with self.assertRaises(WitnessError): w.endorse(head,log.entries)
        c=export_witnessed_certificate(log,head,endorsements,[])
        with self.assertRaisesRegex(InvalidCertificate,'quorum'):
            verified(c,p,policy)

    def test_receipts_after_sealing_target_future_epoch(self):
        p,keys,policy,logkey,wkeys,ws,log,reports,signed,cert=build_baseline()
        fork=SignedObservation.issue(p,p.slots[0].slot_id,1,keys[0])
        later=[w.receive(fork) for w in ws[:3]]
        self.assertTrue(verify_receipts(fork,later,policy,expected_epoch=1))
        self.assertFalse(verify_receipts(fork,later,policy,expected_epoch=0))
        # Retrospective disagreement is possible; the sealed certificate is
        # valid only for reports quorum-acknowledged BEFORE its epoch closed.
        self.assertTrue(verified(cert,p,policy).authorized)

    def test_subthreshold_acknowledgment_does_not_force_inclusion(self):
        p,keys,policy,logkey,wkeys,ws,log=setup()
        for r in bit_reports(p,keys,[0]*12):log.append(r)
        fork=SignedObservation.issue(p,p.slots[0].slot_id,1,keys[0])
        acknowledgments=[w.receive(fork) for w in ws[:2]]
        self.assertFalse(verify_receipts(fork,acknowledgments,policy,expected_epoch=0))
        head,path=log.seal()
        # The bad actor controls notary-0 and signs despite its receipt;
        # honest notaries 2 and 3 have never received the conflicting report.
        payload={'domain':'ACE:checkpoint-endorsement:v1',
                 'witness_id':'notary-0','head_digest':head.head.digest}
        compromised=CheckpointEndorsement('notary-0',head.head.digest,
                                          wkeys[0].sign(_encoding(payload)).hex())
        endorsements=[compromised,ws[2].endorse(head,log.entries),
                      ws[3].endorse(head,log.entries)]
        self.assertTrue(verified(export_witnessed_certificate(log,head,endorsements,path),
                                 p,policy).authorized)

    def test_threshold_requires_honest_witness_overlap(self):
        p,keys,policy,logkey,wkeys,ws,log=setup()
        for q in combinations(range(4),policy.checkpoint_quorum):
            for r in combinations(range(4),policy.receipt_quorum):
                for byzantine in combinations(range(4),policy.max_faulty):
                    self.assertGreater(len((set(q)&set(r))-set(byzantine)),0)
        with self.assertRaises(ValueError):
            replace(policy,checkpoint_quorum=2)
        with self.assertRaises(ValueError):
            replace(policy,receipt_quorum=2)
        with self.assertRaises(ValueError):
            replace(policy,max_faulty=2)
        self.assertGreater(2*policy.checkpoint_quorum,4+policy.max_faulty)
        self.assertGreater(policy.checkpoint_quorum+policy.receipt_quorum,4+policy.max_faulty)

    def test_omit_report_from_sealed_certificate_is_detected(self):
        p,keys,policy,logkey,wkeys,ws,log,reports,signed,cert=build_baseline()
        modified=deepcopy(cert)
        modified['complete_log']=modified['complete_log'][:-1]
        with self.assertRaises(InvalidCertificate): verified(modified,p,policy)
        modified=deepcopy(cert)
        modified['complete_log'][0]['bit']=1
        with self.assertRaises(InvalidCertificate): verified(modified,p,policy)
        modified=deepcopy(cert)
        modified['signed_head']['head']['root_hex']='00'*32
        with self.assertRaises(InvalidCertificate): verified(modified,p,policy)
        modified=deepcopy(cert)
        modified['claimed_decision']['authorized']=False
        with self.assertRaises(InvalidCertificate): verified(modified,p,policy)

    def test_witness_quorum_rejects_duplicates_missing_fake_signatures(self):
        p,keys,policy,logkey,wkeys,ws,log,reports,signed,cert=build_baseline()
        modified=deepcopy(cert)
        modified['endorsements']=modified['endorsements'][:2]
        with self.assertRaises(InvalidCertificate): verified(modified,p,policy)
        modified=deepcopy(cert)
        modified['endorsements']=[modified['endorsements'][0]]*3
        with self.assertRaises(InvalidCertificate): verified(modified,p,policy)
        modified=deepcopy(cert)
        modified['endorsements'][0]['signature_hex']='00'*64
        with self.assertRaises(InvalidCertificate): verified(modified,p,policy)
        modified=deepcopy(cert)
        modified['endorsements'][0]['witness_id']='fabricated-id'
        with self.assertRaises(InvalidCertificate): verified(modified,p,policy)
        modified=deepcopy(cert)
        modified['witness_policy']['checkpoint_quorum']=2
        with self.assertRaises(InvalidCertificate): verified(modified,p,policy)

    def test_pin_challenge_policy_and_epoch_for_anti_replay(self):
        p,keys,policy,logkey,wkeys,ws,log,reports,signed,cert=build_baseline()
        cases=[dict(expected_protocol='ff'*32),
               dict(expected_policy='ee'*32),
               dict(expected_challenge='different'),
               dict(expected_epoch=1),
               dict(expected_previous_digest='ab'*32)]
        for overrides in cases:
            opts=dict(expected_protocol=p.commitment,expected_policy=policy.commitment,
                      expected_challenge=p.challenge,expected_epoch=0,
                      expected_previous_digest=GENESIS_DIGEST)
            opts.update(overrides)
            with self.subTest(overrides=overrides),self.assertRaises(InvalidCertificate):
                verify_witnessed_certificate(cert,**opts)

    def test_monotone_epoch_extension_and_late_equivocation(self):
        p,keys,policy,logkey,wkeys,ws,log,reports,signed,cert=build_baseline()
        self.assertTrue(verified(cert,p,policy).authorized)
        changed=SignedObservation.issue(p,p.slots[0].slot_id,1,keys[0])
        for w in ws[:3]:
            w.receive(changed)
        log.append(changed)
        signed2,proof=log.seal()
        endorsements2=[w.endorse(signed2,log.entries) for w in ws[:3]]
        cert2=export_witnessed_certificate(log,signed2,endorsements2,proof,signed.head)
        d2=verified(cert2,p,policy,epoch=1,previous=signed.head.digest)
        self.assertFalse(d2.authorized)
        self.assertEqual(d2.log_entries,13)
        self.assertEqual(cert2['claimed_decision']['equivocations'],['unit-0'])
        self.assertTrue(proof)
        # Faking a previous anchor or using a different epoch invalidates it.
        with self.assertRaises(InvalidCertificate): verified(cert2,p,policy,epoch=1)
        altered=deepcopy(cert2)
        altered['consistency_path'][-1]='ff'*32
        with self.assertRaises(InvalidCertificate):
            verified(altered,p,policy,epoch=1,previous=signed.head.digest)

    def test_same_epoch_split_view_denied_by_honest_witness(self):
        p,keys,policy,logkey,wkeys,ws,log,reports,signed,cert=build_baseline()
        alternative=Head(policy.commitment,p.commitment,0,0,
                         snapshot_log_root([]),GENESIS_DIGEST)
        alternate=SignedHead(alternative,logkey.sign(_encoding(alternative.canonical())).hex())
        for w in ws[:3]:
            with self.assertRaises(WitnessError): w.endorse(alternate,[])

    def test_invalid_signatures_not_admitted_to_log_or_witness(self):
        p,keys,policy,logkey,wkeys,ws,log=setup()
        report=bit_reports(p,keys,[0])[0]
        tampered=replace(report,signature_hex='00'*64)
        with self.assertRaises(WitnessError): log.append(tampered)
        with self.assertRaises(WitnessError): ws[0].receive(tampered)

    def test_clone_report_does_not_change_inference(self):
        p,keys,policy,logkey,wkeys,ws,log=setup()
        report=bit_reports(p,keys,[0])[0]
        log.append(report)
        a=SignedEvidenceLedger(p,expected_commitment=p.commitment)
        a.offer(report)
        before=a.decide()
        log.append(report)
        a.offer(report)
        after=a.decide()
        self.assertEqual(after.robust_max_log_e,before.robust_max_log_e)
        self.assertEqual(after.accepted_slots,before.accepted_slots)
        # Signature hex spelling is not a distinct observation bit.
        self.assertEqual(a.offer(replace(report,signature_hex=report.signature_hex.upper())).value,
                         'duplicate')

    def test_malformed_payloads_rejected_with_explanations(self):
        p,keys,policy,logkey,wkeys,ws,log,reports,signed,cert=build_baseline()
        edits=[
            lambda d:d['protocol'].update(null_p=True),
            lambda d:d['witness_policy']['witnesses'].append(deepcopy(d['witness_policy']['witnesses'][0])),
            lambda d:d['signed_head']['head'].update(epoch=True),
            lambda d:d.update(previous_head={'not':'a head'}),
            lambda d:d['signed_head'].update(extra=True),
            lambda d:d['complete_log'][0].update(extra=True),
            lambda d:d['claimed_decision'].update(robust_max_log_e=float('nan')),
        ]
        for i,edit in enumerate(edits):
            modified=deepcopy(cert)
            edit(modified)
            with self.subTest(i=i),self.assertRaises(InvalidCertificate):
                verified(modified,p,policy)


if __name__ == '__main__': unittest.main()
