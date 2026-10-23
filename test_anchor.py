"""Adversarial ACE v0.5 anchor quorum / whole-database rollback tests."""
from __future__ import annotations

from contextlib import closing
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest

from anchor import (AnchorCertificate, AnchorError, AnchorIdentity, AnchorPolicy,
                    AnchorQuorum, AnchorReplica, AnchorVote,
                    verify_anchor_certificate)
from anchored_witness import AnchoredWitness
from provenance import _encoding
from test_provenance import seed_key, pub
from test_witnessed import setup, bit_reports
from witnessed import (GENESIS_DIGEST, Head, SignedHead, WitnessError,
                       snapshot_log_root)


class AnchorFixture(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.p,self.keys,self.policy,self.logkey,self.wkeys,_,self.log=setup()
        self.replica_keys=[seed_key(f'ACE-v05-anchor-{i}') for i in range(4)]
        self.anchor_policy=AnchorPolicy('notary-0',pub(self.wkeys[0]),
            self.policy.commitment,self.p.commitment,
            tuple(AnchorIdentity(f'anchor-{i}',pub(key))
                  for i,key in enumerate(self.replica_keys)),1,3)
        self.replicas=[AnchorReplica(self.anchor_policy,f'anchor-{i}',key,
                         self.root/f'anchor-{i}.sqlite')
                       for i,key in enumerate(self.replica_keys)]
        self.quorum=AnchorQuorum(self.anchor_policy,self.replicas)
        self.db=self.root/'witness.sqlite'

    def witness(self):
        return AnchoredWitness(self.policy,self.p,'notary-0',self.wkeys[0],
                               self.db,self.quorum)

    def original_local(self):
        with closing(sqlite3.connect(self.db)) as conn:
            return conn.execute('SELECT state,signature FROM states').fetchone()

    def roll_back_local(self,original):
        with closing(sqlite3.connect(self.db)) as conn,conn:
            conn.execute('UPDATE states SET state=?,signature=?',original)

    def restore_replica(self,index,rows):
        with closing(sqlite3.connect(self.replicas[index].db_path)) as db,db:
            db.execute('DELETE FROM records')
            db.executemany('INSERT INTO records '
                '(policy,seq,record,state,witness_sig,vote_sig) VALUES(?,?,?,?,?,?)',rows)


class AnchorProtocolTests(AnchorFixture):
    def test_genesis_and_receipt_are_independently_certified(self):
        w=self.witness()
        original=self.quorum.current()
        self.assertTrue(verify_anchor_certificate(original,self.anchor_policy))
        self.assertEqual(original.record.sequence,0)
        self.assertEqual(original.record.previous_digest,GENESIS_DIGEST)
        report=bit_reports(self.p,self.keys,[0])[0]
        receipt=w.receive(report)
        current=self.quorum.current()
        self.assertEqual(receipt.target_epoch,0)
        self.assertEqual(current.record.sequence,1)
        self.assertEqual(current.record.previous_digest,original.record.digest)
        self.assertEqual(len(current.votes),4)
        self.assertEqual(current.state_signature,self.original_local()[1])

    def test_duplicate_signed_receipt_does_not_advance_state_counter(self):
        w=self.witness()
        report=bit_reports(self.p,self.keys,[0])[0]
        first=w.receive(report)
        self.assertEqual(self.quorum.current().record.sequence,1)
        second=w.receive(report)
        self.assertEqual(first,second)
        self.assertEqual(self.quorum.current().record.sequence,1)

    def test_rollback_of_valid_local_snapshot_restores_latest_acknowledged_report(self):
        w=self.witness()
        original=self.original_local()
        report=bit_reports(self.p,self.keys,[0])[0]
        w.receive(report)
        self.assertNotEqual(self.original_local(),original)
        self.roll_back_local(original)
        recovered=self.witness()
        self.assertEqual(self.quorum.current().record.sequence,1)
        self.assertNotEqual(self.original_local(),original)
        head,_=self.log.seal()
        with self.assertRaisesRegex(WitnessError,'missing witnessed'):
            recovered.endorse(head,[])

    def test_unanchored_durable_witness_has_valid_snapshot_rollback_fork(self):
        from durable_witness import DurableWitness
        db=self.root/'unanchored-attack.sqlite'
        witness=DurableWitness(self.policy,self.p,'notary-0',self.wkeys[0],db)
        r0,r1=bit_reports(self.p,self.keys,[0,0])
        witness.receive(r0)
        with closing(sqlite3.connect(db)) as connection:
            earlier=connection.execute('SELECT state,signature FROM states').fetchone()
        first_head=Head(self.policy.commitment,self.p.commitment,0,1,
                        snapshot_log_root([r0]),GENESIS_DIGEST)
        first=SignedHead(first_head,self.logkey.sign(
            _encoding(first_head.canonical())).hex())
        a=witness.endorse(first,[r0])
        with closing(sqlite3.connect(db)) as connection,connection:
            connection.execute('UPDATE states SET state=?,signature=?',earlier)
        witness=DurableWitness(self.policy,self.p,'notary-0',self.wkeys[0],db)
        second_head=Head(self.policy.commitment,self.p.commitment,0,2,
                         snapshot_log_root([r0,r1]),GENESIS_DIGEST)
        second=SignedHead(second_head,self.logkey.sign(
            _encoding(second_head.canonical())).hex())
        b=witness.endorse(second,[r0,r1])
        self.assertNotEqual(a.head_digest,b.head_digest)
        self.assertEqual(a.witness_id,b.witness_id)
        self.assertEqual(first_head.epoch,second_head.epoch)

    def test_same_epoch_fork_after_full_local_rollback_rejected(self):
        w=self.witness()
        original=self.original_local()
        first,_=self.log.seal()
        endorsed=w.endorse(first,[])
        self.roll_back_local(original)
        recovered=self.witness()
        alt_report=bit_reports(self.p,self.keys,[0])[0]
        alternative=Head(self.policy.commitment,self.p.commitment,0,1,
                         snapshot_log_root([alt_report]),GENESIS_DIGEST)
        alt=SignedHead(alternative,self.logkey.sign(
                       _encoding(alternative.canonical())).hex())
        with self.assertRaisesRegex(WitnessError,'same witness refuses'):
            recovered.endorse(alt,[alt_report])
        self.assertEqual(self.quorum.current().record.sequence,1)
        self.assertEqual(recovered.endorse(first,[]).head_digest,endorsed.head_digest)

    def test_one_full_replica_rollback_still_fresh_and_progresses(self):
        w=self.witness()
        with closing(sqlite3.connect(self.replicas[0].db_path)) as db:
            genesis=db.execute('SELECT * FROM records').fetchall()
        w.receive(bit_reports(self.p,self.keys,[0])[0])
        self.restore_replica(0,genesis)    # Byzantine replica loses accepted state
        self.assertEqual(self.quorum.current().record.sequence,1)
        w.receive(bit_reports(self.p,self.keys,[0,1])[1])
        self.assertEqual(self.quorum.current().record.sequence,2)
        self.assertEqual(self.replicas[0].read()[0].sequence,0)
        self.assertTrue(all(r.read()[0].sequence==2 for r in self.replicas[1:]))

    def test_two_replica_rollbacks_fail_closed(self):
        w=self.witness()
        with closing(sqlite3.connect(self.replicas[0].db_path)) as db:
            genesis=db.execute('SELECT * FROM records').fetchall()
        w.receive(bit_reports(self.p,self.keys,[0])[0])
        for i in (0,1): self.restore_replica(i,genesis)
        with self.assertRaisesRegex(AnchorError,'unresolved'):
            self.witness()
        with self.assertRaisesRegex(AnchorError,'unresolved'):
            w.receive(bit_reports(self.p,self.keys,[0,1])[1])

    def test_external_commit_then_process_crash_recovers_even_without_local_commit(self):
        w=self.witness()
        parent=self.quorum.current()
        assert parent is not None
        # Simulate mutation + external commit but process death before the
        # local transaction made it durable.
        report=bit_reports(self.p,self.keys,[0])[0]
        from witnessed import Witness
        Witness.receive(w,report)
        raw=_encoding(w._snapshot())
        sig=self.wkeys[0].sign(raw)
        self.quorum.advance(raw,sig,parent)
        recovered=self.witness()
        self.assertEqual(self.quorum.current().record.sequence,1)
        head,_=self.log.seal()
        with self.assertRaisesRegex(WitnessError,'missing witnessed'):
            recovered.endorse(head,[])

    def test_corrupted_anchor_journal_detected_and_other_three_suffice(self):
        w=self.witness()
        w.receive(bit_reports(self.p,self.keys,[0])[0])
        with closing(sqlite3.connect(self.replicas[0].db_path)) as db,db:
            db.execute('UPDATE records SET state=? WHERE seq=1',(b'{}',))
        with self.assertRaises(AnchorError):self.replicas[0].read()
        self.assertEqual(self.quorum.current().record.sequence,1)

    def test_witness_state_and_vote_forgery_rejected(self):
        self.witness()
        cert=self.quorum.current()
        self.assertFalse(verify_anchor_certificate(
            replace(cert,state=b'{}'),self.anchor_policy))
        forged=replace(cert.votes[0],signature_hex='00'*64)
        self.assertFalse(verify_anchor_certificate(
            replace(cert,votes=(forged,)+cert.votes[1:]),self.anchor_policy))
        self.assertFalse(verify_anchor_certificate(
            replace(cert,votes=(cert.votes[0],)*4),self.anchor_policy))
        self.assertFalse(verify_anchor_certificate(
            replace(cert,votes=cert.votes[:2]),self.anchor_policy))
        with self.assertRaises(AnchorError):
            self.replicas[0].vote(cert.record,b'{}',b'0'*64)

    def test_stale_predecessor_and_skip_rejected(self):
        w=self.witness()
        first=self.quorum.current()
        w.receive(bit_reports(self.p,self.keys,[0])[0])
        with self.assertRaisesRegex(AnchorError,'stale'):
            self.quorum.advance(first.state,first.state_signature,first)
        from anchor import AnchorRecord
        prior=self.quorum.current()
        bad=AnchorRecord(self.anchor_policy.commitment,'notary-0',10,
                         prior.record.digest,prior.record.state_digest)
        with self.assertRaisesRegex(AnchorError,'skipped'):
            self.replicas[0].vote(bad,prior.state,prior.state_signature)

    def test_anchor_quorum_preconditions_and_identity_pinning(self):
        with self.assertRaisesRegex(AnchorError,'unsafe'):
            replace(self.anchor_policy,quorum=2)
        with self.assertRaisesRegex(AnchorError,'unsafe'):
            replace(self.anchor_policy,max_faulty=2)
        with self.assertRaisesRegex(AnchorError,'unsafe'):
            replace(self.anchor_policy,replicas=(self.anchor_policy.replicas[0],)*4)
        with self.assertRaisesRegex(AnchorError,'different signing key'):
            AnchoredWitness(self.policy,self.p,'notary-0',self.wkeys[1],
                            self.db,self.quorum)

    def test_legacy_nonempty_unanchored_db_requires_trusted_migration(self):
        from durable_witness import DurableWitness
        unanchored=DurableWitness(self.policy,self.p,'notary-0',self.wkeys[0],self.db)
        unanchored.receive(bit_reports(self.p,self.keys,[0])[0])
        with self.assertRaisesRegex(AnchorError,'requires trusted migration'):
            self.witness()

    def test_end_to_end_certificate_with_rollback_recovered_anchor(self):
        from witnessed import (Witness, IntakeLog, export_witnessed_certificate,
                               verify_witnessed_certificate)
        w=self.witness()
        p,keys,policy,logkey,wkeys,others,log=setup()
        # Setup() uses deterministic research fixtures and matches the
        # pinned witness/anchor policy of this test class.
        local_before=self.original_local()
        reports=bit_reports(self.p,self.keys,[0]*12)
        for report in reports:
            log.append(report)
            w.receive(report)
            for signer in others[1:3]: signer.receive(report)
        self.roll_back_local(local_before)
        w=self.witness()            # restored from remote quorum, not the disk
        signed,consistency=log.seal()
        endorsements=[w.endorse(signed,log.entries)] + [
            signer.endorse(signed,log.entries) for signer in others[1:3]
        ]
        bundle=export_witnessed_certificate(log,signed,endorsements,consistency)
        verified=verify_witnessed_certificate(bundle,
            expected_protocol=self.p.commitment,
            expected_policy=self.policy.commitment,
            expected_challenge=self.p.challenge,expected_epoch=0,
            expected_previous_digest=GENESIS_DIGEST)
        self.assertTrue(verified.authorized)
        self.assertEqual(verified.valid_sources,12)
        self.assertEqual(self.quorum.current().record.sequence,13)

    def test_partially_published_transition_suspends_recovery(self):
        w=self.witness()
        parent=self.quorum.current()
        report=bit_reports(self.p,self.keys,[0])[0]
        from witnessed import Witness
        Witness.receive(w,report)
        raw=_encoding(w._snapshot())
        sig=self.wkeys[0].sign(raw)
        from anchor import AnchorRecord,state_digest
        proposal=AnchorRecord(self.anchor_policy.commitment,'notary-0',1,
                              parent.record.digest,state_digest(raw,sig))
        self.replicas[0].vote(proposal,raw,sig)
        self.replicas[1].vote(proposal,raw,sig)
        # There was never a quorum certificate, so witness freezes. No
        # success response was returned to an external caller.
        with self.assertRaisesRegex(AnchorError,'unresolved'):
            self.witness()


if __name__=='__main__':
    unittest.main()
