"""Campaign budget/antirollback tests; real Ed25519 signatures, synthetic data."""
from __future__ import annotations
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import shutil
import hashlib
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from anchor import AnchorIdentity
from campaign import (CampaignPolicy, CampaignReplica, CampaignQuorum,
                      CampaignRecord, CampaignCertificate, CampaignState,
                      CampaignError, SCALE, transition, verify_certificate,
                      unpack_policy, unpack_certificate)
from campaign_certificate import (CampaignActionGate, verify_attempt, export_attempt, campaign_context)
from certificates import InvalidCertificate
from witnessed import GENESIS_DIGEST
from clustered import Cluster, ClusterPlan
from conditional import ConditionalNull
from clustered_certificate import ActionIntent, AuthorizationPolicyV2, export_clustered_certificate
from test_witnessed import setup
from provenance import SignedObservation
from provenance import _digest


def fixture(tmp:Path,total_units:int=50_000_000_000, *, deterministic:bool=False):
    keys=([Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
              f'ACE-v08-fixture-anchor-{i}'.encode()).digest()) for i in range(4)]
          if deterministic else [Ed25519PrivateKey.generate() for _ in range(4)])
    identities=[]
    from witnessed import _key_hex
    for i,k in enumerate(keys):
        identities.append(AnchorIdentity(f'anchor-{i}',_key_hex(k)))
    policy=CampaignPolicy('regtest-test-campaign-0123456789',total_units,
                          tuple(identities),1,3)
    replicas=[CampaignReplica(policy,f'anchor-{i}',k,tmp/f'anchor-{i}.sqlite')
              for i,k in enumerate(keys)]
    return policy,keys,replicas,CampaignQuorum(policy,replicas)


def attempt(quorum:CampaignQuorum, *,alpha:float=.01,bits=None):
    # Reserve before generating any signed sensor observations.
    protocol,keys,policy,logkey,wkeys,ws,log=setup(n=12)
    plan=ClusterPlan(protocol, tuple(Cluster(f'group-{i//2}',
             (protocol.slots[i].slot_id,protocol.slots[i+1].slot_id))
             for i in range(0,12,2)), ConditionalNull.iid(.8,.2),0,alpha)
    view=quorum.current()
    units=round(alpha*SCALE)
    context=campaign_context(quorum.policy,previous_digest=view.head,
             sequence=view.sequence+1,alpha_units=units,
             spent_units=view.state.spent+units)
    action=ActionIntent(protocol.challenge,'release-test-action','unit-test-vault',
           {'amount':3,'network':'regtest','ace_campaign':context})
    auth=AuthorizationPolicyV2(protocol.commitment,policy.commitment,
                                plan.commitment,action.commitment)
    r=quorum.reserve(challenge=action.challenge,protocol=protocol.commitment,
                     witness_policy=policy.commitment,cluster_plan=plan.commitment,
                     v2_policy=auth.commitment,action=action.commitment,
                     alpha_units=units)
    vals=bits or [0]*6
    for i,slot in enumerate(protocol.slots):
        report=SignedObservation.issue(protocol,slot.slot_id,vals[i//2],keys[i])
        log.append(report)
        for witness in ws[:3]:witness.receive(report)
    head,proof=log.seal()
    endorsements=[w.endorse(head,log.entries) for w in ws[:3]]
    v2=export_clustered_certificate(log,head,endorsements,proof,plan=plan,action=action)
    pins=dict(expected_protocol=protocol.commitment,expected_policy=policy.commitment,
              expected_cluster_plan=plan.commitment,expected_v2_policy=auth.commitment,
              expected_action=action.commitment,expected_challenge=protocol.challenge,
              expected_epoch=0,expected_previous_digest=GENESIS_DIGEST)
    f=quorum.finalize(r,v2_certificate=v2,authorized=v2['claimed_decision_v2']['authorized'])
    wrapper=export_attempt(r,f,v2)
    return wrapper,pins,r,f


class BudgetLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.policy,self.keys,self.replicas,self.quorum=fixture(self.root)

    def test_baseline_reserve_finalize_consume_and_durable_reload(self):
        wrap,pins,r,f=attempt(self.quorum)
        self.assertEqual(self.quorum.current().state.spent,10_000_000_000)
        self.assertEqual(self.quorum.current().state.stage,'authorized')
        checked=verify_attempt(wrap,policy=self.policy,
             expected_reservation_digest=r.record.digest,
             expected_finalization_digest=f.record.digest,
             expected_previous_digest=GENESIS_DIGEST,expected_previous_spent_units=0,
             expected_v2_epoch=0,expected_v2_previous_digest=GENESIS_DIGEST)
        self.assertTrue(checked.authorized)
        g=CampaignActionGate(self.quorum)
        verified=g.check_and_consume(wrap,expected_v2_epoch=0,
                                     expected_v2_previous_digest=GENESIS_DIGEST)
        self.assertTrue(verified.authorized)
        self.assertTrue(verify_certificate(verified.consumption_certificate,self.policy))
        self.assertEqual(self.quorum.current().state.stage,'consumed')
        self.assertEqual(self.quorum.current().sequence,3)
        with self.assertRaises(CampaignError):
            g.check_and_consume(wrap,expected_v2_epoch=0,
                                expected_v2_previous_digest=GENESIS_DIGEST)
        recreated=CampaignQuorum(self.policy,[CampaignReplica(self.policy,f'anchor-{i}',self.keys[i],
                       self.root/f'anchor-{i}.sqlite') for i in range(4)])
        self.assertEqual(recreated.current().sequence,3)
        self.assertEqual(recreated.current().state.spent,10_000_000_000)
        with self.assertRaises(CampaignError):
            recreated.consume(f)

    def test_wrong_v2_certificate_or_alpha_does_not_open(self):
        wrap,pins,r,f=attempt(self.quorum)
        edits=[lambda b:b['v2_certificate']['cluster_plan'].update(alpha=.02),
               lambda b:b['v2_certificate']['claimed_decision_v2'].update(authorized=False),
               lambda b:b['reservation']['record']['payload'].update(alpha_units=100),
               lambda b:b['reservation']['record']['payload'].update(spent_units=100),
               lambda b:b['reservation']['record']['payload'].update(action='0'*64),
               lambda b:b['reservation']['record']['payload'].update(cluster_plan='0'*64),
               lambda b:b['finalization']['record']['payload'].update(authorized=False),
               lambda b:b['finalization']['record']['payload'].update(certificate_digest='f'*64),
               lambda b:b.update(schema='ACE-campaign-authorization-v2')]
        for edit in edits:
            changed=deepcopy(wrap); edit(changed)
            with self.subTest(edit=edit),self.assertRaises((InvalidCertificate,CampaignError)):
                CampaignActionGate(self.quorum).check_and_consume(changed,
                         expected_v2_epoch=0,expected_v2_previous_digest=GENESIS_DIGEST)
        # Honest unchanged decision can still consume.
        self.assertTrue(CampaignActionGate(self.quorum).check_and_consume(wrap,
                 expected_v2_epoch=0,expected_v2_previous_digest=GENESIS_DIGEST).authorized)

    def test_denial_spends_and_next_distinct_challenge(self):
        wrap,_,r,f=attempt(self.quorum,bits=[1]*6)
        self.assertEqual(self.quorum.current().state.stage,'denied')
        decision=CampaignActionGate(self.quorum).check_and_consume(wrap,
                         expected_v2_epoch=0,expected_v2_previous_digest=GENESIS_DIGEST)
        self.assertFalse(decision.authorized)
        self.assertIsNone(decision.consumption_certificate)
        self.assertEqual(self.quorum.current().state.spent,10_000_000_000)
        with self.assertRaises(CampaignError):
            self.quorum.reserve(challenge=r.record.payload['challenge'],protocol='0'*64,
                witness_policy='0'*64,cluster_plan='0'*64,v2_policy='0'*64,
                action='0'*64,alpha_units=1)
        # Distinct challenges must spend fresh alpha.
        t=self.quorum.reserve(challenge='another-test-challenge-2026',protocol='0'*64,
                witness_policy='0'*64,cluster_plan='0'*64,v2_policy='0'*64,
                action='0'*64,alpha_units=5_000_000_000)
        self.assertEqual(t.record.payload['spent_units'],15_000_000_000)
        with self.assertRaises(CampaignError):
            self.quorum.reserve(challenge='third-test-challenge-2026',protocol='0'*64,
                witness_policy='0'*64,cluster_plan='0'*64,v2_policy='0'*64,
                action='0'*64,alpha_units=1)

    def test_overspend_nonrefund_crash_and_exact_units(self):
        r=self.quorum.reserve(challenge='crash-test-2026-abcd',protocol='0'*64,
                witness_policy='0'*64,cluster_plan='0'*64,v2_policy='0'*64,
                action='0'*64,alpha_units=self.policy.total_units)
        self.assertEqual(self.quorum.current().state.spent,self.policy.total_units)
        self.assertEqual(self.quorum.current().state.stage,'reserved')
        with self.assertRaises(CampaignError):
            self.quorum.reserve(challenge='another-test-2026-efgh',protocol='0'*64,
                witness_policy='0'*64,cluster_plan='0'*64,v2_policy='0'*64,
                action='0'*64,alpha_units=1)
        f=self.quorum.commit('finalize',{'reservation_digest':r.record.digest,
                'certificate_digest':'f'*64,'authorized':False})
        self.assertEqual(self.quorum.current().state.stage,'denied')
        with self.assertRaises(CampaignError):
            self.quorum.reserve(challenge='another-test-2026-efgh',protocol='0'*64,
                witness_policy='0'*64,cluster_plan='0'*64,v2_policy='0'*64,
                action='0'*64,alpha_units=1)
        with self.assertRaises(CampaignError):
            self.quorum.commit('consume',{'finalization_digest':f.record.digest})

    def test_one_replica_full_database_rollback_detected_by_quorum(self):
        # Snapshot an old but intact DB; ordinary signature validation accepts it.
        path=self.root/'anchor-0.sqlite'; copy=self.root/'stale.sqlite'
        shutil.copyfile(path,copy)
        wrap,pins,r,f=attempt(self.quorum)
        consumed=CampaignActionGate(self.quorum).check_and_consume(wrap,
                         expected_v2_epoch=0,expected_v2_previous_digest=GENESIS_DIGEST)
        shutil.copyfile(copy,path)
        self.assertEqual(self.quorum.current().sequence,3)
        self.assertEqual(self.quorum.current().state.stage,'consumed')
        with self.assertRaises(CampaignError):
            self.quorum.consume(f)

    def test_two_rolled_back_replicas_suspend_signing(self):
        for i in (0,1):
            shutil.copyfile(self.root/f'anchor-{i}.sqlite',self.root/f'old{i}.sqlite')
        r=self.quorum.reserve(challenge='rollback-epoch-challenge',protocol='0'*64,
                         witness_policy='0'*64,cluster_plan='0'*64,v2_policy='0'*64,
                         action='0'*64,alpha_units=1)
        for i in (0,1):
            shutil.copyfile(self.root/f'old{i}.sqlite',self.root/f'anchor-{i}.sqlite')
        with self.assertRaises(CampaignError):
            self.quorum.current()
        with self.assertRaises(CampaignError):
            self.quorum.commit('finalize',{'reservation_digest':r.record.digest,
                      'certificate_digest':'0'*64,'authorized':False})

    def test_partial_commit_suspends_and_duplicate_vote_recovers(self):
        # Two willing replicas and two unavailable ones leave a durable partial.
        bad=[self.replicas[i] for i in (2,3)]
        previous=[rep.vote for rep in bad]
        for rep in bad:
            def refuse(record): raise CampaignError('replica unreachable')
            rep.vote=refuse
        with self.assertRaises(CampaignError):
            self.quorum.reserve(challenge='partial-2026-reservation',protocol='0'*64,
                   witness_policy='0'*64,cluster_plan='0'*64,v2_policy='0'*64,
                   action='0'*64,alpha_units=1)
        with self.assertRaises(CampaignError):self.quorum.current()
        for rep,fn in zip(bad,previous):rep.vote=fn
        # The same exact event can recover by replaying its committed votes.
        old=self.replicas[0].history()[0][0]
        votes=[rep.vote(old) for rep in self.replicas]
        self.assertTrue(verify_certificate(CampaignCertificate(old,tuple(votes)),self.policy))
        self.assertEqual(self.quorum.current().state.spent,1)

    def test_corrupt_vote_and_single_successor(self):
        r=self.quorum.reserve(challenge='vote-conflict-challenge',protocol='0'*64,
            witness_policy='0'*64,cluster_plan='0'*64,v2_policy='0'*64,action='0'*64,
            alpha_units=1)
        tampered=CampaignCertificate(r.record,tuple(replace(r.votes[0],signature_hex='00'*64) for _ in (0,))+r.votes[1:])
        self.assertFalse(verify_certificate(tampered,self.policy))
        fork=CampaignRecord(self.policy.commitment,1,GENESIS_DIGEST,'reserve',
               {**r.record.payload,'challenge':'some-other-valid-challenge'})
        with self.assertRaises(CampaignError):self.replicas[0].vote(fork)
        with self.assertRaises(CampaignError):
            self.quorum.commit('reserve',{**r.record.payload,'challenge':'some-other-valid-challenge'})

    def test_reconstructed_policy_and_signed_events(self):
        self.assertEqual(unpack_policy(self.policy.canonical()),self.policy)
        r=self.quorum.reserve(challenge='roundtrip-abcdefg-2026',protocol='0'*64,
            witness_policy='0'*64,cluster_plan='0'*64,v2_policy='0'*64,
            action='0'*64,alpha_units=55)
        back=unpack_certificate(r.canonical())
        self.assertEqual(back.record.digest,r.record.digest)
        self.assertTrue(verify_certificate(back,self.policy))
        changed=deepcopy(self.policy.canonical());changed['total_units']=10
        self.assertNotEqual(unpack_policy(changed).commitment,self.policy.commitment)

    def test_signed_reservation_cannot_be_replayed_for_different_certificate(self):
        bundle,pins,r,f=attempt(self.quorum)
        other=deepcopy(bundle);other['v2_certificate']['claimed_decision_v2']['authorized']=False
        with self.assertRaises(InvalidCertificate):
            verify_attempt(other,policy=self.policy,
                expected_reservation_digest=r.record.digest,
                expected_finalization_digest=f.record.digest,
                expected_previous_digest=GENESIS_DIGEST,expected_previous_spent_units=0,
                expected_v2_epoch=0,expected_v2_previous_digest=GENESIS_DIGEST)


if __name__=='__main__':unittest.main()
