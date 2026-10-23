"""v0.6 signed clusters: source duplication, missing, forgery and correlation."""
from __future__ import annotations

import hashlib
import math
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from clustered import Cluster, ClusterPlan, ClusteredEvidenceGate
from conditional import ConditionalNull
from provenance import Protocol, Receipt, SignedObservation, Slot


def fixture(*, n:int=24, size:int=4, null=None, k:int=0):
    assert n%size==0
    keys=[];slots=[]
    for i in range(n):
        key=Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f'v06-test-{i}'.encode()).digest())
        keys.append(key)
        pub=key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw).hex()
        slots.append(Slot(f'slot-{i:02}',f'source-{i:02}',f'uncertified-domain-{i:02}',pub))
    protocol=Protocol('cluster-v06-experiment','fixed-16-byte-challenge',tuple(slots),
                      .8,.2,.05,0)
    clusters=tuple(Cluster(f'cluster-{j}',tuple(f'slot-{i:02}' for i in range(j*size,(j+1)*size)))
                   for j in range(n//size))
    model=null or ConditionalNull.iid(.8,.2)
    plan=ClusterPlan(protocol,clusters,model,k,.05)
    gate=ClusteredEvidenceGate(plan,expected_plan_commitment=plan.commitment,
                               expected_protocol_commitment=protocol.commitment)
    return plan,gate,keys


def fill(gate, keys, cluster_bits, *, skip=frozenset()):
    plan=gate.plan
    for j,cluster in enumerate(plan.clusters):
        for slot_id in cluster.slot_ids:
            i=next(i for i,x in enumerate(plan.protocol.slots) if x.slot_id==slot_id)
            if i in skip:continue
            gate.offer(SignedObservation.issue(plan.protocol,slot_id,cluster_bits[j],keys[i]))


class ClusterTests(unittest.TestCase):
    def test_exact_cover_rejects_missing_slots(self):
        p,_,_=fixture()
        with self.assertRaises(ValueError):
            ClusterPlan(p.protocol,p.clusters[:-1],p.null,0)

    def test_double_enrollment_rejected(self):
        p,_,_=fixture()
        with self.assertRaises(ValueError):
            ClusterPlan(p.protocol,p.clusters+(p.clusters[0],),p.null,0)

    def test_cluster_swap_changes_plan_digest(self):
        p,_,_=fixture()
        altered=ClusterPlan(p.protocol,p.clusters[::-1],p.null,0)
        self.assertNotEqual(p.commitment,altered.commitment)

    def test_null_swap_changes_plan_digest(self):
        p,_,_=fixture()
        altered=ClusterPlan(p.protocol,p.clusters,
                            ConditionalNull.iid(.7,.2),0)
        self.assertNotEqual(p.commitment,altered.commitment)

    def test_policy_pin_required(self):
        p,_,_=fixture()
        with self.assertRaises(ValueError):
            ClusteredEvidenceGate(p,expected_plan_commitment='bogus',
                                  expected_protocol_commitment=p.protocol.commitment)
        with self.assertRaises(ValueError):
            ClusteredEvidenceGate(p,expected_plan_commitment=p.commitment,
                                  expected_protocol_commitment='bogus')

    def test_one_physical_latent_mapped_once(self):
        p,g,keys=fixture(size=24)
        fill(g,keys,[0])
        self.assertEqual(g.decide().admitted_clusters,1)
        self.assertFalse(g.decide().authorized)
        self.assertAlmostEqual(g.decide().robust_max_log_e,math.log(4))

    def test_naive_falsifier_when_one_latent_misassigned_to_24_clusters(self):
        p,g,keys=fixture(size=1)
        fill(g,keys,[0]*24)
        self.assertTrue(g.decide().authorized)
        # This invalid application of iid inference has 20% false opens under
        # a single shared Bernoulli(.8) latent observation, not 5%.

    def test_incomplete_cluster_is_erasure(self):
        p,g,keys=fixture(n=4,size=4)
        fill(g,keys,[0],skip={3})
        self.assertEqual(g.decide().cluster_bits,(None,))
        self.assertFalse(g.decide().authorized)

    def test_conflicting_authentic_sensors_fail_closed(self):
        p,g,keys=fixture(n=4,size=4)
        fill(g,keys,[0])
        report=SignedObservation.issue(p.protocol,'slot-03',1,keys[3])
        self.assertEqual(g.offer(report),Receipt.EQUIVOCATION)
        self.assertFalse(g.decide().authorized)
        self.assertEqual(g.decide().equivocated_slots,('slot-03',))

    def test_disagreement_between_distinct_keys_fails_closed(self):
        p,g,keys=fixture(n=4,size=4)
        for i,bit in enumerate([0,1,0,0]):
            self.assertEqual(g.offer(SignedObservation.issue(p.protocol,f'slot-{i:02}',bit,keys[i])),
                             Receipt.ACCEPTED)
        self.assertFalse(g.decide().authorized)
        self.assertEqual(g.decide().conflicting_clusters,('cluster-0',))

    def test_partial_cluster_with_conflicting_signatures_still_blocks(self):
        p,g,keys=fixture(n=4,size=4)
        for i,bit in enumerate([0,1,0]):
            report=SignedObservation.issue(p.protocol,f'slot-{i:02}',bit,keys[i])
            self.assertEqual(g.offer(report),Receipt.ACCEPTED)
        dec=g.decide()
        self.assertEqual(dec.cluster_bits,(None,))
        self.assertEqual(dec.conflicting_clusters,('cluster-0',))
        self.assertFalse(dec.authorized)

    def test_corruption_budget_changes_commitment(self):
        p,_,_=fixture()
        q=ClusterPlan(p.protocol,p.clusters,p.null,1)
        self.assertNotEqual(p.commitment,q.commitment)

    def test_corrupt_signed_member_does_not_mint_extra_cluster(self):
        p,g,keys=fixture(n=8,size=4)
        fill(g,keys,[0,0])
        for _ in range(5):
            r=SignedObservation.issue(p.protocol,'slot-00',0,keys[0])
            self.assertEqual(g.offer(r),Receipt.DUPLICATE)
        self.assertEqual(g.decide().admitted_clusters,2)

    def test_forged_roster_id_quarantined(self):
        p,g,keys=fixture(n=4,size=4)
        bogus=SignedObservation.issue(p.protocol,'slot-forged',0,keys[0])
        self.assertEqual(g.offer(bogus),Receipt.QUARANTINED)
        self.assertEqual(g.decide().quarantined_reports,1)
        self.assertEqual(g.decide().missing_clusters,1)

    def test_copying_report_cannot_increase_sample_count(self):
        p,g,keys=fixture(n=4,size=4)
        report=SignedObservation.issue(p.protocol,'slot-00',0,keys[0])
        self.assertEqual(g.offer(report),Receipt.ACCEPTED)
        for _ in range(50):
            self.assertEqual(g.offer(report),Receipt.DUPLICATE)
        self.assertEqual(g.decide().admitted_clusters,0)

    def test_cluster_corruption_one_budget_prevents_early_false_open(self):
        p,g,keys=fixture(n=12,size=4,k=1)
        fill(g,keys,[0]*3)
        self.assertFalse(g.decide().authorized)
        self.assertLess(g.decide().robust_max_log_e, math.log(20))

    def test_full_roster_can_authorize_clear_evidence(self):
        p,g,keys=fixture(n=24,size=1)
        fill(g,keys,[0]*24)
        self.assertTrue(g.decide().authorized)
        self.assertEqual(g.decide().admitted_clusters,24)

    def test_signed_report_from_wrong_experiment_quarantined(self):
        p,g,keys=fixture(n=4,size=4)
        wrong=SignedObservation('other',p.protocol.commitment,'slot-00',0,'00')
        self.assertEqual(g.offer(wrong),Receipt.QUARANTINED)
        self.assertFalse(g.decide().authorized)

    def test_markov_cluster_dependencies_are_scored(self):
        null=ConditionalNull.markov(initial=(.7,.85),after_zero=(.6,.75),after_one=(.8,.95),bet_q=.2)
        p,g,keys=fixture(n=24,size=4,null=null)
        fill(g,keys,[0]*6)
        self.assertEqual(g.decide().admitted_clusters,6)
        self.assertTrue(g.decide().authorized)


if __name__=='__main__':
    unittest.main()
