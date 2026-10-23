"""Small exhaustive reference-model checks of alpha ledger transition rules."""
import itertools
import unittest

from campaign import (CampaignState, CampaignRecord, CampaignError,
                      CampaignPolicy, transition, GENESIS_DIGEST, SCALE)
from anchor import AnchorIdentity
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witnessed import _key_hex


def policy(cap=4):
    keys=[Ed25519PrivateKey.from_private_bytes(bytes([i+1])*32) for i in range(4)]
    return CampaignPolicy('model-check-campaign-2026',cap,
                          tuple(AnchorIdentity(f'p{i}',_key_hex(k)) for i,k in enumerate(keys)),1,3)


class AccountingStateMachineTests(unittest.TestCase):
    def test_every_short_transition_trace(self):
        p=policy(4)
        frontier=[(CampaignState(),0,GENESIS_DIGEST,[])]
        visited=0
        for depth in range(7):
            nxt=[]
            for state,sequence,prev,trace in frontier:
                visited+=1
                self.assertGreaterEqual(state.spent,0)
                self.assertLessEqual(state.spent,p.total_units)
                self.assertEqual(state.spent,sum(e.payload['alpha_units'] for e in trace if e.kind=='reserve'))
                self.assertEqual(len(state.seen),len([e for e in trace if e.kind=='reserve']))
                choices=[]
                for a in (1,2,3,4,5):
                    for name in ('abcdefghij-000000','abcdefghij-111111'):
                        choices.append(('reserve',dict(challenge=name,protocol='0'*64,
                            witness_policy='0'*64,cluster_plan='0'*64,v2_policy='0'*64,
                            action='0'*64,alpha_units=a,spent_units=state.spent+a)))
                if state.reservation:
                    for authorized in (True,False):
                        choices.append(('finalize',{'reservation_digest':state.reservation.digest,
                            'certificate_digest':'f'*64,'authorized':authorized}))
                if state.finalization:
                    choices.append(('consume',{'finalization_digest':state.finalization.digest}))
                for kind,body in choices:
                    rec=CampaignRecord(p.commitment,sequence+1,prev,kind,body)
                    try:
                        new=transition(state,rec,p)
                    except CampaignError:
                        continue
                    self.assertGreaterEqual(new.spent,state.spent)
                    self.assertLessEqual(new.spent,p.total_units)
                    if kind=='reserve':self.assertEqual(new.spent,state.spent+body['alpha_units'])
                    else:self.assertEqual(new.spent,state.spent)
                    nxt.append((new,sequence+1,rec.digest,trace+[rec]))
            frontier=nxt
            # The research test enumerates traces of length <=6 with 2 challenges and
            # cap 4. It never relies on pseudorandom coverage.
        self.assertGreater(visited,100)

    def test_quorum_intersections_exhaustive_small_n(self):
        for n in range(2,8):
            for f in range(n):
                for q in range(1,n+1):
                    if 2*q<=n+f:continue
                    masks=[set(x) for x in itertools.combinations(range(n),q)]
                    for a in masks:
                        for b in masks:
                            self.assertGreater(len(a&b),f)

    def test_exact_integer_failures(self):
        p=policy()
        body=dict(challenge='abcdefghij-000000',protocol='0'*64,witness_policy='0'*64,
                  cluster_plan='0'*64,v2_policy='0'*64,action='0'*64,
                  alpha_units=1,spent_units=1)
        for bad in (0,-1,True,1.0,SCALE):
            with self.subTest(value=bad),self.assertRaises(CampaignError):
                CampaignRecord(p.commitment,1,GENESIS_DIGEST,'reserve',{**body,'alpha_units':bad})
        with self.assertRaises(CampaignError):
            CampaignRecord(p.commitment,1,GENESIS_DIGEST,'reserve',{**body,'spent_units':True})
        with self.assertRaises(CampaignError):
            CampaignPolicy('short',5,p.replicas,1,3)

if __name__=='__main__':unittest.main()
