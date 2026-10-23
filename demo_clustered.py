"""Deterministic synthetic v2 certificate and externally pinned fixture.

Only TEST keys (taken from the existing unit-test fixture) are used.
"""
import argparse
import json
from pathlib import Path
from clustered_certificate import (ActionIntent,AuthorizationPolicyV2,export_clustered_certificate)
from clustered import Cluster, ClusterPlan
from conditional import ConditionalNull
from provenance import SignedObservation
from test_witnessed import setup
from witnessed import GENESIS_DIGEST


def generate() -> tuple[dict,dict]:
    p,keys,policy,logkey,wkeys,ws,log=setup(n=12)
    plan=ClusterPlan(p,tuple(Cluster(f'cluster-{i//2}',
            (p.slots[i].slot_id,p.slots[i+1].slot_id)) for i in range(0,12,2)),
            ConditionalNull.iid(.8,.2),corruption_budget_clusters=0)
    action=ActionIntent(p.challenge,'release-fixture','synthetic-wallet',
                        {'chain':'regtest','units':1})
    for i,slot in enumerate(p.slots):
        report=SignedObservation.issue(p,slot.slot_id,0,keys[i])
        log.append(report)
        for w in ws[:3]:w.receive(report)
    signed,proof=log.seal()
    endorsements=[w.endorse(signed,log.entries) for w in ws[:3]]
    bundle=export_clustered_certificate(log,signed,endorsements,proof,
                                         plan=plan,action=action)
    auth=AuthorizationPolicyV2(p.commitment,policy.commitment,
                                plan.commitment,action.commitment)
    pins=dict(expected_protocol=p.commitment,expected_policy=policy.commitment,
              expected_cluster_plan=plan.commitment,expected_v2_policy=auth.commitment,
              expected_action=action.commitment,expected_challenge=p.challenge,
              expected_epoch=0,expected_previous_digest=GENESIS_DIGEST)
    return bundle,pins


def main() -> None:
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--pins',type=Path,required=True)
    a=parser.parse_args()
    cert,pins=generate()
    a.output.write_text(json.dumps(cert,indent=2,sort_keys=True,allow_nan=False)+'\n')
    a.pins.write_text(json.dumps(pins,indent=2,sort_keys=True,allow_nan=False)+'\n')
    print(json.dumps({'certificate':str(a.output),'pins':str(a.pins),
                      'authorization':cert['claimed_decision_v2']['authorized']}))

if __name__=='__main__':main()
