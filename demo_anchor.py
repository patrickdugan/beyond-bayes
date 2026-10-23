"""Deterministic research-only anchor certificate for independent replay."""
from __future__ import annotations

import argparse
from pathlib import Path
import json
import tempfile

from anchor import AnchorIdentity, AnchorPolicy, AnchorQuorum, AnchorReplica
from anchored_witness import AnchoredWitness
from test_provenance import seed_key, pub
from test_witnessed import bit_reports, setup
from witnessed import GENESIS_DIGEST


def make_demo():
    protocol,keys,policy,logkey,wkeys,_,_=setup()
    anchor_keys=[seed_key('ACE-v05-anchor-'+str(i)) for i in range(4)]
    anchor_policy=AnchorPolicy('notary-0',pub(wkeys[0]),policy.commitment,
        protocol.commitment,tuple(AnchorIdentity('anchor-'+str(i),pub(k))
        for i,k in enumerate(anchor_keys)),1,3)
    with tempfile.TemporaryDirectory() as folder:
        base=Path(folder)
        replicas=[AnchorReplica(anchor_policy,'anchor-'+str(i),k,
                                 base/('anchor-'+str(i)+'.db'))
                  for i,k in enumerate(anchor_keys)]
        quorum=AnchorQuorum(anchor_policy,replicas)
        witness=AnchoredWitness(policy,protocol,'notary-0',wkeys[0],
                                base/'witness.db',quorum)
        witness.receive(bit_reports(protocol,keys,[0])[0])
        cert=quorum.current()
        return {'schema':'ACE-anchor-bundle-v1',
                'anchor_policy':anchor_policy.canonical(),
                'certificate':cert.canonical()}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=Path('/tmp/ace-anchor.json'))
    args=parser.parse_args()
    bundle=make_demo()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(bundle,indent=2,sort_keys=True)+'\n')
    r=bundle['certificate']['record']
    print('TEST ONLY, NEVER DEPLOY THESE KEYS')
    print('output:',args.output)
    print('expected policy:',bundle['certificate']['record']['policy_commitment'])
    print('expected witness id:',r['witness_id'])
    print('expected sequence:',r['sequence'])
    print('expected predecessor:',r['previous_digest'])


if __name__=='__main__':
    main()
