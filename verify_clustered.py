"""Fail-closed offline verification of ACE v0.7 certificate JSON."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from certificates import InvalidCertificate
from clustered_certificate import verify_clustered_certificate
from clustered_action_gate import ClusteredActionGate


def _reject_duplicate_keys(pairs):
    d={}
    for k,v in pairs:
        if k in d:
            raise InvalidCertificate('duplicate JSON object key: '+k)
        d[k]=v
    return d


def main() -> int:
    p=argparse.ArgumentParser(description='Verify witnessed, clustered ACE v2 authorization')
    p.add_argument('certificate',type=Path)
    for name in ('protocol','policy','cluster-plan','v2-policy','action','challenge',
                 'previous-digest'):
        p.add_argument('--expected-'+name,required=True)
    p.add_argument('--expected-epoch',type=int,required=True)
    p.add_argument('--consume-db',type=Path,default=None)
    a=p.parse_args()
    args={'expected_protocol':a.expected_protocol,'expected_policy':a.expected_policy,
          'expected_cluster_plan':a.expected_cluster_plan,
          'expected_v2_policy':a.expected_v2_policy,'expected_action':a.expected_action,
          'expected_challenge':a.expected_challenge}
    try:
        cert=json.loads(a.certificate.read_text(encoding='utf-8'),
                        object_pairs_hook=_reject_duplicate_keys,
                        parse_constant=lambda v: (_ for _ in ()).throw(InvalidCertificate('non-finite JSON')))
        verified=verify_clustered_certificate(cert,**args,expected_epoch=a.expected_epoch,
                           expected_previous_digest=a.expected_previous_digest)
        if a.consume_db is not None:
            gate=ClusteredActionGate(a.consume_db)
            committed=gate.verify_and_consume(cert,**args)
            if committed != verified:
                raise InvalidCertificate('transactional verification disagrees with offline pins')
        print(json.dumps({'schema':'ACE-verified-clustered-v2',
                          'authorized':verified.authorized,
                          'checkpoint_digest':verified.checkpoint_digest,
                          'epoch':verified.epoch,'log_entries':verified.log_entries,
                          'admitted_clusters':verified.admitted_clusters,
                          'missing_clusters':verified.missing_clusters,
                          'v2_policy':verified.authorization_policy_commitment,
                          'action':verified.action_commitment},indent=2))
        return 0 if verified.authorized else 2
    except (InvalidCertificate,ValueError,OSError) as e:
        print('REJECTED:',e,file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
