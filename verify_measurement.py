"""ACE v0.10 independent offline replay of witnessed acquisition ordering.

The signed envelope order is verifiable. Actual physical sampling time requires
honest device acquisition logic and protection against prestart data access.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from certificates import InvalidCertificate
from campaign import unpack_policy as unpack_campaign_policy,unpack_certificate as unpack_campaign_certificate,verify_certificate as verify_campaign_certificate
from clustered_certificate import verify_clustered_certificate
from measurement_start import (StartError,unpack_certificate as unpack_start_certificate,
                               unpack_observation,verify_history as verify_start_history,
                               verify_observations)
from provenance import _digest
from root_registry import (RegistryError,unpack_policy as unpack_registry_policy,
                           unpack_certificate as unpack_registry_certificate,
                           verify_history as verify_registry_history)
from scope import (ScopeError,unpack_policy as unpack_scope_policy,
                   unpack_certificate as unpack_scope_certificate,
                   verify_history as verify_scope_history, check_child_policy)
from witnessed import unpack_protocol,report_digest
from witnessed import _typed_report

SCHEMA='ACE-measurement-audit-v1'
PIN_FIELDS={'registry_commitment','registry_head','scope_commitment','scope_head',
            'campaign_commitment','reservation_digest','start_head','v2_policy',
            'action','expected_v2_epoch','expected_v2_previous_digest'}
BUNDLE_FIELDS={'schema','registry_policy','registry_history','scope_policy',
               'scope_history','campaign_policy','reservation_certificate',
               'start_history','instrument_measurements','v2_certificate'}


def replay(bundle,pins):
    if (type(bundle) is not dict or set(bundle)!=BUNDLE_FIELDS or bundle.get('schema')!=SCHEMA or
        type(pins) is not dict or set(pins)!=PIN_FIELDS):
        raise StartError('missing or altered independently pinned timing policy')
    if any(type(bundle[x]) is not list for x in ('registry_history','scope_history','start_history','instrument_measurements')):
        raise StartError('malformed signed history or measurement collection')
    registry=unpack_registry_policy(bundle['registry_policy'])
    if registry.commitment!=pins['registry_commitment']:raise StartError('registry identity changed')
    roots=tuple(unpack_registry_certificate(x) for x in bundle['registry_history'])
    current=verify_registry_history(roots,registry,pins['registry_head'])
    scope=unpack_scope_policy(bundle['scope_policy'])
    if scope.commitment!=pins['scope_commitment']:raise StartError('changed parent root policy')
    active=current.active.get((scope.principal_id,scope.resource_id))
    if active is None or active.scope.commitment!=scope.commitment:
        raise StartError('root scope not globally active at pinned registry head')
    root_history=tuple(unpack_scope_certificate(x) for x in bundle['scope_history'])
    verify_scope_history(root_history,scope,expected_head=pins['scope_head'])
    campaign=unpack_campaign_policy(bundle['campaign_policy'])
    if campaign.commitment!=pins['campaign_commitment']:raise StartError('changed child campaign')
    matches=[x.grant for x in root_history if x.grant.child_policy==campaign.commitment]
    if len(matches)!=1:raise StartError('unique signed child grant missing')
    check_child_policy(scope,matches[0],campaign)
    reservation=unpack_campaign_certificate(bundle['reservation_certificate'])
    if (not verify_campaign_certificate(reservation,campaign) or
        reservation.record.digest!=pins['reservation_digest'] or
        reservation.record.kind!='reserve'):
        raise StartError('missing or changed signed reservation')
    starts=tuple(unpack_start_certificate(x) for x in bundle['start_history'])
    verify_start_history(starts,registry,pins['start_head'])
    if not starts:raise StartError('missing attested start')
    receipt=starts[-1]
    b=receipt.record.binding
    r=reservation.record
    if (b.registry!=registry.commitment or b.registry_head!=pins['registry_head'] or
        b.scope!=scope.commitment or b.scope_head!=pins['scope_head'] or
        b.root_grant!=matches[0].digest or b.campaign!=campaign.commitment or
        b.reservation!=r.digest or b.protocol!=r.payload['protocol'] or
        b.witness_policy!=r.payload['witness_policy'] or
        b.cluster_plan!=r.payload['cluster_plan'] or b.v2_policy!=r.payload['v2_policy'] or
        b.action!=r.payload['action'] or b.v2_policy!=pins['v2_policy'] or
        b.action!=pins['action']):
        raise StartError('start receipt differs from precommitted budget or evidence policies')
    v2=bundle['v2_certificate']
    witnessed=v2['witnessed_log_v1']
    protocol=unpack_protocol(witnessed['protocol'])
    result=verify_clustered_certificate(v2,expected_protocol=b.protocol,
            expected_policy=b.witness_policy,expected_cluster_plan=b.cluster_plan,
            expected_v2_policy=b.v2_policy,expected_action=b.action,
            expected_challenge=r.payload['challenge'],
            expected_epoch=pins['expected_v2_epoch'],
            expected_previous_digest=pins['expected_v2_previous_digest'])
    measurements=tuple(unpack_observation(o) for o in bundle['instrument_measurements'])
    attested=verify_observations(receipt,measurements,protocol,registry)
    original=tuple(_typed_report(o) for o in witnessed['complete_log'])
    if attested!=original:raise StartError('signed instrument reports differ from complete witnessed log')
    if result.log_entries!=len(attested):raise StartError('log sample count differs from instrument')
    return {'verified':True,'authorized':result.authorized,
            'registry_head':pins['registry_head'],
            'start_digest':receipt.record.digest,'start_head':pins['start_head'],
            'samples':len(attested),'device_epoch':b.epoch,
            'instrument_id':b.instrument_id,'campaign_commitment':campaign.commitment,
            'scope_commitment':scope.commitment,'action_commitment':b.action}


def _duplicate_pairs(pairs):
    out={}
    for key,value in pairs:
        if key in out:raise StartError('duplicate JSON key')
        out[key]=value
    return out


def _load(path):
    return json.loads(Path(path).read_text(),object_pairs_hook=_duplicate_pairs,
         parse_constant=lambda v:(_ for _ in ()).throw(StartError('non-finite JSON value')))


def main():
    ap=argparse.ArgumentParser(description='Replay a pinned, quorum-witnessed instrument start and signed sample log')
    ap.add_argument('bundle');ap.add_argument('--pins',required=True)
    args=ap.parse_args()
    try:
        result=replay(_load(args.bundle),_load(args.pins))
    except (StartError,RegistryError,ScopeError,InvalidCertificate,ValueError,TypeError,KeyError,OverflowError,OSError) as exc:
        ap.exit(1,str(exc)+'\n')
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=='__main__':main()
