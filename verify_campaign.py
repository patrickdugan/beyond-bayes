"""Independent CLI to verify an externally pinned synthetic ACE v0.8 attempt.

An offline certificate can authenticate past votes, while a *live* relying
party must check quorum freshness and call CampaignActionGate before actuation.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from campaign import (CampaignError, unpack_policy, unpack_certificate,verify_certificate)
from campaign_certificate import verify_attempt
from certificates import InvalidCertificate


def _unique_pairs(pairs):
    out={}
    for key,value in pairs:
        if key in out:raise ValueError('duplicate JSON key: '+key)
        out[key]=value
    return out


def _invalid_constant(value):
    raise ValueError('nonfinite JSON constant: '+value)


def load_json(path:Path) -> dict:
    if path.stat().st_size>2_000_000:raise ValueError('JSON exceeds 2MB verifier limit')
    return json.loads(path.read_text(),object_pairs_hook=_unique_pairs,
                      parse_constant=_invalid_constant)


def replay(bundle:dict,pins:dict) -> dict:
    if type(bundle) is not dict or set(bundle)!={'schema','campaign_policy','attempt','consumption'} or bundle['schema']!='ACE-campaign-demo-v1':
        raise InvalidCertificate('malformed demo certificate wrapper')
    if type(pins) is not dict or set(pins)!={'campaign_policy','campaign_commitment','reservation_digest','finalization_digest',
        'consumption_digest','previous_campaign_digest','previous_spent_units',
        'v2_epoch','v2_previous_digest'}:
        raise InvalidCertificate('expected trust anchor set is incomplete')
    policy=unpack_policy(pins['campaign_policy'])
    if (policy.commitment!=pins['campaign_commitment'] or
        policy.canonical()!=bundle['campaign_policy']):
        raise InvalidCertificate('untrusted campaign policy substitution')
    check=verify_attempt(bundle['attempt'],policy=policy,
        expected_reservation_digest=pins['reservation_digest'],
        expected_finalization_digest=pins['finalization_digest'],
        expected_previous_digest=pins['previous_campaign_digest'],
        expected_previous_spent_units=pins['previous_spent_units'],
        expected_v2_epoch=pins['v2_epoch'],
        expected_v2_previous_digest=pins['v2_previous_digest'])
    consumption=unpack_certificate(bundle['consumption'])
    if (not check.authorized or not verify_certificate(consumption,policy) or
        consumption.record.kind!='consume' or
        consumption.record.sequence!=bundle['attempt']['finalization']['record']['sequence']+1 or
        consumption.record.previous_digest!=check.finalization_digest or
        consumption.record.payload['finalization_digest']!=check.finalization_digest or
        consumption.record.digest!=pins['consumption_digest']):
        raise InvalidCertificate('invalid one-shot consumption attestation')
    return {'authorized':True,'campaign_commitment':check.campaign_commitment,
            'reserved_alpha':check.risk_units/10**12,
            'total_alpha_spent':check.spent_units/10**12,
            'reservation_digest':check.reservation_digest,
            'finalization_digest':check.finalization_digest,
            'consumption_digest':consumption.record.digest}


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('bundle',type=Path)
    ap.add_argument('--pins',type=Path,required=True)
    args=ap.parse_args()
    try:
        print(json.dumps(replay(load_json(args.bundle),load_json(args.pins)),sort_keys=True))
    except (InvalidCertificate,CampaignError,ValueError,KeyError,TypeError) as exc:
        print(f'campaign certificate rejected: {exc}',file=sys.stderr)
        raise SystemExit(1)

if __name__=='__main__':main()
