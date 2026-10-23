"""Offline verification of one quorum-signed ACE witness-state anchor.

A certificate authenticates a *record*, not its freshness. Operational callers
must also perform a quorum read against independently pinned replica keys.
"""
from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from dataclasses import fields
from pathlib import Path

from anchor import (AnchorCertificate, AnchorIdentity, AnchorPolicy,
                    AnchorRecord, AnchorVote, verify_anchor_certificate)


class InvalidAnchorBundle(ValueError):
    pass


def _exact(raw, expected: set[str], label: str):
    if not isinstance(raw,dict) or set(raw) != expected:
        raise InvalidAnchorBundle(f'malformed {label}')


def unpack_anchor_policy(raw: dict) -> AnchorPolicy:
    _exact(raw,{'domain','witness_id','witness_public_key_hex',
                'witness_policy_commitment','protocol_commitment',
                'replicas','max_faulty','quorum'},'anchor policy')
    if raw['domain']!='ACE:anchor-policy:v1' or not isinstance(raw['replicas'],list):
        raise InvalidAnchorBundle('unrecognized anchor policy')
    identities=[]
    for record in raw['replicas']:
        _exact(record,{'replica_id','public_key_hex'},'anchor identity')
        identities.append(AnchorIdentity(**record))
    return AnchorPolicy(raw['witness_id'],raw['witness_public_key_hex'],
                        raw['witness_policy_commitment'],raw['protocol_commitment'],
                        tuple(identities),raw['max_faulty'],raw['quorum'])


def unpack_anchor_certificate(raw: dict) -> AnchorCertificate:
    _exact(raw,{'record','state_hex','state_signature_hex','votes'},'anchor certificate')
    record=raw['record']
    _exact(record,{'domain','policy_commitment','witness_id','sequence',
                   'previous_digest','state_digest'},'anchor record')
    if record['domain'] != 'ACE:anchor-record:v1' or not isinstance(raw['votes'],list):
        raise InvalidAnchorBundle('unrecognized anchor record')
    votes=[]
    for vote in raw['votes']:
        _exact(vote,{'replica_id','record_digest','signature_hex'},'anchor vote')
        votes.append(AnchorVote(**vote))
    try:
        return AnchorCertificate(
            AnchorRecord(record['policy_commitment'],record['witness_id'],
                         record['sequence'],record['previous_digest'],record['state_digest']),
            bytes.fromhex(raw['state_hex']), bytes.fromhex(raw['state_signature_hex']),
            tuple(votes))
    except (TypeError,ValueError) as e:
        raise InvalidAnchorBundle('invalid encoded anchor contents') from e


def verify_anchor_bundle(bundle: Mapping, *, expected_policy: str,
                         expected_witness_id: str, expected_sequence: int,
                         expected_previous_digest: str) -> AnchorCertificate:
    _exact(bundle,{'schema','anchor_policy','certificate'},'anchor bundle')
    if bundle['schema']!='ACE-anchor-bundle-v1':
        raise InvalidAnchorBundle('unknown anchor bundle version')
    try:
        policy=unpack_anchor_policy(bundle['anchor_policy'])
        cert=unpack_anchor_certificate(bundle['certificate'])
        if (policy.commitment!=expected_policy or policy.witness_id!=expected_witness_id
            or type(expected_sequence) is not int or cert.record.sequence!=expected_sequence
            or cert.record.previous_digest!=expected_previous_digest):
            raise InvalidAnchorBundle('externally pinned anchor mismatch')
        if not verify_anchor_certificate(cert,policy):
            raise InvalidAnchorBundle('invalid quorum certificate')
        return cert
    except (TypeError,KeyError,AttributeError,ValueError) as e:
        if isinstance(e,InvalidAnchorBundle):
            raise
        raise InvalidAnchorBundle('malformed anchor bundle') from e


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle',type=Path)
    parser.add_argument('--expected-policy',required=True)
    parser.add_argument('--expected-witness-id',required=True)
    parser.add_argument('--expected-sequence',required=True,type=int)
    parser.add_argument('--expected-previous-digest',required=True)
    args=parser.parse_args()
    try:
        bundle=json.loads(args.bundle.read_text())
        verified=verify_anchor_bundle(bundle,expected_policy=args.expected_policy,
             expected_witness_id=args.expected_witness_id,
             expected_sequence=args.expected_sequence,
             expected_previous_digest=args.expected_previous_digest)
    except (InvalidAnchorBundle,OSError,json.JSONDecodeError) as e:
        parser.exit(1,f'REJECTED: {e}\n')
    print('VERIFIED:',verified.record.digest)
    print('The certificate is authentic under the pinned policy; current freshness '
          'requires an independent quorum read.')


if __name__=='__main__':
    main()
