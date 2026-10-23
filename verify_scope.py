"""Offline audit of a quorum-certified parent risk-scope allocation history.

This is a historical verification tool. Live action execution must read a live
quorum via ScopeActionGate, and the signed parent head must be externally pinned.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from scope import (ScopeError, unpack_policy, unpack_certificate,
                   verify_history, check_child_policy)
from campaign import unpack_policy as unpack_child_policy


def _duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ScopeError('duplicate JSON key in scope certificate')
        result[key] = value
    return result


def replay(bundle: object, pins: object) -> dict:
    if type(bundle) is not dict or set(bundle) != {'schema', 'scope_history', 'child_policy'} or \
            bundle.get('schema') != 'ACE-root-grant-demo-v1' or \
            type(bundle['scope_history']) is not list:
        raise ScopeError('malformed scope certificate bundle')
    fields = {'scope_policy', 'scope_commitment', 'trusted_head', 'child_commitment',
              'grant_digest', 'principal_id', 'resource_id'}
    if type(pins) is not dict or set(pins) != fields:
        raise ScopeError('missing externally required scope pins')
    root = unpack_policy(pins['scope_policy'])
    if (root.commitment != pins['scope_commitment'] or
        root.principal_id != pins['principal_id'] or root.resource_id != pins['resource_id']):
        raise ScopeError('scope differs from pinned principal/resource')
    child = unpack_child_policy(bundle['child_policy'])
    if child.commitment != pins['child_commitment']:
        raise ScopeError('unexpected child campaign policy')
    history = tuple(unpack_certificate(x) for x in bundle['scope_history'])
    if len(history) == 0:
        raise ScopeError('missing root grant')
    state = verify_history(history, root, expected_head=pins['trusted_head'])
    found = [cert for cert in history if cert.grant.digest == pins['grant_digest']]
    if len(found) != 1:
        raise ScopeError('required grant missing or duplicated')
    grant = found[0].grant
    check_child_policy(root, grant, child)
    return {'valid_grant': True, 'scope_commitment': root.commitment,
            'principal_id': root.principal_id, 'resource_id': root.resource_id,
            'child_campaign': child.campaign_id, 'child_budget_units': child.total_units,
            'allocated_units': state.allocated,
            'scope_head': pins['trusted_head'], 'grant_digest': grant.digest}


def main():
    parser = argparse.ArgumentParser(description='Replay a signed root-scope grant history')
    parser.add_argument('bundle', type=Path)
    parser.add_argument('--pins', type=Path, required=True)
    args = parser.parse_args()
    try:
        b = json.loads(args.bundle.read_text(), object_pairs_hook=_duplicates,
                       parse_constant=lambda s: (_ for _ in ()).throw(ScopeError('non-finite JSON value')))
        p = json.loads(args.pins.read_text(), object_pairs_hook=_duplicates,
                       parse_constant=lambda s: (_ for _ in ()).throw(ScopeError('non-finite JSON value')))
        result = replay(b, p)
    except (ScopeError, ValueError, TypeError, KeyError, OSError) as exc:
        parser.exit(1, str(exc)+'\n')
    print(json.dumps(result, sort_keys=True, indent=2))

if __name__ == '__main__':
    main()
