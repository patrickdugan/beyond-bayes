"""Deterministic, synthetic signed parent grant vectors (PUBLIC TEST KEYS ONLY)."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import tempfile
from test_scope import identity_fixture, child_fixture


def generate():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        scope, _keys, _replicas, quorum = identity_fixture(root)
        nonce = 'ACE-v09-first-child-2026'
        from scope import child_id
        child, _, _, _ = child_fixture(root, scope, nonce=nonce, units=10_000_000_000)
        grant = quorum.allocate(child, nonce)
        view = quorum.current()
        bundle = {'schema': 'ACE-root-grant-demo-v1',
                  'scope_history': [cert.canonical() for cert in view.history],
                  'child_policy': child.canonical()}
        pins = {'scope_policy': scope.canonical(), 'scope_commitment': scope.commitment,
                'trusted_head': view.head, 'child_commitment': child.commitment,
                'grant_digest': grant.grant.digest,
                'principal_id': scope.principal_id, 'resource_id': scope.resource_id}
        return bundle, pins


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--pins', type=Path, required=True)
    a = p.parse_args()
    bundle, pins = generate()
    a.output.write_text(json.dumps(bundle, indent=2, sort_keys=True, allow_nan=False)+'\n')
    a.pins.write_text(json.dumps(pins, indent=2, sort_keys=True, allow_nan=False)+'\n')
    print(json.dumps({'bundle': str(a.output), 'pins': str(a.pins),
                      'scope_commitment': pins['scope_commitment'],
                      'scope_head': pins['trusted_head']}))

if __name__ == '__main__':
    main()
