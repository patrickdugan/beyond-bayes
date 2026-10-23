"""Replay witnessed ACE JSON with explicit externally pinned trust anchors."""
import argparse
import json
from pathlib import Path
import sys

from certificates import InvalidCertificate
from relying_party import ActionGate
from witnessed import verify_witnessed_certificate


def main() -> int:
    parser=argparse.ArgumentParser(description='Verify a sealed ACE v0.4 authorization certificate')
    parser.add_argument('certificate',type=Path)
    parser.add_argument('--expected-protocol',required=True)
    parser.add_argument('--expected-policy',required=True)
    parser.add_argument('--expected-challenge',required=True)
    parser.add_argument('--expected-epoch',required=True,type=int)
    parser.add_argument('--expected-previous-digest',required=True)
    parser.add_argument('--consume-db',type=Path,default=None,
                        help='persist one-use action nonce and monotonically anchored heads')
    args=parser.parse_args()
    try:
        cert=json.loads(args.certificate.read_text(encoding='utf-8'))
        result=verify_witnessed_certificate(
            cert,expected_protocol=args.expected_protocol,
            expected_policy=args.expected_policy,
            expected_challenge=args.expected_challenge,
            expected_epoch=args.expected_epoch,
            expected_previous_digest=args.expected_previous_digest)
        if args.consume_db:
            gate=ActionGate(args.consume_db)
            committed=gate.verify_and_consume(
                cert,expected_protocol=args.expected_protocol,
                expected_policy=args.expected_policy,
                expected_challenge=args.expected_challenge)
            if result != committed:
                raise InvalidCertificate('pinning and replay-guard views disagree')
        print(json.dumps({'authorized':result.authorized,
                          'checkpoint_digest':result.checkpoint_digest,
                          'epoch':result.epoch,'log_entries':result.log_entries,
                          'accepted_slots':result.valid_sources},indent=2))
        return 0 if result.authorized else 2
    except (InvalidCertificate, OSError, ValueError) as exc:
        print('REJECTED:',exc,file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
