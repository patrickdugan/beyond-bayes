"""Independent relying-party CLI for ACE authorization certificates.

Exit 0: authentic and AUTHORIZED.
Exit 2: authentic certificate but DENIED.
Exit 1: invalid certificate or failure to read.
The expected commitment MUST come from a trusted external anchor.
"""
from __future__ import annotations

import argparse
import json
import sys

from certificates import verify_certificate, InvalidCertificate


def main() -> int:
    ap=argparse.ArgumentParser(description='Verify ACE signed evidence receipt')
    ap.add_argument('certificate')
    ap.add_argument('--expected-commitment',required=True,
                    help='64-hex protocol digest from separate trusted channel')
    args=ap.parse_args()
    try:
        with open(args.certificate,'r',encoding='utf8') as f:
            bundle=json.load(f)
        outcome=verify_certificate(bundle,expected_commitment=args.expected_commitment)
    except (OSError, ValueError, TypeError) as exc:
        print(f'INVALID: {exc}',file=sys.stderr)
        return 1
    if outcome:
        print('VERIFIED: AUTHORIZED, conditional on the enrolled sampling model')
        return 0
    print('VERIFIED: DENIED')
    return 2


if __name__=='__main__':
    sys.exit(main())
