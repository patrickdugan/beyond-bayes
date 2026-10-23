"""Synthetic-only fully signed checkpoint + receipt quorum demonstration."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path

from test_witnessed import setup, bit_reports
from witnessed import export_witnessed_certificate, verify_receipts, GENESIS_DIGEST


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',default='results/witnessed_demo.json')
    args=parser.parse_args()
    p,keys,policy,logkey,wkeys,ws,log=setup()
    for r in bit_reports(p,keys,[0]*12):
        receipts=[w.receive(r) for w in ws[:3]]
        assert verify_receipts(r,receipts,policy,expected_epoch=0)
        log.append(r)
    head,consistency=log.seal()
    endorsements=[w.endorse(head,log.entries) for w in ws[:3]]
    certificate=export_witnessed_certificate(log,head,endorsements,consistency)
    path=Path(args.output)
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(certificate,indent=2,sort_keys=True)+'\n',encoding='utf8')
    print('Synthetic certificate:',path)
    print('Externally pinned protocol digest:',p.commitment)
    print('Externally pinned witness-policy digest:',policy.commitment)
    print('Expected action challenge:',p.challenge)
    print('Expected epoch: 0')
    print('Expected previous digest:',GENESIS_DIGEST)
    print('TEST-ONLY PRIVATE KEYS; do not use this example for real-world authorization')


if __name__=='__main__': main()
