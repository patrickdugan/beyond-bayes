"""Create a disposable synthetic ACE signed authorization certificate.

DEMONSTRATION ONLY. Uses deterministic fixture keys and synthetic observations.
No real sensor enrollment, source independence or third-party integrity audit.
"""
from pathlib import Path

from certificates import export_certificate, dumps_certificate, verify_certificate
from provenance import SignedEvidenceLedger
from test_provenance import fixture, emit


def main():
    protocol, keys = fixture(n=12,k=0)
    ledger = SignedEvidenceLedger(protocol,expected_commitment=protocol.commitment)
    emit(protocol,keys,ledger,[0]*12)
    receipt=export_certificate(ledger)
    dest=Path('results/demo_signed_certificate.json')
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(dumps_certificate(receipt),encoding='utf8')
    verified=verify_certificate(receipt,expected_commitment=protocol.commitment)
    print('Demonstration certificate:',dest)
    print('Externally pinned commitment to supply to verifier:',protocol.commitment)
    print('Authorized:',verified)


if __name__=='__main__':main()
