"""Portable, independently replayable ACE authorization certificate.

The relying party must obtain a trusted protocol commitment OUT OF BAND.
Its verification proves that the included evidence is signed by enrolled
keys and that the claimed decision follows the fixed algorithm and policy.

A standalone bundle cannot prove the evidence collector provided EVERY
received report, or that a reported sample reflects physical reality.
For full auditability, externally anchor an append-only intake log and use
its consistent snapshot with this verifier.
"""
from __future__ import annotations

from dataclasses import asdict
import json
import math
from typing import Mapping

from provenance import Protocol, Slot, SignedObservation, SignedEvidenceLedger, Receipt


class InvalidCertificate(ValueError):
    pass


def export_certificate(ledger: SignedEvidenceLedger) -> dict:
    """Serialize protocol, admitted signed evidence, and a decision digest."""
    decision = ledger.decide()
    return {
        'schema': 'ACE-authorization-certificate-v1',
        'protocol': ledger.protocol.canonical(),
        'protocol_commitment': ledger.protocol.commitment,
        'valid_signed_reports': [asdict(r) for r in ledger.valid_reports],
        'claimed_decision': {
            'authorized': decision.authorized,
            'robust_max_log_e': decision.robust_max_log_e,
            'accepted_slots': decision.accepted_slots,
            'missing_slots': decision.missing_slots,
            'equivocations': list(decision.equivocations),
        },
        'incomplete_intake_warning': ('Proof applies to included signed reports '
                                     'and externally pinned enrollment manifest.'),
    }


def verify_certificate(bundle: Mapping, *, expected_commitment: str) -> bool:
    """Check keys, signatures, fixed manifest, and independently replayed rule.

    Returns only the claimed boolean decision after verifying all claimed
    score/count fields. Throws InvalidCertificate on mismatch, never permits
    a malformed or missing commitment to auto-authorize.
    """
    try:
        if bundle['schema'] != 'ACE-authorization-certificate-v1':
            raise InvalidCertificate('unsupported certificate schema')
        if not expected_commitment or expected_commitment != bundle['protocol_commitment']:
            raise InvalidCertificate('externally pinned manifest mismatch')
        d = bundle['protocol']
        if set(d) != {'version','experiment_id','challenge','slots','null_p',
                      'bet_q','alpha','corruption_budget'} or d['version'] != 1:
            raise InvalidCertificate('unexpected protocol fields/version')
        protocol = Protocol(d['experiment_id'],d['challenge'],
                            tuple(Slot(**s) for s in d['slots']),d['null_p'],
                            d['bet_q'],d['alpha'],d['corruption_budget'])
        if protocol.commitment != expected_commitment:
            raise InvalidCertificate('manifest bytes and digest disagree')
        ledger = SignedEvidenceLedger(protocol, expected_commitment=expected_commitment)
        report_list = bundle['valid_signed_reports']
        if not isinstance(report_list,list):
            raise InvalidCertificate('signed reports must be an array')
        for raw in report_list:
            if set(raw) != {'experiment_id','protocol_commitment','slot_id','bit','signature_hex'}:
                raise InvalidCertificate('unexpected report keys')
            res = ledger.offer(SignedObservation(**raw))
            if res not in (Receipt.ACCEPTED, Receipt.EQUIVOCATION):
                raise InvalidCertificate(f'bad signed report: {res.value}')
        claim = bundle['claimed_decision']
        if set(claim) != {'authorized','robust_max_log_e','accepted_slots',
                         'missing_slots','equivocations'}:
            raise InvalidCertificate('unexpected claimed decision fields')
        d = ledger.decide()
        if (type(claim['authorized']) is not bool or
            claim['authorized'] != d.authorized or
            type(claim['accepted_slots']) is not int or
            claim['accepted_slots'] != d.accepted_slots or
            type(claim['missing_slots']) is not int or
            claim['missing_slots'] != d.missing_slots or
            claim['equivocations'] != list(d.equivocations) or
            not isinstance(claim['robust_max_log_e'], (float,int)) or
            not math.isfinite(claim['robust_max_log_e']) or
            not math.isclose(claim['robust_max_log_e'],d.robust_max_log_e,
                             rel_tol=1e-12,abs_tol=1e-12)):
            raise InvalidCertificate('claimed decision is not reproducible')
        return d.authorized
    except (KeyError, TypeError, ValueError, OverflowError) as e:
        if isinstance(e, InvalidCertificate):
            raise
        raise InvalidCertificate(str(e)) from e


def dumps_certificate(bundle: Mapping) -> str:
    return json.dumps(bundle, indent=2,sort_keys=True, allow_nan=False) + '\n'
