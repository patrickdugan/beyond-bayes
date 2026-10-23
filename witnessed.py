"""ACE v0.4 research prototype: externally witnessed evidence intake.

Trust assumptions (indispensable):
  * At most f enrolled witness identities collude, honest signing keys stay safe.
  * Honest witnesses persist a single signed view per epoch across restarts.
  * An acknowledged observation was submitted to at least receipt_quorum
    distinct witnesses BEFORE they sealed the epoch being relied upon.
  * Honest witnesses inspect ALL raw log entries and insist their individually
    acknowledged reports are present before co-signing.
  * The relying party pins protocol and witness-policy digests out-of-band;
    a trusted anchor supplies the previous checkpoint and action challenge.
  * Physical sampling independence, null law and k corruption limit remain
    external statistical premises.

A signature quorum plus receipt quorum with q+r > n+f guarantees they
intersect at an honest witness, so an already quorum-acknowledged report
cannot be omitted from an accepted checkpoint, conditional on the assumptions.

Witness and collector state here is IN MEMORY. Durable witness journaling,
network scheduling, enrollment and bounded delivery remain open engineering.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import math
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from certificates import InvalidCertificate
from merklelog import merkle_root, consistency_proof, verify_consistency
from provenance import (Protocol, Receipt, SignedEvidenceLedger, SignedObservation,
                        Slot, _digest, _encoding)

GENESIS_DIGEST = '0' * 64
SCHEMA = 'ACE-witnessed-certificate-v1'


class WitnessError(ValueError):
    pass


def _pub_valid(key_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
        return len(bytes.fromhex(key_hex)) == 32
    except (TypeError, ValueError):
        return False


def _check_hex256(value: str) -> bool:
    if type(value) is not str or len(value) != 64:
        return False
    try:
        return len(bytes.fromhex(value)) == 32
    except ValueError:
        return False


def _check_sig(public_hex: str, signature_hex: str, message: bytes) -> bool:
    try:
        signature = bytes.fromhex(signature_hex)
        if len(signature) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _report_dict(report: SignedObservation) -> dict:
    return asdict(report)


def _report_bytes(report: SignedObservation) -> bytes:
    return _encoding(_report_dict(report))


def report_digest(report: SignedObservation) -> str:
    return hashlib.sha256(b'ACE:report:v1\x00' + _report_bytes(report)).hexdigest()


def _typed_report(raw: Mapping) -> SignedObservation:
    if not isinstance(raw, dict) or set(raw) != {
        'experiment_id','protocol_commitment','slot_id','bit','signature_hex'
    }:
        raise InvalidCertificate('invalid raw report structure')
    return SignedObservation(**raw)


def _verify_reports(protocol: Protocol, reports: list[SignedObservation]) -> SignedEvidenceLedger:
    ledger = SignedEvidenceLedger(protocol,expected_commitment=protocol.commitment)
    for r in reports:
        result = ledger.offer(r)
        if result == Receipt.QUARANTINED:
            raise WitnessError(f'invalid source report: {ledger.quarantines[-1]}')
    return ledger


@dataclass(frozen=True)
class WitnessIdentity:
    witness_id: str
    public_key_hex: str

    def canonical(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class WitnessPolicy:
    protocol_commitment: str
    log_public_key_hex: str
    witnesses: tuple[WitnessIdentity, ...]
    max_faulty: int
    checkpoint_quorum: int
    receipt_quorum: int

    def __post_init__(self):
        n = len(self.witnesses)
        if not _check_hex256(self.protocol_commitment) or not _pub_valid(self.log_public_key_hex):
            raise ValueError('invalid manifest commitment or log key')
        ids = [w.witness_id for w in self.witnesses]
        keys = [w.public_key_hex for w in self.witnesses]
        if not n or any(not v or type(v) is not str for v in ids) or len(set(ids)) != n or \
                len(set(keys)) != n or any(not _pub_valid(k) for k in keys) or \
                self.log_public_key_hex in keys:
            raise ValueError('distinct, nonempty witness IDs and real keys required')
        f, q, r = self.max_faulty, self.checkpoint_quorum, self.receipt_quorum
        if any(type(x) is not int for x in (f,q,r)) or not 0 <= f < n or not 1 <= q <= n or \
                not 1 <= r <= n:
            raise ValueError('invalid witness quorum parameters')
        if 2*q <= n+f or q+r <= n+f:
            raise ValueError('quorums may intersect only at faulty identities')

    def canonical(self) -> dict:
        return {'schema':'ACE-witness-policy-v1',
                'protocol_commitment':self.protocol_commitment,
                'log_public_key_hex':self.log_public_key_hex,
                'witnesses':[w.canonical() for w in self.witnesses],
                'max_faulty':self.max_faulty,
                'checkpoint_quorum':self.checkpoint_quorum,
                'receipt_quorum':self.receipt_quorum}

    @property
    def commitment(self) -> str:
        return _digest(self.canonical())

    def witness_keys(self) -> dict[str,str]:
        return {w.witness_id:w.public_key_hex for w in self.witnesses}


def unpack_policy(d: dict) -> WitnessPolicy:
    if not isinstance(d,dict) or set(d) != {
        'schema','protocol_commitment','log_public_key_hex','witnesses',
        'max_faulty','checkpoint_quorum','receipt_quorum'
    } or d['schema'] != 'ACE-witness-policy-v1':
        raise InvalidCertificate('unrecognized witness policy schema')
    if not isinstance(d['witnesses'],list):
        raise InvalidCertificate('witness roster must be a list')
    for witness in d['witnesses']:
        if not isinstance(witness,dict) or set(witness) != {'witness_id','public_key_hex'}:
            raise InvalidCertificate('invalid witness identity')
    return WitnessPolicy(d['protocol_commitment'],d['log_public_key_hex'],
                         tuple(WitnessIdentity(**w) for w in d['witnesses']),
                         d['max_faulty'],d['checkpoint_quorum'],d['receipt_quorum'])


def unpack_protocol(d: dict) -> Protocol:
    if not isinstance(d,dict) or set(d) != {
        'version','experiment_id','challenge','slots','null_p','bet_q',
        'alpha','corruption_budget'
    } or type(d['version']) is not int or d['version'] != 1:
        raise InvalidCertificate('unrecognized protocol schema')
    if not isinstance(d['slots'],list):
        raise InvalidCertificate('invalid slot roster')
    for slot in d['slots']:
        if not isinstance(slot,dict) or set(slot) != {
            'slot_id','source_id','dependence_domain','public_key_hex'
        }:
            raise InvalidCertificate('invalid slot identity')
    return Protocol(d['experiment_id'],d['challenge'],
                    tuple(Slot(**s) for s in d['slots']), d['null_p'],
                    d['bet_q'],d['alpha'],d['corruption_budget'])


@dataclass(frozen=True)
class ReportReceipt:
    witness_id: str
    policy_commitment: str
    report_digest: str
    target_epoch: int
    signature_hex: str

    def body(self) -> dict:
        return {'domain':'ACE:receipt:v2', 'witness_id':self.witness_id,
                'policy_commitment':self.policy_commitment,
                'report_digest':self.report_digest,
                'target_epoch':self.target_epoch}

    def canonical(self) -> dict:
        return asdict(self)


def verify_receipts(report: SignedObservation, receipts: list[ReportReceipt],
                    policy: WitnessPolicy, *, expected_epoch: int) -> bool:
    valid = set()
    roster = policy.witness_keys()
    for receipt in receipts:
        if not isinstance(receipt,ReportReceipt) or receipt.witness_id in valid or \
            receipt.witness_id not in roster or \
            type(receipt.target_epoch) is not int or \
            receipt.target_epoch != expected_epoch or \
            receipt.policy_commitment != policy.commitment or \
            receipt.report_digest != report_digest(report) or \
            not _check_sig(roster[receipt.witness_id], receipt.signature_hex,
                           _encoding(receipt.body())):
            return False
        valid.add(receipt.witness_id)
    return len(valid) >= policy.receipt_quorum


@dataclass(frozen=True)
class Head:
    policy_commitment: str
    protocol_commitment: str
    epoch: int
    size: int
    root_hex: str
    previous_digest: str

    def __post_init__(self):
        if type(self.epoch) is not int or self.epoch < 0 or type(self.size) is not int or \
            self.size < 0 or not all(_check_hex256(v) for v in
                                    (self.policy_commitment,self.protocol_commitment,
                                     self.root_hex,self.previous_digest)):
            raise ValueError('bad checkpoint fields')

    def canonical(self) -> dict:
        return {'domain':'ACE:head:v1', 'policy_commitment':self.policy_commitment,
                'protocol_commitment':self.protocol_commitment,
                'epoch':self.epoch,'size':self.size,'root_hex':self.root_hex,
                'previous_digest':self.previous_digest}

    @property
    def digest(self) -> str:
        return _digest(self.canonical())


def unpack_head(d: dict) -> Head:
    if not isinstance(d,dict) or set(d) != {
        'domain','policy_commitment','protocol_commitment','epoch','size',
        'root_hex','previous_digest'
    } or d['domain'] != 'ACE:head:v1':
        raise InvalidCertificate('invalid checkpoint body')
    return Head(d['policy_commitment'],d['protocol_commitment'],d['epoch'],
                d['size'],d['root_hex'],d['previous_digest'])


@dataclass(frozen=True)
class SignedHead:
    head: Head
    log_signature_hex: str

    def canonical(self) -> dict:
        return {'head':self.head.canonical(), 'log_signature_hex':self.log_signature_hex}


def verify_signed_head(signed: SignedHead, policy: WitnessPolicy) -> bool:
    return (signed.head.policy_commitment == policy.commitment and
            signed.head.protocol_commitment == policy.protocol_commitment and
            _check_sig(policy.log_public_key_hex, signed.log_signature_hex,
                       _encoding(signed.head.canonical())))


def snapshot_log_root(reports: list[SignedObservation]) -> str:
    return merkle_root([_report_bytes(r) for r in reports]).hex()


@dataclass(frozen=True)
class CheckpointEndorsement:
    witness_id: str
    head_digest: str
    signature_hex: str

    def body(self) -> dict:
        return {'domain':'ACE:checkpoint-endorsement:v1',
                'witness_id':self.witness_id,'head_digest':self.head_digest}

    def canonical(self) -> dict:
        return asdict(self)


class Witness:
    """Direct-submission sink and in-memory one-view-per-epoch signer."""
    def __init__(self, policy: WitnessPolicy, protocol: Protocol,
                 witness_id: str, private_key: Ed25519PrivateKey):
        if policy.protocol_commitment != protocol.commitment:
            raise WitnessError('manifest mismatch')
        if witness_id not in policy.witness_keys() or \
                policy.witness_keys()[witness_id] != _key_hex(private_key):
            raise WitnessError('witness ID/key does not match roster')
        self.policy=policy
        self.protocol=protocol
        self.witness_id=witness_id
        self._key=private_key
        self._seen: dict[str, SignedObservation] = {}
        self._last_entries: tuple[bytes,...] = ()
        self._last_head: Head | None = None
        self._signed_epochs: dict[int, str] = {}

    def receive(self, report: SignedObservation) -> ReportReceipt:
        _verify_reports(self.protocol,[report])
        digest=report_digest(report)
        self._seen[digest]=report
        target=0 if self._last_head is None else self._last_head.epoch+1
        body={'domain':'ACE:receipt:v2','witness_id':self.witness_id,
              'policy_commitment':self.policy.commitment,
              'report_digest':digest, 'target_epoch':target}
        return ReportReceipt(self.witness_id,self.policy.commitment,digest,target,
                             self._key.sign(_encoding(body)).hex())

    def endorse(self, signed: SignedHead,
                reports: list[SignedObservation]) -> CheckpointEndorsement:
        if not verify_signed_head(signed,self.policy):
            raise WitnessError('invalid log signature, manifest, or policy')
        h=signed.head
        if h.epoch in self._signed_epochs:
            if self._signed_epochs[h.epoch] != h.digest:
                raise WitnessError('same witness refuses an incompatible same-epoch head')
            return self._sign_endorsement(h)
        if h.size != len(reports) or h.root_hex != snapshot_log_root(reports):
            raise WitnessError('checkpoint root/size disagrees with supplied complete log')
        _verify_reports(self.protocol,reports)
        items=tuple(_report_bytes(report) for report in reports)
        if self._last_head is None:
            if h.epoch != 0 or h.previous_digest != GENESIS_DIGEST:
                raise WitnessError('unanchored genesis')
        elif h.epoch != self._last_head.epoch+1 or \
                h.previous_digest != self._last_head.digest or \
                items[:len(self._last_entries)] != self._last_entries:
            raise WitnessError('checkpoint does not extend witness\' prior view')
        present={report_digest(r) for r in reports}
        if not self._seen.keys() <= present:
            raise WitnessError('missing witnessed submission from checkpoint')
        self._last_head=h
        self._last_entries=items
        self._signed_epochs[h.epoch]=h.digest
        return self._sign_endorsement(h)

    def _sign_endorsement(self, h: Head) -> CheckpointEndorsement:
        body={'domain':'ACE:checkpoint-endorsement:v1',
              'witness_id':self.witness_id,'head_digest':h.digest}
        return CheckpointEndorsement(self.witness_id,h.digest,
                                     self._key.sign(_encoding(body)).hex())


def _key_hex(private_key: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()


class IntakeLog:
    def __init__(self, protocol: Protocol, policy: WitnessPolicy,
                 log_key: Ed25519PrivateKey):
        if policy.protocol_commitment != protocol.commitment or \
                policy.log_public_key_hex != _key_hex(log_key):
            raise WitnessError('log key/protocol differs from frozen manifest')
        self.protocol=protocol
        self.policy=policy
        self._key=log_key
        self.entries: list[SignedObservation]=[]
        self._checkpoints: list[Head]=[]

    def append(self, report: SignedObservation) -> None:
        _verify_reports(self.protocol,[report])
        self.entries.append(report)

    def seal(self) -> tuple[SignedHead, list[str]]:
        prev=self._checkpoints[-1] if self._checkpoints else None
        epoch=0 if prev is None else prev.epoch+1
        head=Head(self.policy.commitment,self.protocol.commitment,epoch,
                  len(self.entries),snapshot_log_root(self.entries),
                  prev.digest if prev else GENESIS_DIGEST)
        consistency=[] if prev is None else consistency_proof(
            [_report_bytes(r) for r in self.entries],prev.size)
        self._checkpoints.append(head)
        return SignedHead(head,self._key.sign(_encoding(head.canonical())).hex()),consistency


def verify_endorsements(head: Head, endorsements: list[CheckpointEndorsement],
                        policy: WitnessPolicy) -> bool:
    keys=policy.witness_keys()
    valid=set()
    for e in endorsements:
        if not isinstance(e,CheckpointEndorsement) or e.witness_id in valid or \
                e.witness_id not in keys or e.head_digest != head.digest or \
                not _check_sig(keys[e.witness_id],e.signature_hex,_encoding(e.body())):
            return False
        valid.add(e.witness_id)
    return len(valid)>=policy.checkpoint_quorum


def _decision_claim(ledger: SignedEvidenceLedger) -> dict:
    d=ledger.decide()
    return {'authorized':d.authorized, 'robust_max_log_e':d.robust_max_log_e,
            'accepted_slots':d.accepted_slots,'missing_slots':d.missing_slots,
            'equivocations':list(d.equivocations)}


def export_witnessed_certificate(log: IntakeLog, signed_head: SignedHead,
                                 endorsements: list[CheckpointEndorsement],
                                 consistency: list[str],
                                 previous_head: Head | None = None) -> dict:
    ledger=_verify_reports(log.protocol,log.entries)
    return {'schema':SCHEMA,
            'protocol':log.protocol.canonical(),
            'witness_policy':log.policy.canonical(),
            'signed_head':signed_head.canonical(),
            'endorsements':[e.canonical() for e in endorsements],
            'complete_log':[_report_dict(r) for r in log.entries],
            'previous_head':None if previous_head is None else previous_head.canonical(),
            'consistency_path':consistency,
            'claimed_decision':_decision_claim(ledger)}


@dataclass(frozen=True)
class VerifiedDecision:
    authorized: bool
    checkpoint_digest: str
    epoch: int
    log_entries: int
    valid_sources: int


def verify_witnessed_certificate(bundle: Mapping, *,
                                 expected_protocol: str,
                                 expected_policy: str,
                                 expected_challenge: str,
                                 expected_epoch: int,
                                 expected_previous_digest: str) -> VerifiedDecision:
    """Offline verification; caller must persist checkpoint digest to reject rollback.

    The complete log bundle is used rather than an attacker-chosen subset of
    signed observations. Quorum honesty is a trust assumption, not a fact
    established by signatures. This verifier fails closed on malformed inputs.
    """
    try:
        if not isinstance(bundle,dict) or set(bundle) != {
            'schema','protocol','witness_policy','signed_head','endorsements',
            'complete_log','previous_head','consistency_path','claimed_decision'
        } or bundle['schema'] != SCHEMA:
            raise InvalidCertificate('unknown certificate schema')
        protocol=unpack_protocol(bundle['protocol'])
        policy=unpack_policy(bundle['witness_policy'])
        if not expected_protocol or not expected_policy or not expected_challenge or \
                policy.commitment != expected_policy or protocol.commitment != expected_protocol or \
                policy.protocol_commitment != protocol.commitment or \
                protocol.challenge != expected_challenge:
            raise InvalidCertificate('external policy, roster, or action anchor mismatch')
        raw_signed=bundle['signed_head']
        if not isinstance(raw_signed,dict) or set(raw_signed) != {'head','log_signature_hex'}:
            raise InvalidCertificate('bad signed checkpoint structure')
        head=unpack_head(raw_signed['head'])
        signed=SignedHead(head,raw_signed['log_signature_hex'])
        if not verify_signed_head(signed,policy):
            raise InvalidCertificate('invalid log checkpoint signature')
        if type(expected_epoch) is not int or head.epoch != expected_epoch or \
                not _check_hex256(expected_previous_digest) or \
                head.previous_digest != expected_previous_digest:
            raise InvalidCertificate('epoch or expected prior anchor mismatch')
        if not isinstance(bundle['endorsements'],list):
            raise InvalidCertificate('endorsements must be an array')
        endorsements=[]
        for raw in bundle['endorsements']:
            if not isinstance(raw,dict) or set(raw) != {
                'witness_id','head_digest','signature_hex'
            }:
                raise InvalidCertificate('malformed witness signature')
            endorsements.append(CheckpointEndorsement(**raw))
        if not verify_endorsements(head,endorsements,policy):
            raise InvalidCertificate('invalid or insufficient witness quorum')
        if not isinstance(bundle['complete_log'],list):
            raise InvalidCertificate('log must be an array')
        reports=[_typed_report(raw) for raw in bundle['complete_log']]
        if head.size != len(reports) or snapshot_log_root(reports) != head.root_hex:
            raise InvalidCertificate('complete log missing data or altered')
        ledger=_verify_reports(protocol,reports)
        previous=bundle['previous_head']
        path=bundle['consistency_path']
        if not isinstance(path,list):
            raise InvalidCertificate('malformed consistency path')
        if head.epoch == 0:
            if previous is not None or path or head.previous_digest != GENESIS_DIGEST:
                raise InvalidCertificate('genesis must be anchored')
        else:
            if previous is None:
                raise InvalidCertificate('missing prior head for consistency check')
            old=unpack_head(previous)
            if old.digest != expected_previous_digest or old.epoch+1 != head.epoch or \
                    old.policy_commitment != policy.commitment or \
                    old.protocol_commitment != protocol.commitment or \
                    not verify_consistency(old.size,head.size,old.root_hex,head.root_hex,path):
                raise InvalidCertificate('append-only consistency failed')
        claim=bundle['claimed_decision']
        actual=_decision_claim(ledger)
        if not isinstance(claim,dict) or set(claim) != set(actual) or \
                type(claim['authorized']) is not bool or \
                any(type(claim[f]) is not int for f in ('accepted_slots','missing_slots')) or \
                not isinstance(claim['equivocations'],list) or \
                claim['authorized'] != actual['authorized'] or \
                claim['accepted_slots'] != actual['accepted_slots'] or \
                claim['missing_slots'] != actual['missing_slots'] or \
                claim['equivocations'] != actual['equivocations'] or \
                type(claim['robust_max_log_e']) not in (int,float) or \
                not math.isfinite(claim['robust_max_log_e']) or \
                not math.isclose(claim['robust_max_log_e'],actual['robust_max_log_e'],
                                 rel_tol=1e-12,abs_tol=1e-12):
            raise InvalidCertificate('claimed authorization is inconsistent with sealed log')
        return VerifiedDecision(actual['authorized'],head.digest,head.epoch,
                                head.size,actual['accepted_slots'])
    except (TypeError,KeyError,ValueError,OverflowError) as exc:
        if isinstance(exc,InvalidCertificate):
            raise
        raise InvalidCertificate(str(exc)) from exc
