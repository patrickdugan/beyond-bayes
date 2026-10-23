"""ACE v0.3: signed, precommitted observation admission.

Assumptions are intentionally visible:
* Roster enrollment is an OUT-OF-BAND trust decision, prior to sampling.
* Ed25519 authenticates a pre-enrolled key, not the sensor reading's truth.
* Domain uniqueness expresses a sampling-plan assertion, NOT a statistical
  independence proof.  The clean model must be validated separately.
* At most k distinct enrolled slots have adversarially replaced bit values.
* Absent/withheld evidence is erased, never omitted from the sample schedule.
* Attackers cannot change the frozen roster, experiment challenge, protocol,
  verifier, or the clean-data distribution.

Requires cryptography (Ed25519). No secrets are stored in an evidence bundle.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import math
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from robust import robust_log_e_from_counts


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _encoding(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


@dataclass(frozen=True)
class Slot:
    slot_id: str
    source_id: str
    dependence_domain: str
    public_key_hex: str

    def canonical(self) -> dict:
        return {'slot_id': self.slot_id, 'source_id': self.source_id,
                'dependence_domain': self.dependence_domain,
                'public_key_hex': self.public_key_hex}


@dataclass(frozen=True)
class Protocol:
    experiment_id: str
    challenge: str
    slots: tuple[Slot, ...]
    null_p: float
    bet_q: float
    alpha: float
    corruption_budget: int

    def __post_init__(self) -> None:
        if not self.experiment_id or len(self.challenge) < 16:
            raise ValueError('nonempty experiment ID and unpredictable >=16-character challenge required')
        if not self.slots:
            raise ValueError('roster needs at least one preregistered slot')
        for field in ('slot_id', 'source_id', 'dependence_domain', 'public_key_hex'):
            vals = [getattr(x, field) for x in self.slots]
            if any(not v for v in vals) or len(set(vals)) != len(vals):
                raise ValueError(f'nonempty unique {field} required across slots')
        for slot in self.slots:
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(slot.public_key_hex))
            except (ValueError, TypeError) as exc:
                raise ValueError('invalid Ed25519 key in roster') from exc
        for p in (self.null_p, self.bet_q):
            if not (isinstance(p, (int, float)) and 0 < p < 1 and math.isfinite(p)):
                raise ValueError('null and bet must be finite probabilities in (0,1)')
        if not (0 < self.alpha < 1 and math.isfinite(self.alpha)):
            raise ValueError('invalid alpha')
        if type(self.corruption_budget) is not int or not 0 <= self.corruption_budget <= len(self.slots):
            raise ValueError('invalid corruption budget')

    def canonical(self) -> dict:
        return {'version': 1, 'experiment_id': self.experiment_id,
                'challenge': self.challenge, 'slots': [s.canonical() for s in self.slots],
                'null_p': self.null_p, 'bet_q': self.bet_q,
                'alpha': self.alpha, 'corruption_budget': self.corruption_budget}

    @property
    def commitment(self) -> str:
        return _digest(self.canonical())


@dataclass(frozen=True)
class SignedObservation:
    experiment_id: str
    protocol_commitment: str
    slot_id: str
    bit: int
    signature_hex: str

    def message(self) -> dict:
        return {'version': 1, 'experiment_id': self.experiment_id,
                'protocol_commitment': self.protocol_commitment,
                'slot_id': self.slot_id, 'bit': self.bit}

    @classmethod
    def issue(cls, protocol: Protocol, slot_id: str, bit: int,
              private_key: Ed25519PrivateKey) -> SignedObservation:
        if type(bit) is not int or bit not in (0, 1):
            raise ValueError('bit must be exactly 0 or 1')
        msg = {'version': 1, 'experiment_id': protocol.experiment_id,
               'protocol_commitment': protocol.commitment, 'slot_id': slot_id,
               'bit': bit}
        sig = private_key.sign(_encoding(msg)).hex()
        return cls(protocol.experiment_id, protocol.commitment, slot_id, bit, sig)


class Receipt(str, Enum):
    ACCEPTED = 'accepted'
    DUPLICATE = 'duplicate'
    QUARANTINED = 'quarantined'
    EQUIVOCATION = 'equivocation'


@dataclass(frozen=True)
class Decision:
    authorized: bool
    protocol_commitment: str
    robust_max_log_e: float
    alpha: float
    accepted_slots: int
    missing_slots: int
    unauthorized_reports: int
    equivocations: tuple[str, ...]


class SignedEvidenceLedger:
    """Signed report copies map to one fixed sample slot each.

    Unrecognized or invalid attestations are quarantined with zero influence
    on inference. Two distinct VALID claims for the same slot freeze
    authorization pending forensic reconciliation. A changed/suppressed
    report cannot silently cause existing sample slots to disappear.
    """
    def __init__(self, protocol: Protocol, *, expected_commitment: str):
        if not expected_commitment or expected_commitment != protocol.commitment:
            raise ValueError('trusted externally pinned protocol commitment required')
        self.protocol = protocol
        self._slots = {slot.slot_id: slot for slot in protocol.slots}
        self._accepted: dict[str, SignedObservation] = {}
        self._valid_reports: dict[tuple[str, int], SignedObservation] = {}
        self._equivocations: set[str] = set()
        self._quarantine: list[str] = []

    @property
    def quarantines(self) -> tuple[str, ...]:
        return tuple(self._quarantine)

    @property
    def equivocations(self) -> tuple[str, ...]:
        return tuple(sorted(self._equivocations))

    @property
    def valid_reports(self) -> tuple[SignedObservation, ...]:
        """One copy per distinct valid signed bit; duplicates do not accumulate."""
        return tuple(self._valid_reports[key] for key in sorted(self._valid_reports))

    @property
    def observed(self) -> tuple[Optional[int], ...]:
        return tuple(self._accepted[slot.slot_id].bit if slot.slot_id in self._accepted
                     and slot.slot_id not in self._equivocations else None
                     for slot in self.protocol.slots)

    def _quarantine_report(self, reason: str) -> Receipt:
        self._quarantine.append(reason)
        return Receipt.QUARANTINED

    def offer(self, report: SignedObservation) -> Receipt:
        if not isinstance(report, SignedObservation):
            return self._quarantine_report('invalid payload type')
        slot = self._slots.get(report.slot_id)
        if slot is None:
            return self._quarantine_report('unknown slot')
        if report.experiment_id != self.protocol.experiment_id or \
                report.protocol_commitment != self.protocol.commitment:
            return self._quarantine_report('experiment or manifest mismatch')
        if type(report.bit) is not int or report.bit not in (0, 1):
            return self._quarantine_report('non-binary data')
        try:
            signature = bytes.fromhex(report.signature_hex)
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(slot.public_key_hex))
            key.verify(signature, _encoding(report.message()))
        except (InvalidSignature, ValueError, TypeError):
            return self._quarantine_report('bad signature')
        self._valid_reports[(report.slot_id, report.bit)] = report
        prior = self._accepted.get(report.slot_id)
        if prior is None:
            self._accepted[report.slot_id] = report
            return Receipt.ACCEPTED
        if prior.bit == report.bit:
            return Receipt.DUPLICATE
        self._equivocations.add(report.slot_id)
        return Receipt.EQUIVOCATION

    @property
    def max_log_e(self) -> float:
        """Max over scheduled prefixes, with unknowns included as erasures.

        This recomputes after each update; admission order may be adversarial.
        It is a pathwise lower envelope of the precommitted clean e-process.
        """
        values = self.observed
        best = 0.0
        ones = zeros = missing = 0
        for bit in values:
            if bit is None:
                missing += 1
            elif bit == 1:
                ones += 1
            else:
                zeros += 1
            best = max(best, robust_log_e_from_counts(
                ones, zeros, missing, self.protocol.corruption_budget,
                self.protocol.null_p, self.protocol.bet_q))
        return best

    def decide(self) -> Decision:
        log_e = self.max_log_e
        evidence = self.observed
        authorized = not self._equivocations and log_e >= math.log(1 / self.protocol.alpha)
        return Decision(authorized, self.protocol.commitment, log_e,
                        self.protocol.alpha, sum(v is not None for v in evidence),
                        sum(v is None for v in evidence), len(self._quarantine),
                        self.equivocations)
