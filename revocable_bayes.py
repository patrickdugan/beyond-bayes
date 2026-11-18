"""BB-CQ-02: exact ECA-04 Bayesian inference with revocable source groups.

Research-only exact finite development model. Input labels and evidence-group
membership are EXTERNALLY declared synthetic assumptions. The ECA-04 likelihood
treats signed report/host-gold pairs as conditionally independent given a
single regime. This file supplies neither signatures nor source independence,
a causal neural measurement, a probability certificate, or action authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction as Q
from itertools import product

from continuation_quotient import FiniteMachine

SCHEMA = "ace-bb-cq02-revocable-bayes-v1"
# ECA-04 original priors and complementary report channels, source-pinned.
PRIORS = (Q(45, 100), Q(35, 100), Q(20, 100))
MATCH_PROBS = (Q(95, 100), Q(65, 100), Q(15, 100))
ECA04_ORIGINAL_MODEL_SHA256 = "49bf2db1316942a23b91943843eb0398043c806cadd40421371af571aa15b3d8"


def _bit(v: int) -> None:
    if type(v) is not int or v not in (0, 1):
        raise ValueError("a report or known label must be an integer bit")


def _identity(s: str) -> None:
    if type(s) is not str or not 0 < len(s) <= 128:
        raise ValueError("nonempty bounded identity required")


def posterior_counts(matches: int, total: int) -> tuple[Q, Q, Q]:
    """Exact ECA-04 posterior over three regimes for n public label/report pairs.

    Complementary channels make P(report agrees with gold | regime k)=t_k
    independent of the gold bit, *conditional on* the stated sensor model.
    """
    if (type(matches) is not int or type(total) is not int or
            total < 0 or not 0 <= matches <= total):
        raise ValueError("invalid sufficient counts")
    weights = tuple(prior * t ** matches * (1 - t) ** (total - matches)
                    for prior, t in zip(PRIORS, MATCH_PROBS))
    denom = sum(weights, Q(0))
    return tuple(w / denom for w in weights)


def posterior_full_replay(pairs: tuple[tuple[int, int], ...]) -> tuple[Q, Q, Q]:
    """Independent full-history likelihood oracle; never calls count scorer."""
    weighted = []
    for k, prior in enumerate(PRIORS):
        yes = MATCH_PROBS[k]
        no = 1 - yes
        mass = prior
        for known_label, report in pairs:
            _bit(known_label)
            _bit(report)
            # ECA-04: when label=1 P(yes)=t, otherwise P(yes)=f=1-t.
            f = 1 - yes
            p_report_one = yes if known_label else f
            mass *= p_report_one if report else 1 - p_report_one
        weighted.append(mass)
    denom = sum(weighted, Q(0))
    return tuple(v / denom for v in weighted)


def posterior_label(posterior: tuple[Q, Q, Q]) -> str:
    """Stable machine observation, kept exact rather than rounded."""
    return "|".join(f"{p.numerator}/{p.denominator}" for p in posterior)


@dataclass(frozen=True)
class Slot:
    id: str
    evidence_group: str
    known_label: int

    def __post_init__(self) -> None:
        _identity(self.id)
        _identity(self.evidence_group)
        _bit(self.known_label)


@dataclass(frozen=True)
class Event:
    kind: str
    subject: str
    report: int | None = None

    def __post_init__(self) -> None:
        _identity(self.subject)
        if self.kind == "observe":
            _bit(self.report)
        elif self.kind == "revoke":
            if self.report is not None:
                raise ValueError("revoke has no report value")
        else:
            raise ValueError("unknown event")


@dataclass(frozen=True)
class Ledger:
    """Immutable events, one-shot slots, irreversible evidence-group revocations.

    Source grouping is a hypothetical provenance extension to ECA-04, whose
    original host signs all twelve sentinels under ONE issuer key. A group in
    this toy roster is NOT automatically a separately authenticated issuer.
    """
    slots: tuple[Slot, ...]
    events: tuple[Event, ...] = ()

    def __post_init__(self) -> None:
        if (type(self.slots) is not tuple or not self.slots or
                any(type(s) is not Slot for s in self.slots)):
            raise ValueError("nonempty bounded tuple of slots required")
        if len(self.slots) > 64 or len({s.id for s in self.slots}) != len(self.slots):
            raise ValueError("overlarge or duplicated slot roster")
        if type(self.events) is not tuple or len(self.events) > 2 * len(self.slots):
            raise ValueError("invalid event sequence")
        self.replay()

    def replay(self) -> tuple[dict[str, int], frozenset[str]]:
        slots = {s.id: s for s in self.slots}
        groups = {s.evidence_group for s in self.slots}
        observed: dict[str, int] = {}
        revoked: set[str] = set()
        for event in self.events:
            if type(event) is not Event:
                raise ValueError("event must be typed")
            if event.kind == "observe":
                if (event.subject not in slots or event.subject in observed or
                        slots[event.subject].evidence_group in revoked):
                    raise ValueError("unknown, repeated, or revoked observation slot")
                observed[event.subject] = event.report
            else:
                if event.subject not in groups or event.subject in revoked:
                    raise ValueError("unknown or repeated group revocation")
                revoked.add(event.subject)
        return observed, frozenset(revoked)

    def observe(self, slot_id: str, report: int) -> Ledger:
        return Ledger(self.slots, self.events + (Event("observe", slot_id, report),))

    def revoke(self, evidence_group: str) -> Ledger:
        return Ledger(self.slots, self.events + (Event("revoke", evidence_group),))

    def active_pairs(self) -> tuple[tuple[int, int], ...]:
        observed, revoked = self.replay()
        return tuple((s.known_label, observed[s.id]) for s in self.slots
                     if s.id in observed and s.evidence_group not in revoked)

    def grouped_counts(self) -> dict[str, tuple[int, int, bool]]:
        """Per-group (observed count, matching count, revoked flag)."""
        observed, revoked = self.replay()
        groups = {s.evidence_group for s in self.slots}
        counts = {g: (0, 0, g in revoked) for g in groups}
        for slot in self.slots:
            if slot.id not in observed or slot.evidence_group in revoked:
                continue
            n, m, flag = counts[slot.evidence_group]
            counts[slot.evidence_group] = (n + 1, m + int(slot.known_label == observed[slot.id]), flag)
        return counts

    def grouped_posterior(self) -> tuple[Q, Q, Q]:
        summary = self.grouped_counts()
        n = sum(v[0] for v in summary.values())
        m = sum(v[1] for v in summary.values())
        return posterior_counts(m, n)

    def full_posterior(self) -> tuple[Q, Q, Q]:
        return posterior_full_replay(self.active_pairs())

    @property
    def authorizes_action(self) -> bool:
        return False


def static_revocation_machine(groups: int = 3) -> FiniteMachine:
    """Full initial one-report-per-group roster, then idempotent revocations.

    Encoded root status: 0=active mismatch, 1=active match, 2=revoked.
    Unlike Ledger, this abstract machine makes repeated revocation idempotent.
    """
    if type(groups) is not int or not 1 <= groups <= 5:
        raise ValueError("finite static study supports one to five groups")
    states = tuple(product((0, 1, 2), repeat=groups))
    index = {s: i for i, s in enumerate(states)}
    names = tuple("".join(str(v) for v in s) for s in states)
    outputs = tuple(posterior_label(posterior_counts(sum(v == 1 for v in s),
                                                     sum(v != 2 for v in s))) for s in states)
    transitions = tuple(
        tuple(index[tuple(2 if j == i else v for j, v in enumerate(s))]
              for i in range(groups))
        for s in states
    )
    return FiniteMachine(names, tuple(f"revoke:{i}" for i in range(groups)),
                         outputs, transitions)


def prospective_machine(groups: int = 3) -> FiniteMachine:
    """One future observation per group; admit legally invalid events as sink.

    States 0=unobserved, 1=observed mismatch, 2=observed match, 3=revoked.
    The contract rejects repeated observations/revocations, matching Ledger.
    The sink is essential: an illegal future action is a distinct outcome.
    """
    if type(groups) is not int or not 1 <= groups <= 3:
        raise ValueError("finite prospective study supports one to three groups")
    states = tuple(product(range(4), repeat=groups))
    index = {s: i for i, s in enumerate(states)}
    sink = len(states)
    events = tuple((typ, j, report) for j in range(groups)
                   for typ, report in (("observe", 0), ("observe", 1), ("revoke", None)))
    matrix = []
    for state in states:
        row = []
        for kind, j, report in events:
            successor = list(state)
            if kind == "observe" and state[j] == 0:
                successor[j] = 1 + report
            elif kind == "revoke" and state[j] != 3:
                successor[j] = 3
            else:
                row.append(sink)
                continue
            row.append(index[tuple(successor)])
        matrix.append(tuple(row))
    matrix.append((sink,) * len(events))
    outputs = tuple(posterior_label(posterior_counts(
        sum(v == 2 for v in s), sum(v in (1, 2) for v in s))) for s in states) + ("INVALID",)
    names = tuple("".join(str(v) for v in s) for s in states) + ("INVALID",)
    event_names = tuple(f"{kind}:{j}" if report is None else f"{kind}:{j}:{report}"
                        for kind, j, report in events)
    return FiniteMachine(names, event_names, outputs, tuple(matrix))
