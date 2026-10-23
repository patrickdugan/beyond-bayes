"""ACE v0.6: predictable finite-state conditional-null e-processes.

For every state s, the clean next bit X has a conditional success probability
in [row.low, row.high], conditional on the full history.  The state itself is
updated *only from clean observations* via a precommitted automaton.

The betting target q is precommitted for each current state. The per-round
factor is a one-sided likelihood-ratio factor against the least favourable
null endpoint; a bet inside the null interval contributes 1. Its conditional
expectation is at most 1 under every distribution in the envelope.

A dynamic program takes the minimum score over all clean bit paths compatible
with up to k adversarial substitutions of observed bits and any number of
missing observations. Its pathwise lower-envelope property yields the same
anytime null-error guarantee through Ville's inequality, provided the entire
clean data-generating process obeys the conditional envelope.

This code does not infer a causal or conditional-null model from signatures.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Sequence


def _prob(x: float) -> bool:
    return type(x) in (float, int) and math.isfinite(x) and 0 < x < 1


@dataclass(frozen=True)
class ConditionalRow:
    state: str
    low: float
    high: float
    bet_q: float
    after_zero: str
    after_one: str

    def __post_init__(self) -> None:
        if not self.state or not self.after_zero or not self.after_one:
            raise ValueError('state and transitions must be nonempty')
        if not all(_prob(x) for x in (self.low, self.high, self.bet_q)):
            raise ValueError('probability bounds and bet must be strictly inside (0,1)')
        if self.low > self.high:
            raise ValueError('conditional lower bound exceeds upper bound')

    def log_factor(self, clean_bit: int) -> float:
        if type(clean_bit) is not int or clean_bit not in (0, 1):
            raise ValueError('clean bit must be 0 or 1')
        if self.bet_q < self.low:
            p = self.low
        elif self.bet_q > self.high:
            p = self.high
        else:
            return 0.0
        return math.log(self.bet_q / p) if clean_bit else math.log((1-self.bet_q)/(1-p))

    def credal_log_factor(self, clean_bit: int) -> float:
        """Conservative rectangular-credal Bayes factor for this bit.

        The alternative probability is q. The null probability for a
        particular realised bit is maximised separately over the stated
        conditional interval. This treats unknown null parameters as freely
        varying with the full clean history, so the resulting lower Bayes
        factor is robust and can be more conservative than the e-bet.
        """
        if type(clean_bit) is not int or clean_bit not in (0, 1):
            raise ValueError('clean bit must be 0 or 1')
        return (math.log(self.bet_q / self.high) if clean_bit
                else math.log((1-self.bet_q)/(1-self.low)))

    def expected_factor(self, actual_p: float) -> float:
        """Diagnostic for the row's conditional e-validity, not a statistical test."""
        if not _prob(actual_p):
            raise ValueError('invalid actual conditional probability')
        return (actual_p * math.exp(self.log_factor(1))
                + (1-actual_p) * math.exp(self.log_factor(0)))

    def next_state(self, clean_bit: int) -> str:
        if type(clean_bit) is not int or clean_bit not in (0, 1):
            raise ValueError('clean bit must be 0 or 1')
        return self.after_one if clean_bit else self.after_zero

    def canonical(self) -> dict:
        return {'state': self.state, 'low': self.low, 'high': self.high,
                'bet_q': self.bet_q, 'after_zero': self.after_zero,
                'after_one': self.after_one}


@dataclass(frozen=True)
class ConditionalNull:
    initial_state: str
    rows: tuple[ConditionalRow, ...]

    def __post_init__(self) -> None:
        if not self.rows or not self.initial_state:
            raise ValueError('nonempty conditional model required')
        states = [r.state for r in self.rows]
        if len(set(states)) != len(states):
            raise ValueError('duplicate conditional state')
        if self.initial_state not in states:
            raise ValueError('initial state absent from transition table')
        for r in self.rows:
            if r.after_zero not in states or r.after_one not in states:
                raise ValueError('transition refers to nonexistent state')
        # Exclude unreachable states to make precommitted model review simpler.
        reachable = {self.initial_state}
        pending = [self.initial_state]
        indexed = {r.state: r for r in self.rows}
        while pending:
            row = indexed[pending.pop()]
            for state in (row.after_zero, row.after_one):
                if state not in reachable:
                    reachable.add(state)
                    pending.append(state)
        if len(reachable) != len(states):
            raise ValueError('unreachable conditional state')

    @classmethod
    def iid(cls, null_p: float, bet_q: float) -> 'ConditionalNull':
        return cls('iid', (ConditionalRow('iid', null_p, null_p, bet_q, 'iid', 'iid'),))

    @classmethod
    def markov(cls, *, initial: tuple[float, float],
               after_zero: tuple[float, float],
               after_one: tuple[float, float], bet_q: float) -> 'ConditionalNull':
        return cls('start', (
            ConditionalRow('start', *initial, bet_q, 'zero', 'one'),
            ConditionalRow('zero', *after_zero, bet_q, 'zero', 'one'),
            ConditionalRow('one', *after_one, bet_q, 'zero', 'one'),
        ))

    def row(self, state: str) -> ConditionalRow:
        for r in self.rows:
            if r.state == state:
                return r
        raise ValueError('unrecognized conditional state')

    def canonical(self) -> dict:
        return {'version': 1, 'initial_state': self.initial_state,
                'rows': [r.canonical() for r in self.rows]}

    @property
    def commitment(self) -> str:
        raw = json.dumps(self.canonical(), sort_keys=True, separators=(',', ':'),
                         allow_nan=False, ensure_ascii=True).encode('ascii')
        return hashlib.sha256(raw).hexdigest()


def clean_log_e(clean: Sequence[int], model: ConditionalNull) -> float:
    state = model.initial_state
    total = 0.0
    for bit in clean:
        row = model.row(state)
        total += row.log_factor(bit)
        state = row.next_state(bit)
    return total


def _candidate_min_log_prefixes(observed: Sequence[int | None],
                                budget: int, model: ConditionalNull,
                                *, credal: bool) -> tuple[float, ...]:
    """Shared O(n * (k+1) * |states|) reconstruction dynamic program.

    The reconstruction set contains every clean binary path with at most
    `budget` substitutions at *present* observation positions. Erasures
    always admit either clean bit. Scores use the clean path's conditional
    history to choose factors. This avoids calculating adaptive bets from
    adversarially altered observations.
    """
    if type(budget) is not int or budget < 0:
        raise ValueError('budget must be a nonnegative integer')
    # Cache the transition table so DP complexity stays O(n*k*|states|).
    state_rows = {row.state: row for row in model.rows}
    states: dict[tuple[int, str], float] = {(0, model.initial_state): 0.0}
    values: list[float] = []
    for reported in observed:
        if reported is not None and (type(reported) is not int or reported not in (0, 1)):
            raise ValueError('binary bit or explicit erasure required')
        following: dict[tuple[int, str], float] = {}
        for (spent, state), log_score in states.items():
            row = state_rows[state]
            for clean_bit in (0, 1):
                extra = int(reported is not None and clean_bit != reported)
                if spent + extra > budget:
                    continue
                key = (spent + extra, row.next_state(clean_bit))
                score = log_score + (row.credal_log_factor(clean_bit) if credal
                                     else row.log_factor(clean_bit))
                if key not in following or score < following[key]:
                    following[key] = score
        if not following:
            raise AssertionError('reconstruction set unexpectedly empty')
        states = following
        values.append(min(states.values()))
    return tuple(values)


def robust_log_e_prefixes(observed: Sequence[int | None],
                          budget: int, model: ConditionalNull) -> tuple[float, ...]:
    """Exact pathwise lower envelope of the valid conditional e-process."""
    return _candidate_min_log_prefixes(observed, budget, model, credal=False)


def credal_log_e_prefixes(observed: Sequence[int | None],
                          budget: int, model: ConditionalNull) -> tuple[float, ...]:
    """Worst-case Bayes-factor log-score over the rectangular null family.

    Bayes uses prior odds 1:1 and a fixed alternative process q; nuisance
    conditional probabilities vary anywhere in the same null intervals ACE
    has committed to, subject to the same corruption/erasure budget.
    """
    return _candidate_min_log_prefixes(observed, budget, model, credal=True)


def anytime_robust_max_log_e(observed: Sequence[int | None],
                             budget: int, model: ConditionalNull) -> float:
    return max((0.0, *robust_log_e_prefixes(observed, budget, model)))


def compatible(clean: Sequence[int], observed: Sequence[int | None], budget: int) -> bool:
    if len(clean) != len(observed) or type(budget) is not int or budget < 0:
        return False
    if any(type(x) is not int or x not in (0, 1) for x in clean):
        return False
    if any(y is not None and (type(y) is not int or y not in (0, 1)) for y in observed):
        return False
    return sum(x != y for x, y in zip(clean, observed) if y is not None) <= budget


def null_trace_probability(clean: Sequence[int], model: ConditionalNull,
                           *, endpoint: str = 'mid') -> float:
    """A particular Markov distribution inside the null envelope, for benches.

    This distribution is a benchmark fixture, not learned from observation.
    """
    if endpoint not in ('low', 'mid', 'high'):
        raise ValueError('endpoint must be low/mid/high')
    state = model.initial_state
    probability = 1.0
    for bit in clean:
        row = model.row(state)
        p = {'low': row.low, 'mid': (row.low + row.high)/2,
             'high': row.high}[endpoint]
        probability *= p if bit else 1-p
        state = row.next_state(bit)
    return probability
