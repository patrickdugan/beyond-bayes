"""Bounded-contamination, anytime-valid evidence envelopes.

The sample space contains distinct *verified* observation roots.  An
arbitrary adversary may replace up to k binary root observations over the
entire run.  On each prefix E_rob is the minimum simple-null e-process value
among all hypothetical clean prefixes within Hamming distance k.

Pathwise domination E_rob_t(observed) <= E_t(clean) supplies the optional-
stopping guarantee from Ville's inequality whenever clean observations
obey the specified simple conditional null distribution and q is fixed in
advance.  Contamination can be adaptive or clairvoyant, subject to the
Hamming-budget bound; clean observations themselves are iid Bernoulli(p).

A certified observation root is an assumption, not inferred from report IDs.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
from itertools import combinations, product
from typing import Iterable, Sequence


def _validate_prob(p: float) -> None:
    if not (0 < p < 1) or not math.isfinite(p):
        raise ValueError("p and q must be finite in (0,1)")


def simple_log_e(outcomes: Iterable[int], null_p: float, bet_q: float) -> float:
    _validate_prob(null_p)
    _validate_prob(bet_q)
    up = math.log(bet_q / null_p)
    down = math.log((1 - bet_q) / (1 - null_p))
    total = 0.0
    for bit in outcomes:
        if bit not in (0, 1):
            raise ValueError("binary observations required")
        total += up if bit else down
    return total


def robust_log_e(ones: int, total: int, k: int, null_p: float, bet_q: float) -> float:
    """Exact lower log-e envelope among all clean prefixes <=k flips away.

    With a fixed bet, the evidence is affine in the number of 1's.  So an
    extremal clean sequence is obtained by flipping up to k observed bits
    in whichever direction lowers the e-process.
    """
    if not (isinstance(total, int) and isinstance(ones, int) and isinstance(k, int)):
        raise ValueError("counts and budget must be integers")
    if total < 0 or ones < 0 or ones > total or k < 0:
        raise ValueError("invalid counts or budget")
    _validate_prob(null_p)
    _validate_prob(bet_q)
    incr_one = math.log(bet_q / null_p)
    incr_zero = math.log((1 - bet_q) / (1 - null_p))
    if incr_one > incr_zero:
        least_ones = max(0, ones - k)
    else:
        least_ones = min(total, ones + k)
    return least_ones * incr_one + (total - least_ones) * incr_zero


def robust_log_e_from_counts(
    ones: int, zeros: int, missing: int, k: int, null_p: float, bet_q: float
) -> float:
    """O(1) exact contaminated-and-erased Bernoulli lower log-e envelope."""
    if any(type(c) is not int or c < 0 for c in (ones, zeros, missing, k)):
        raise ValueError('counts and budget must be nonnegative integers')
    _validate_prob(null_p)
    _validate_prob(bet_q)
    up = math.log(bet_q / null_p)
    down = math.log((1 - bet_q) / (1 - null_p))
    if up > down:
        minimum_ones = max(0, ones - k)
    else:
        minimum_ones = ones + missing + min(zeros, k)
    n = ones + zeros + missing
    return minimum_ones * up + (n - minimum_ones) * down


def robust_log_e_with_erasures(
    observations: Sequence[int | None], k: int, null_p: float, bet_q: float
) -> float:
    """Exact lower envelope under <=k substitutions plus arbitrary erasures.

    Missing positions remain part of the precommitted schedule. This bound
    remains pathwise <= clean e-process when every present bit differs
    from its clean value on at most k slots, with no restriction on erasures.

    For q>p the least favorable completion sets all missing bits to 0 and
    replaces up to k observed 1s with 0s. For q<p it makes missing bits 1
    and changes up to k observed 0s into 1s. O(t) counting.
    """
    ones = zeros = missing = 0
    for bit in observations:
        if bit is None:
            missing += 1
        elif type(bit) is int and bit == 1:
            ones += 1
        elif type(bit) is int and bit == 0:
            zeros += 1
        else:
            raise ValueError('observations must be 0, 1, or None')
    return robust_log_e_from_counts(ones, zeros, missing, k, null_p, bet_q)


@dataclass
class RobustBernoulliEProcess:
    """Anytime test against a simple iid Bernoulli null, robust to <=k flips."""

    null_p: float
    bet_q: float
    budget: int
    alpha: float = .05

    def __post_init__(self):
        _validate_prob(self.null_p)
        _validate_prob(self.bet_q)
        if not (0 < self.alpha < 1) or not math.isfinite(self.alpha):
            raise ValueError("alpha must be in (0,1)")
        if type(self.budget) is not int or self.budget < 0:
            raise ValueError("budget must be a nonnegative integer")
        self.total = 0
        self.ones = 0
        self.max_log_e = 0.0

    def observe(self, bit: int) -> None:
        if bit not in (0, 1):
            raise ValueError("binary observations required")
        self.total += 1
        self.ones += bit
        self.max_log_e = max(self.max_log_e, self.log_e)

    @property
    def log_e(self) -> float:
        return robust_log_e(self.ones, self.total, self.budget, self.null_p, self.bet_q)

    @property
    def rejected(self) -> bool:
        return self.max_log_e >= math.log(1 / self.alpha)


def live_binary_models(
    observations: Sequence[int], k: int, alpha: float = .05,
    p_safe: float = .2, p_risky: float = .8
) -> tuple[tuple[str, ...], dict[str, RobustBernoulliEProcess]]:
    tests = {
        "safe": RobustBernoulliEProcess(p_safe, p_risky, k, alpha),
        "risky": RobustBernoulliEProcess(p_risky, p_safe, k, alpha),
    }
    for bit in observations:
        for test in tests.values():
            test.observe(bit)
    live = tuple(name for name, test in tests.items() if not test.rejected)
    return live, tests


def hamming(a: Sequence[int], b: Sequence[int]) -> int:
    if len(a) != len(b):
        raise ValueError("different lengths")
    return sum(x != y for x, y in zip(a, b))


def exact_worst_case_false_exclusion(
    n: int, k: int, p: float, q: float, alpha: float = .05
) -> float:
    """Enumerate clean sequences and *all possible attacks* of <=k flips.

    An event counts as a false exclusion when some adversarially selected
    observed sequence can cross the robust threshold on any prefix. The
    attacker may observe the entire clean sequence before choosing the flips.
    Exhaustive enumeration is exponential; intended for n<=12.
    """
    if n < 0 or n > 12 or k < 0:
        raise ValueError("exact enumeration is limited to 0<=n<=12")
    threshold = math.log(1 / alpha)
    total_prob = 0.0
    for clean in product((0, 1), repeat=n):
        seen_crossing = False
        for corrupted_count in range(min(k, n) + 1):
            if seen_crossing:
                break
            for indices in combinations(range(n), corrupted_count):
                attack = set(indices)
                ones = 0
                for t, x in enumerate(clean, start=1):
                    ones += 1 - x if (t - 1) in attack else x
                    if robust_log_e(ones, t, k, p, q) >= threshold - 1e-12:
                        seen_crossing = True
                        break
                if seen_crossing:
                    break
        if seen_crossing:
            heads = sum(clean)
            total_prob += p ** heads * (1 - p) ** (n - heads)
    return total_prob
