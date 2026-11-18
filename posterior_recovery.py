"""BB-CQ-05: calibrated posterior recovery with explicit disclosure timing.

Exact finite ECA-04 Bayesian calculations. A hidden, outcome-independent set
of old reports contains fair provisional bits. The early-schedule count
baseline and delayed-schedule recovery family have different information.
Archive checking below is a local structural fixture; authentication and
acquisition assumptions remain external.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction as Q
from functools import lru_cache
from itertools import combinations
from math import comb

from amendment_memory import (
    EvidenceArchive, EvidenceDelta, apply_externally_verified_delta,
    verify_archive_delta,
)
from revocable_bayes import MATCH_PROBS, PRIORS, posterior_counts

SCHEMA = "ace-bb-cq05-posterior-recovery-v1"
N = 12
ARMS = (1, 3, 6)
RECOVERY_TARGET = Q(9, 10)


def _integer(value: int, low: int, high: int) -> None:
    if type(value) is not int or not low <= value <= high:
        raise ValueError("integer outside the declared finite domain")


def _domain(j: int, n: int) -> None:
    _integer(n, 1, N)
    _integer(j, 0, n)


@lru_cache(maxsize=None)
def _binomial(n: int, count: int, p: Q) -> Q:
    if not 0 <= count <= n:
        return Q(0)
    return comb(n, count) * p ** count * (1 - p) ** (n - count)


def _normalize(weights: tuple[Q, ...]) -> tuple[Q, ...]:
    mass = sum(weights, Q(0))
    if mass <= 0:
        raise ValueError("impossible evidence message")
    return tuple(weight / mass for weight in weights)


@lru_cache(maxsize=None)
def _mixed_count_likelihood(count: int, valid: int, fair: int, t: Q) -> Q:
    return sum((_binomial(valid, u, t) * _binomial(fair, count - u, Q(1, 2))
                for u in range(valid + 1)), Q(0))


@lru_cache(maxsize=None, typed=True)
def initial_posterior(old_m: int, j: int, n: int = N) -> tuple[Q, ...]:
    """Pr(K | old vector) when the uniformly hidden j-subset is undisclosed.

    Exchangeability makes the count sufficient for the present regime. For a
    particular vector with that count, the count likelihood has an additional
    common divisor C(n, old_m), which cancels during normalization.
    """
    _domain(j, n)
    _integer(old_m, 0, n)
    return _normalize(tuple(
        prior * _mixed_count_likelihood(old_m, n - j, j, t)
        for prior, t in zip(PRIORS, MATCH_PROBS)))


@lru_cache(maxsize=None, typed=True)
def recovery_posterior(old_m: int, new_q: int, old_s: int, revealed: int,
                       j: int, n: int = N) -> tuple[Q, ...]:
    """Optimal posterior given the mixed count and fixed-prefix old disclosures.

    At correction time all new reports are available. The first `revealed`
    old bits from an outcome-independent order of corrected slots have sum
    `old_s`. Remaining uncertainty is in the `j-revealed` hidden fair bits.
    """
    _domain(j, n)
    _integer(revealed, 0, j)
    _integer(old_m, 0, n)
    _integer(new_q, 0, j)
    _integer(old_s, 0, revealed)
    residual = old_m - old_s
    if not 0 <= residual <= n - revealed:
        raise ValueError("revealed old values incompatible with the old count")
    return _normalize(tuple(
        prior * _binomial(j, new_q, t)
        * _mixed_count_likelihood(residual, n - j, j - revealed, t)
        for prior, t in zip(PRIORS, MATCH_PROBS)))


@dataclass(frozen=True)
class CalibratedCount:
    """Sufficient numeric state for conditionally iid accepted observations.

    The public protocol supplies eligibility, event identity, and step count.
    This object does not enforce event uniqueness or verify a report's source.
    """
    matches: int
    total: int

    def __post_init__(self) -> None:
        _integer(self.total, 0, N)
        _integer(self.matches, 0, self.total)

    @property
    def posterior(self) -> tuple[Q, ...]:
        return posterior_counts(self.matches, self.total)

    def accept(self, bit: int) -> CalibratedCount:
        _integer(bit, 0, 1)
        return CalibratedCount(self.matches + bit, self.total + 1)


def early_count_state(old_bits: tuple[int, ...],
                      correction_slots: tuple[int, ...]) -> CalibratedCount:
    """Encode after the replacement set has been disclosed."""
    if type(old_bits) is not tuple or type(correction_slots) is not tuple:
        raise ValueError("immutable tuples required")
    _integer(len(old_bits), 1, N)
    for bit in old_bits:
        _integer(bit, 0, 1)
    for slot in correction_slots:
        _integer(slot, 0, len(old_bits) - 1)
    if len(set(correction_slots)) != len(correction_slots):
        raise ValueError("duplicate corrected slot")
    chosen = set(correction_slots)
    valid = tuple(bit for i, bit in enumerate(old_bits) if i not in chosen)
    return CalibratedCount(sum(valid), len(valid))


def apply_checked_delta(count: int, pin: str, before: EvidenceArchive,
                        after: EvidenceArchive,
                        delta: EvidenceDelta) -> tuple[int, str]:
    """Full-archive fixture gate before invoking the numeric-only updater.

    The caller must supply authoritative, fresh archive snapshots. This local
    check proves a consistent transition under those assumptions; the digest
    supplies neither source authentication nor evidence of physical truth.
    """
    if type(before) is not EvidenceArchive or type(after) is not EvidenceArchive:
        raise ValueError("typed before and after archives required")
    _integer(count, 0, len(before.matches))
    if type(pin) is not str or pin != before.digest or count != before.count:
        raise ValueError("numeric state differs from the pinned archive")
    if type(delta) is not EvidenceDelta:
        raise ValueError("typed evidence delta required")
    for value in (delta.old_match, delta.new_match):
        _integer(value, 0, 1)
    _integer(delta.slot, 0, len(before.matches) - 1)
    _integer(delta.old_version, 0, 2**31 - 2)
    _integer(delta.new_version, 1, 2**31 - 1)
    if any(type(digest) is not str for digest in
           (delta.old_archive_digest, delta.new_archive_digest)):
        raise ValueError("archive digests must be strings")
    if not verify_archive_delta(before, after, delta):
        raise ValueError("full archive transition verification failed")
    # The inherited numeric updater additionally checks the predecessor pin
    # and successor-version relation. Strict field types are enforced above.
    result = apply_externally_verified_delta(count, delta, pin, len(before.matches))
    if result != (after.count, after.digest):
        raise AssertionError("checked archive and numeric successor disagree")
    return result


def _squared_distance(left: tuple[Q, ...], right: tuple[Q, ...]) -> Q:
    return sum(((a - b) ** 2 for a, b in zip(left, right)), Q(0))


def population_point(j: int, revealed: int, n: int = N) -> dict:
    """Integrate K,U,S_r,W,Q exactly, including every disclosed old value.

    This evaluates the full joint distribution. It does not score on samples,
    round intermediate calculations, or treat counts as independent units.
    """
    _domain(j, n)
    _integer(revealed, 0, j)
    mass = Q(0)
    full_brier = Q(0)
    recovery_brier = Q(0)
    squared_gap = Q(0)
    # Regime-conditioned sufficient cells are cached by (u,w,q). All possible
    # revealed fair counts s are still explicitly weighted below.
    for k, (prior, t) in enumerate(zip(PRIORS, MATCH_PROBS)):
        truth = tuple(Q(int(i == k)) for i in range(len(PRIORS)))
        for u in range(n - j + 1):
            for w in range(j - revealed + 1):
                for q in range(j + 1):
                    base_mass = (prior * _binomial(n - j, u, t)
                                 * _binomial(j - revealed, w, Q(1, 2))
                                 * _binomial(j, q, t))
                    fine = posterior_counts(u + q, n)
                    recovered = recovery_posterior(u + w, q, 0, revealed, j, n)
                    fine_loss = _squared_distance(fine, truth)
                    recovered_loss = _squared_distance(recovered, truth)
                    gap = _squared_distance(fine, recovered)
                    for s in range(revealed + 1):
                        joint = base_mass * _binomial(revealed, s, Q(1, 2))
                        # The following equality also audits the canceled
                        # common factor for every reachable disclosure count.
                        if recovery_posterior(u + s + w, q, s, revealed, j, n) != recovered:
                            raise AssertionError("revealed-count cancellation failed")
                        mass += joint
                        full_brier += joint * fine_loss
                        recovery_brier += joint * recovered_loss
                        squared_gap += joint * gap
    regret = recovery_brier - full_brier
    if mass != 1 or regret != squared_gap or regret < 0:
        raise AssertionError("probability or Brier conditional-expectation identity failed")
    if revealed == j and regret != 0:
        raise AssertionError("complete old-value disclosure failed to recover full Bayes")
    return {"mass": mass, "full_brier": full_brier,
            "recovery_brier": recovery_brier, "regret": regret,
            "squared_gap": squared_gap}


def disclosure_curve(j: int, n: int = N) -> list[dict]:
    """All fixed old-bit reveal budgets; this is not an optimal bit-rate curve."""
    _domain(j, n)
    points = [dict(population_point(j, r, n), revealed=r) for r in range(j + 1)]
    coarse_gap = points[0]["regret"]
    for point in points:
        point["recovery_fraction"] = (1 - point["regret"] / coarse_gap
                                      if coarse_gap else None)
    if any(a["regret"] < b["regret"] for a, b in zip(points, points[1:])):
        raise AssertionError("nested information increased population Bayes risk")
    return points


def correction_witness(left_mask: int, right_mask: int, j: int,
                       n: int = N) -> tuple[int, ...]:
    """A correcting j-subset distinguishing two different same-count vectors.

    Choose opposite-sign difference positions a,b. Two candidate subsets
    consist of a common (j-1)-set and either a or b. Their difference sums
    differ by two, so at least one is nonzero. Identical replacement values
    then produce different final counts.
    """
    _domain(j, n)
    if not 1 <= j < n:
        raise ValueError("a proper nonempty correction subset is required")
    _integer(left_mask, 0, (1 << n) - 1)
    _integer(right_mask, 0, (1 << n) - 1)
    if left_mask == right_mask or left_mask.bit_count() != right_mask.bit_count():
        raise ValueError("distinct same-count histories are required")
    difference = tuple(((left_mask >> i) & 1) - ((right_mask >> i) & 1)
                       for i in range(n))
    a, b = difference.index(1), difference.index(-1)
    common = tuple(i for i in range(n) if i not in (a, b))[:j - 1]
    candidate = common + (a,)
    if sum(difference[i] for i in candidate) == 0:
        candidate = common + (b,)
    if sum(difference[i] for i in candidate) == 0:
        raise AssertionError("constructive correction witness failed")
    return tuple(sorted(candidate))


def memory_certificate(j: int, n: int = N) -> dict:
    """Finite-parameter count-label check and constructive worst-case bounds.

    The proof applies to delayed schedule disclosure and every legal future
    correction. Numeric count and message bit counts exclude public metadata,
    archive storage, pins, source verification and arithmetic precision.
    """
    _domain(j, n)
    if not 1 <= j < n:
        raise ValueError("a proper nonempty correction subset is required")
    initial_labels = tuple(initial_posterior(m, j, n) for m in range(n + 1))
    if len(set(initial_labels)) != n + 1:
        raise AssertionError("initial count posterior labels are not injective")
    if len({posterior_counts(m, n) for m in range(n + 1)}) != n + 1:
        raise AssertionError("final count posterior labels are not injective")
    biggest_fiber = max(comb(n, m) for m in range(n + 1))
    return {
        "n": n, "j": j, "initial_histories": 1 << n,
        "initial_posterior_count": len(set(initial_labels)),
        "max_same_posterior_histories": biggest_fiber,
        "minimum_total_bits": n,
        "extra_fixed_tag_bits_given_current_posterior": (biggest_fiber - 1).bit_length(),
        "early_initial_count_states": n - j + 1,
        "early_max_count_states": n + 1,
        "early_max_count_bits": n.bit_length(),
        "old_total_message_values": j + 1,
        "old_total_message_bits": j.bit_length(),
    }


def finite_structure_audit(max_n: int = 6) -> dict:
    """Independent all-subset output signatures plus constructive pair witnesses.

    A corrected stream with q=0 already distinguishes the stored histories.
    Current count labels are included in the signature. This audit enumerates
    small domains; the general n-bit claim uses the proof in the research note.
    """
    _integer(max_n, 2, 7)
    cases = []
    pair_checks = 0
    for n in range(2, max_n + 1):
        masks = tuple(range(1 << n))
        for j in range(1, n):
            subsets = tuple(combinations(range(n), j))
            signatures = {
                (mask.bit_count(), tuple(
                    sum((mask >> i) & 1 for i in range(n) if i not in chosen)
                    for chosen in subsets)) for mask in masks}
            if len(signatures) != 1 << n:
                raise AssertionError("independent continuation signatures collided")
            for left, right in combinations(masks, 2):
                if left.bit_count() != right.bit_count():
                    continue
                chosen = correction_witness(left, right, j, n)
                a = sum((left >> i) & 1 for i in range(n) if i not in chosen)
                b = sum((right >> i) & 1 for i in range(n) if i not in chosen)
                if a == b:
                    raise AssertionError("same-count correction witness did not distinguish")
                pair_checks += 1
            cert = memory_certificate(j, n)
            cases.append({"n": n, "j": j, "continuation_classes": len(signatures),
                          "initial_posterior_labels": cert["initial_posterior_count"]})
    return {"maximum_n": max_n, "cases": cases,
            "same_count_pair_witness_checks": pair_checks}
