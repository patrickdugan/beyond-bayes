"""Sharp finite-population bounds when adverse audit traces may be omitted.

This diagnostic requires an independently fixed universe of expected receipt
IDs. Its finite-population result makes no missing-at-random assumption and is
independent of signed witness and sequential-inference error guarantees.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha256
import json
from typing import Iterable, Mapping


@dataclass(frozen=True)
class AuditCoverageBound:
    universe_hash: str
    total: int
    reviewed: int
    omitted: int
    observed_adverse: int
    lower: Fraction
    upper: Fraction

    @property
    def coverage(self) -> Fraction:
        return Fraction(self.reviewed, self.total)

    def certifies_at_most(self, budget: Fraction | int | str) -> bool:
        """True only if every possible assignment to omitted traces passes."""
        if isinstance(budget, bool) or isinstance(budget, float):
            raise TypeError("use Fraction/int/decimal string for an exact risk budget")
        threshold = Fraction(budget)
        if not 0 <= threshold <= 1:
            raise ValueError("budget must lie in [0,1]")
        return self.upper <= threshold


def bound_omitted_traces(
    expected_ids: Iterable[str], reviewed: Mapping[str, bool],
) -> AuditCoverageBound:
    """Compute sharp identified bounds on the adverse fraction.

    expected_ids MUST be fixed and independently attested before reviewing;
    otherwise suppression of the event inventory itself evades this test.
    reviewed[id]=True records an independently adjudicated adverse trace.
    All unreviewed events remain adversarially free to be adverse.
    """
    ids = tuple(expected_ids)
    if not ids or any(not isinstance(i, str) or not i.strip() for i in ids):
        raise ValueError("expected_ids must be nonempty, nonblank strings")
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate expected receipt ID")
    if not isinstance(reviewed, Mapping):
        raise TypeError("reviewed must be a mapping")
    universe = set(ids)
    if not set(reviewed).issubset(universe):
        raise ValueError("reviewed includes an ID outside the sealed universe")
    if any(type(v) is not bool for v in reviewed.values()):
        raise TypeError("every reviewed verdict must be a bool")
    n = len(ids)
    adverse = sum(reviewed.values())
    unseen = n - len(reviewed)
    # IDs are sorted only for deterministic hashing; collision resistance
    # cannot substitute for a trusted and independently anchored inventory.
    payload = json.dumps(["audit-universe-v1", *sorted(ids)], ensure_ascii=False,
                         separators=(",", ":")).encode("utf-8")
    return AuditCoverageBound(
        universe_hash=sha256(payload).hexdigest(),
        total=n, reviewed=len(reviewed), omitted=unseen,
        observed_adverse=adverse,
        lower=Fraction(adverse, n), upper=Fraction(adverse + unseen, n),
    )
