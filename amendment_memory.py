"""BB-CQ-03: finite evidence amendments and the memory carried by an archive.

Research-only exact arithmetic for the ORIGINAL twelve-sentinel ECA-04
complementary-channel likelihood. A report amendment is a stipulated change
to a fixed historical record. Recomputed likelihoods describe the revised
data contract, not a causal posterior given an adaptively chosen amendment.

The authenticated-archive boundary is EXTERNAL. Digests provide only
integrity commitments; no trusted timestamps, quorum, real signatures,
admission ordering or action authority are implemented here.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from fractions import Fraction as Q
from hashlib import sha256
import json
from math import comb

from revocable_bayes import MATCH_PROBS, PRIORS, posterior_counts

SCHEMA = "ace-bb-cq03-amendment-v1"
DEFAULT_SLOTS = 12


def _int(value: int, lower: int, upper: int) -> None:
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError("out-of-range integer (bool is not accepted)")


def overwrite_match(mask: int, slot: int, new_match: int, slots: int = DEFAULT_SLOTS) -> int:
    """Change the named record's *match status* without changing other slots."""
    _int(slots, 1, 12)
    _int(mask, 0, (1 << slots) - 1)
    _int(slot, 0, slots - 1)
    _int(new_match, 0, 1)
    return (mask & ~(1 << slot)) | (new_match << slot)


def corrected_count(count: int, old_match: int, new_match: int, slots: int = DEFAULT_SLOTS) -> int:
    """Count update after an EXTERNALLY VERIFIED old/new evidence change."""
    _int(slots, 1, 12)
    _int(count, 0, slots)
    _int(old_match, 0, 1)
    _int(new_match, 0, 1)
    result = count - old_match + new_match
    if not 0 <= result <= slots:
        raise ValueError("old-match claim inconsistent with aggregate count")
    return result


def source_aware_revised_posterior(mask: int, slot: int, new_match: int,
                                   slots: int = DEFAULT_SLOTS) -> tuple[Q, Q, Q]:
    revised = overwrite_match(mask, slot, new_match, slots)
    return posterior_counts(revised.bit_count(), slots)


def count_mass(count: int, slots: int = DEFAULT_SLOTS) -> Q:
    """Original pre-amendment IID mixture probability P(M=count)."""
    _int(slots, 1, 12)
    _int(count, 0, slots)
    return Q(comb(slots, count)) * sum(
        (p * t ** count * (1 - t) ** (slots - count)
         for p, t in zip(PRIORS, MATCH_PROBS)), Q(0))


def aggregate_only_optimum(count: int, new_match: int,
                           slots: int = DEFAULT_SLOTS) -> dict:
    """Sharp conditional squared-L2 loss for reconstructing the revised posterior.

    Condition on observed aggregate M=count under the *original* IID mixture,
    choose a fixed named slot, then externally force its status to new_match.
    The original slot is a match with probability count/slots by exchangeable
    symmetry, even after marginalizing the latent issuer regime.

    The response is the revised-data posterior under a hypothetical overwrite.
    The count-only observer lacks the old slot value, so its optimal prediction
    is the mixture of the two possible revised posteriors. The minimum expected
    squared L2 risk is w*(1-w)*||P_old1-P_old0||^2. All quantities are rational.
    """
    _int(slots, 1, 12)
    _int(count, 0, slots)
    _int(new_match, 0, 1)
    w = Q(count, slots)
    posterior_old0 = (posterior_counts(count + new_match, slots)
                      if count < slots else None)
    posterior_old1 = (posterior_counts(count - 1 + new_match, slots)
                      if count > 0 else None)
    if posterior_old0 is None:
        midpoint = posterior_old1
        loss = Q(0)
    elif posterior_old1 is None:
        midpoint = posterior_old0
        loss = Q(0)
    else:
        midpoint = tuple((1 - w) * a + w * b
                         for a, b in zip(posterior_old0, posterior_old1))
        loss = w * (1 - w) * sum(
            ((a - b) ** 2 for a, b in zip(posterior_old0, posterior_old1)), Q(0))
    return {
        "count": count, "new_match": new_match, "old_match_probability": w,
        "optimal_aggregate_only_posterior": midpoint,
        "squared_l2_error_floor": loss,
    }


def expected_aggregate_only_error(slots: int = DEFAULT_SLOTS) -> Q:
    """Sharp *design-weighted* posterior imitation floor for a fixed slot.

    Draw original IID reports from the ECA-04 mixture, then choose new_match
    independently with probability 1/2. Only the original M and new value are
    revealed to the compressed observer. With one replaced slot, this is the
    least achievable expected squared-L2 error against the revised-data
    posterior, under the declared original-data/intervention design.
    """
    _int(slots, 1, 12)
    return sum(
        (count_mass(m, slots) * Q(1, 2) *
         aggregate_only_optimum(m, c, slots)["squared_l2_error_floor"]
         for m in range(slots + 1) for c in (0, 1)), Q(0))


def amendment_memory(slots: int = DEFAULT_SLOTS) -> dict:
    """Exact fixed-width bounds for self-contained blind slot amendments."""
    _int(slots, 1, 12)
    biggest_fiber = max(comb(slots, m) for m in range(slots + 1))
    return {
        "slots": slots,
        "initial_histories": 1 << slots,
        "current_posterior_count": slots + 1,
        "max_same_posterior_histories": biggest_fiber,
        "minimum_total_bits": slots,
        "extra_fixed_tag_bits_given_current_posterior": (biggest_fiber - 1).bit_length(),
    }


@dataclass(frozen=True)
class EvidenceDelta:
    """Untrusted until an external archive verifier authenticates the full change."""
    slot: int
    old_match: int
    new_match: int
    old_version: int
    new_version: int
    old_archive_digest: str
    new_archive_digest: str


@dataclass(frozen=True)
class EvidenceArchive:
    """Small local demo archive carrying the memory excluded from m alone."""
    matches: tuple[int, ...]
    versions: tuple[int, ...]

    def __post_init__(self) -> None:
        if (type(self.matches) is not tuple or type(self.versions) is not tuple
                or not 1 <= len(self.matches) <= 12
                or len(self.versions) != len(self.matches)):
            raise ValueError("invalid archive shape")
        for v in self.matches:
            _int(v, 0, 1)
        for v in self.versions:
            _int(v, 0, 2**31 - 1)

    @property
    def digest(self) -> str:
        raw = json.dumps({"schema": SCHEMA, "matches": self.matches,
                          "versions": self.versions},
                         sort_keys=True, separators=(",", ":")).encode()
        return sha256(raw).hexdigest()

    @property
    def count(self) -> int:
        return sum(self.matches)

    def change(self, slot: int, new_match: int) -> tuple[EvidenceArchive, EvidenceDelta]:
        _int(slot, 0, len(self.matches) - 1)
        _int(new_match, 0, 1)
        old_match = self.matches[slot]
        previous = self.versions[slot]
        if previous >= 2**31 - 1:
            raise ValueError("version counter exhausted")
        updated_matches = list(self.matches)
        updated_versions = list(self.versions)
        updated_matches[slot] = new_match
        updated_versions[slot] = previous + 1
        new_archive = EvidenceArchive(tuple(updated_matches), tuple(updated_versions))
        delta = EvidenceDelta(slot, old_match, new_match, previous, previous + 1,
                              self.digest, new_archive.digest)
        return new_archive, delta


def verify_archive_delta(before: EvidenceArchive, after: EvidenceArchive,
                         claimed: EvidenceDelta) -> bool:
    """Full archive replay validation. A digest by itself cannot do this."""
    if not isinstance(claimed, EvidenceDelta):
        return False
    try:
        expected_after, expected = before.change(claimed.slot, claimed.new_match)
    except (ValueError, TypeError):
        return False
    return after == expected_after and claimed == expected


def apply_externally_verified_delta(count: int, delta: EvidenceDelta,
                                    pinned_old_digest: str, slots: int = DEFAULT_SLOTS) -> tuple[int, str]:
    """Numeric-only update after an independent trusted verifier accepted delta.

    Checking two digests and a version relation here is NOT authentication:
    this function deliberately has no access to stored old slot values. The
    caller must have independently checked verify_archive_delta against the
    authoritative archive and established its current external head.
    """
    if not isinstance(delta, EvidenceDelta):
        raise ValueError("typed external delta required")
    _int(delta.slot, 0, slots - 1)
    if delta.old_archive_digest != pinned_old_digest:
        raise ValueError("stale archive-head pin")
    _int(delta.old_version, 0, 2**31 - 2)
    if delta.new_version != delta.old_version + 1:
        raise ValueError("non-successor version claim")
    return corrected_count(count, delta.old_match, delta.new_match, slots), delta.new_archive_digest
