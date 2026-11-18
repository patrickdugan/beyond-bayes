"""Reproduce BB-CQ-05's complete source-hashed finite posterior-recovery receipt."""
from __future__ import annotations

import argparse
from dataclasses import replace
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
from fractions import Fraction as Q
from hashlib import sha256
import json
from pathlib import Path

from amendment_memory import EvidenceArchive
from bb_cq04_core import coarse_posterior, exact_population
from posterior_recovery import (
    ARMS, N, RECOVERY_TARGET, SCHEMA, apply_checked_delta, disclosure_curve,
    early_count_state, finite_structure_audit, initial_posterior,
    memory_certificate, recovery_posterior,
)
from revocable_bayes import PRIORS, posterior_counts, posterior_full_replay

ROOT = Path(__file__).resolve().parent
SOURCE_FILES = (
    "posterior_recovery.py", "bb_cq05_exact.py", "test_posterior_recovery.py",
    "research/bb_cq05_protocol.md", "research/bb_cq05_mathematics.md",
    "bb_cq04_core.py", "amendment_memory.py", "revocable_bayes.py",
    "continuation_quotient.py",
)
PROTOCOL_COMMIT = "2e605f1d522c130e3f931aa4b552f83c31aad393"


def exact_number(value: Q) -> dict:
    """Readable decimal plus a SHA-256 commitment to the exact rational.

    Hash input is UTF-8 lowercase hexadecimal numerator, '/', denominator,
    without 0x prefixes or a trailing newline. This avoids Python's decimal
    integer string limit for large exact denominators. Decisions use Fraction;
    rounding happens only in the displayed decimal.
    """
    exact = f"{value.numerator:x}/{value.denominator:x}".encode("utf-8")
    with localcontext() as context:
        context.prec = 60
        context.rounding = ROUND_HALF_EVEN
        decimal = format(Decimal(value.numerator) / Decimal(value.denominator), ".15f")
    return {"decimal": decimal, "exact_fraction_sha256": sha256(exact).hexdigest()}


def archive_audit() -> dict:
    """Fixed positive-support fixtures; no scientific roots are sampled."""
    rows = []
    rejections = 0
    transitions = 0
    for j in ARMS:
        old = tuple(i % 2 for i in range(N))
        chosen = tuple(range(j))
        new = tuple(int(i % 3 == 0) for i in chosen)
        archive = EvidenceArchive(old, (0,) * N)
        count, pin = archive.count, archive.digest
        early = early_count_state(old, chosen)
        # Replay the eligible old reports with a separately implemented raw
        # known-label/report likelihood before starting the acceptance stream.
        eligible = tuple((1, bit) for i, bit in enumerate(old) if i not in chosen)
        if early.posterior != posterior_full_replay(eligible):
            raise AssertionError("early baseline was not calibrated at initialization")
        for slot, bit in zip(chosen, new):
            after, delta = archive.change(slot, bit)
            attempts = (
                (count, pin, archive, after, replace(delta, old_match=1-delta.old_match)),
                (count, "0" * 64, archive, after, delta),
                (count, pin, archive, archive, delta),
                (count, pin, archive, after, replace(delta, new_version=True)),
            )
            for args in attempts:
                try:
                    apply_checked_delta(*args)
                except ValueError:
                    rejections += 1
                else:
                    raise AssertionError("malformed archive transition was accepted")
            count, pin = apply_checked_delta(count, pin, archive, after, delta)
            try:
                apply_checked_delta(count, pin, after, after, delta)
            except ValueError:
                rejections += 1
            else:
                raise AssertionError("replayed archive delta was accepted")
            archive = after
            early = early.accept(bit)
            eligible += ((1, bit),)
            if early.posterior != posterior_full_replay(eligible):
                raise AssertionError("early count update and full replay disagree")
            transitions += 1
        final = posterior_full_replay(tuple((1, bit) for bit in archive.matches))
        v, q = sum(old[i] for i in chosen), sum(new)
        from_message = posterior_counts(sum(old) - v + q, N)
        if final != early.posterior or final != posterior_counts(count, N) or final != from_message:
            raise AssertionError("count summary, early count, verified delta and replay differ")
        rows.append({"j": j, "initial_old_count": sum(old), "old_corrected_count": v,
                     "new_count": q, "final_count": count,
                     "full_early_delta_summary_parity": True})
    return {"fixtures": rows, "checked_transitions": transitions,
            "rejected_malformed_or_replayed_transitions": rejections,
            "authentication": "external premise; local archive consistency fixture"}


def run() -> dict:
    curves = {j: disclosure_curve(j) for j in ARMS}
    cq04_checks = 0
    for j, curve in curves.items():
        prior_result = exact_population(j)
        if (curve[0]["full_brier"] != prior_result["regime_brier"]["fine"]
                or curve[0]["recovery_brier"] != prior_result["regime_brier"]["coarse"]
                or curve[0]["regret"] != prior_result["squared_l2_fine_coarse"]):
            raise AssertionError("CQ04 exact rational endpoint failed to reproduce")
        for m in range(N + 1):
            for q in range(j + 1):
                if recovery_posterior(m, q, 0, 0, j) != coarse_posterior(m, q, j):
                    raise AssertionError("CQ04 coarse posterior changed")
                cq04_checks += 1
    primary = next(point["revealed"] for point in curves[6]
                   if point["recovery_fraction"] >= RECOVERY_TARGET)
    initial_labels = {str(j): len({initial_posterior(m, j) for m in range(N + 1)})
                      for j in range(1, N)}
    if any(count != N + 1 for count in initial_labels.values()):
        raise AssertionError("registered initial posterior count injectivity failed")
    prior_brier = 1 - sum((p*p for p in PRIORS), Q(0))
    return {
        "schema": SCHEMA,
        "status": "EXACT_DISCLOSURE_CHARACTERIZED",
        "evidence_status": "finite mathematical development; Brier endpoint motivated by CQ04",
        "protocol_commit": PROTOCOL_COMMIT,
        "source_file_sha256": {path: sha256((ROOT / path).read_bytes()).hexdigest()
                               for path in SOURCE_FILES},
        "numeric_encoding": {
            "computation": "exact Fraction arithmetic",
            "decimal": "15 places, Decimal precision 60, presentation only",
            "exact_fraction_sha256": "UTF-8 lowercase hex numerator/denominator, no prefixes or newline",
        },
        "n": N,
        "arms": list(ARMS),
        "primary_summary": {
            "j": 6, "target_recovery_fraction": "9/10",
            "minimum_individual_old_values_revealed": primary,
            "scope": "fixed outcome-independent old-bit disclosure family",
            "optimal_communication_claim": False,
        },
        "prior_brier": exact_number(prior_brier),
        "curves": {str(j): [{
            "revealed": point["revealed"],
            **{name: exact_number(point[name]) for name in
               ("mass", "full_brier", "recovery_brier", "regret", "squared_gap", "recovery_fraction")},
        } for point in curve] for j, curve in curves.items()},
        "early_schedule_full_brier": exact_number(curves[6][-1]["full_brier"]),
        "early_schedule_excess_brier": exact_number(Q(0)),
        "cq04_exact_rational_endpoints_preserved": True,
        "cq04_coarse_posterior_cells_compared": cq04_checks,
        "cq04_authorization_verdict": "HEADROOM_BLOCKED",
        "initial_posterior_labels_by_j": initial_labels,
        "memory_contracts": {str(j): memory_certificate(j) for j in ARMS},
        "small_domain_structure": finite_structure_audit(),
        "archive_fixture": archive_audit(),
        "new_scientific_roots": 0,
        "neural_weights_loaded": False,
        "neural_mechanism_tested": False,
        "authorizes_action": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output", type=Path)
    group.add_argument("--check", type=Path)
    args = parser.parse_args()
    payload = json.dumps(run(), indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        print(f"Wrote BB-CQ-05 exact receipt: {args.output}")
    elif args.check.read_text(encoding="utf-8") != payload:
        raise SystemExit("FAIL: BB-CQ-05 registered exact receipt differs")
    else:
        print("PASS: BB-CQ-05 exact receipt replay")


if __name__ == "__main__":
    main()
