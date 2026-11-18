"""BB-CQ-03 exact finite development receipt with independent bitmask checks.

Does not load model checkpoints, sample research roots, or authorize actions.
"""
from __future__ import annotations

import argparse
from itertools import combinations
from math import comb
import json
from pathlib import Path

from amendment_memory import (
    amendment_memory, aggregate_only_optimum, expected_aggregate_only_error,
    overwrite_match, corrected_count,
)
from revocable_bayes import posterior_counts

SCHEMA = "ace-bb-cq03-amendment-exact-v1"


def run() -> dict:
    n = 12
    memory = amendment_memory(n)
    assert memory["max_same_posterior_histories"] == 924
    assert len({posterior_counts(m, n) for m in range(n + 1)}) == 13

    amendment_checks = 0
    for mask in range(1 << n):
        for slot in range(n):
            old = (mask >> slot) & 1
            for new in (0, 1):
                target_count = overwrite_match(mask, slot, new, n).bit_count()
                assert target_count == corrected_count(mask.bit_count(), old, new, n)
                amendment_checks += 1
    assert amendment_checks == 98304

    # Independent shorter-domain exhaustive pair discriminator, rather
    # than trusting the closed-form class-count formula on its own.
    n_small = 8
    within_count_pairs = 0
    for a, b in combinations(range(1 << n_small), 2):
        if a.bit_count() != b.bit_count():
            continue
        distinguishing_slot = ((a ^ b) & -(a ^ b)).bit_length() - 1
        revised_a = overwrite_match(a, distinguishing_slot, 0, n_small)
        revised_b = overwrite_match(b, distinguishing_slot, 0, n_small)
        assert revised_a.bit_count() != revised_b.bit_count()
        within_count_pairs += 1
    assert within_count_pairs == 6307

    # For n=12 this pair count is combinatorially exact and independently
    # implied by the proved single-differing-slot argument.
    pair_count_twelve = sum(comb(comb(n,m),2) for m in range(n + 1))
    assert pair_count_twelve == 1350030

    risk = expected_aggregate_only_error(n)
    m6c0 = aggregate_only_optimum(6, 0, n)["squared_l2_error_floor"]
    m6c1 = aggregate_only_optimum(6, 1, n)["squared_l2_error_floor"]
    floors = [aggregate_only_optimum(m,c,n)["squared_l2_error_floor"]
              for m in range(n+1) for c in (0,1)]

    return {
        "schema": SCHEMA,
        "evidence_class": "development_exact_finite_model",
        "authorizes_action": False,
        "source_model": "original_ECA04_complementary_channel_12_sentinels",
        "report_revision_contract": "indexed_blind_replace_or_archive_verified_delta",
        "histories": memory["initial_histories"],
        "current_exact_bayes_posterior_labels": memory["current_posterior_count"],
        "minimal_self_contained_bits_for_blind_revisions": memory["minimum_total_bits"],
        "extra_bits_given_present_posterior_label": memory["extra_fixed_tag_bits_given_current_posterior"],
        "largest_present_posterior_fiber": memory["max_same_posterior_histories"],
        "exhaustive_source_aware_revision_updates": amendment_checks,
        "n8_independent_same_count_pair_witnesses": within_count_pairs,
        "n12_same_count_pair_count_combinatorial": pair_count_twelve,
        "conditional_count6_revised0_risk_squared_l2": f"{float(m6c0):.12f}",
        "conditional_count6_revised1_risk_squared_l2": f"{float(m6c1):.12f}",
        "sharp_design_weighted_blind_revision_risk_squared_l2": f"{float(risk):.12f}",
        "max_conditional_blind_revision_risk_squared_l2": f"{float(max(floors)):.12f}",
        "archive_validation": "source-only unit tests, external trust assumed",
        "new_scientific_roots_sampled": 0,
        "model_checkpoint_loaded": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output", type=Path)
    group.add_argument("--check", type=Path)
    args = parser.parse_args()
    payload = json.dumps(run(), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        assert args.check.read_text(encoding="utf-8") == payload, "BB-CQ-03 receipt mismatch"
        print("PASS: BB-CQ-03 exact amendment receipt")


if __name__ == "__main__":
    main()
