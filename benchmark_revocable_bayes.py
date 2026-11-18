"""BB-CQ-02 exact finite development receipt; source and endpoints are public.

This script does not generate new CSPRNG issuer cohorts or open protected tests.
"""
from __future__ import annotations

import argparse
from itertools import combinations
import json
from pathlib import Path

from continuation_quotient import audit_projection, quotient_partition, shortest_witness
from revocable_bayes import (
    PRIORS, SCHEMA, posterior_counts, static_revocation_machine, prospective_machine,
)


def run() -> dict:
    static = {}
    for groups in range(1, 6):
        m = static_revocation_machine(groups)
        r = audit_projection(m, m.outputs)
        count = 3**groups
        assert r["minimal_output_classes"] == count
        static[str(groups)] = {
            "states": count,
            "present_posteriors": len(set(m.outputs)),
            "continuation_classes": r["minimal_output_classes"],
            "minimal_total_bits": r["minimal_output_bits"],
            "extra_online_bits_given_posterior": r["additional_bits_for_online_repair"],
            "posterior_only_sufficient": r["behaviorally_sufficient"],
        }

    prospective = {}
    for groups in (2, 3):
        m = prospective_machine(groups)
        r = audit_projection(m, m.outputs)
        assert r["minimal_output_classes"] == 4**groups + 1
        prospective[str(groups)] = {
            "states_including_invalid": len(m.states),
            "current_outputs_including_invalid": len(set(m.outputs)),
            "continuation_classes": r["minimal_output_classes"],
            "minimal_total_bits": r["minimal_output_bits"],
            "extra_online_bits_given_output": r["additional_bits_for_online_repair"],
        }

    static3 = static_revocation_machine(3)
    prospective3 = prospective_machine(3)
    comparisons = 0
    for machine in (static3, prospective3):
        quotient = quotient_partition(machine)
        for i, j in combinations(range(len(machine.states)), 2):
            # Independent product-machine BFS checks the actual shortest suffix.
            assert (quotient[i] == quotient[j]) == (
                shortest_witness(machine, i, j) is None)
            comparisons += 1

    collision = shortest_witness(static3, static3.states.index("011"),
                                 static3.states.index("101"))
    assert collision == ("revoke:0",)

    observed = {
        "schema": SCHEMA,
        "evidence_class": "exact_finite_development",
        "authorizes_action": False,
        "eca04_priors": [str(v) for v in PRIORS],
        "static_revocation": static,
        "prospective_observe_revoke": prospective,
        "first_same_posterior_collision": {
            "states": ["011", "101"],
            "suffix": list(collision),
        },
        "independent_product_bfs": {
            "pairwise_comparisons": comparisons,
            "disagreements": 0,
        },
        "neural_checkpoint_accessed": False,
        "random_scientific_roots_sampled": 0,
    }
    assert comparisons == 2431
    return observed


def main() -> None:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output", type=Path)
    group.add_argument("--check", type=Path)
    args = parser.parse_args()
    output = json.dumps(run(), sort_keys=True, indent=2) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
        print(output)
    else:
        assert args.check.read_text(encoding="utf-8") == output, "BB-CQ-02 receipt differs"
        print("PASS: exact BB-CQ-02 independently replayed against committed receipt")


if __name__ == "__main__":
    main()
