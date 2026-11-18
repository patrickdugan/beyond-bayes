"""Replayable exact finite continuation-state checks, with independent BFS oracle.

No model inference, statistical sampling claim or research authorization occurs.
The deterministic synthetic cases and seeds were selected during development.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from itertools import combinations
import json
from pathlib import Path
from random import Random

from continuation_quotient import (
    FiniteMachine, audit_projection, delayed_swap_machine, quotient_partition,
    repair_tags, revocable_support_machine, shortest_witness,
)

ROOT = Path(__file__).resolve().parent
SEED = 20261118


def run() -> dict:
    roots = {}
    for m in (2, 3, 4, 5):
        machine = revocable_support_machine(m)
        report = audit_projection(machine, machine.outputs)
        roots[str(m)] = {
            "states": len(machine.states),
            "horizon_class_counts": [len(set(quotient_partition(machine, horizon=h))) for h in range(m + 1)],
            "minimal_bits": report["minimal_output_bits"],
            "additional_online_bits_given_verdict": report["additional_bits_for_online_repair"],
            "verdict_only_sufficient": report["behaviorally_sufficient"],
        }
    machine = delayed_swap_machine()
    swap_report = audit_projection(machine, machine.outputs)
    swap = {
        "horizon_class_counts": [len(set(quotient_partition(machine, horizon=h))) for h in range(3)],
        "additional_online_bits_given_current_readout": swap_report["additional_bits_for_online_repair"],
        "first_collision": swap_report["first_output_collision"],
    }
    update_example = FiniteMachine(
        ("s0", "s1", "s2"), ("step",),
        ("constant", "constant", "constant"), ((2,), (0,), (2,)),
    )
    update_report = audit_projection(update_example, ("same", "same", "different"))
    update = {
        "behaviorally_sufficient": update_report["behaviorally_sufficient"],
        "incrementally_realizable": update_report["incrementally_realizable"],
        "output_repair_bits": update_report["additional_bits_for_output_only"],
        "online_repair_bits": update_report["additional_bits_for_online_repair"],
    }
    rng = Random(SEED)
    machine_count = 96
    comparisons = 0
    repaired_pairs = 0
    for _ in range(machine_count):
        n = rng.randrange(2, 8)
        a = rng.randrange(0, 4)
        machine = FiniteMachine(
            tuple(f"s{i}" for i in range(n)),
            tuple(f"e{i}" for i in range(a)),
            tuple(str(rng.randrange(3)) for _ in range(n)),
            tuple(tuple(rng.randrange(n) for _ in range(a)) for _ in range(n)),
        )
        labels = tuple(str(rng.randrange(3)) for _ in range(n))
        part = quotient_partition(machine)
        online_part = quotient_partition(machine, retained_labels=labels)
        tags = repair_tags(machine, labels)
        for i, j in combinations(range(n), 2):
            # Product-automaton BFS never invokes the partition refinement.
            assert (part[i] == part[j]) == (shortest_witness(machine, i, j) is None)
            assert (online_part[i] == online_part[j]) == (
                shortest_witness(machine, i, j, retained_labels=labels) is None)
            comparisons += 2
            if labels[i] == labels[j] and tags[i] == tags[j]:
                assert machine.outputs[i] == machine.outputs[j]
                for k in range(a):
                    ni, nj = machine.transitions[i][k], machine.transitions[j][k]
                    assert (labels[ni], tags[ni]) == (labels[nj], tags[nj])
                repaired_pairs += 1
    source_sha = sha256((ROOT / "continuation_quotient.py").read_bytes()).hexdigest()
    return {
        "schema": "ace-continuation-quotient-exact-v1",
        "evidence_class": "development_exact_finite_domain",
        "authorizes_action": False,
        "source_sha256": source_sha,
        "seed": SEED,
        "revocation": roots,
        "delayed_observer": swap,
        "label_updater_counterexample": update,
        "independent_bfs": {
            "machines": machine_count,
            "pairwise_equivalence_comparisons": comparisons,
            "repaired_fiber_pairs_checked": repaired_pairs,
            "disagreements": 0,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output", type=Path)
    group.add_argument("--check", type=Path)
    args = parser.parse_args()
    result = run()
    content = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8")
    else:
        if args.check.read_text(encoding="utf-8") != content:
            raise SystemExit("FAIL: continuation receipt differs from independent replay")
        print("PASS: continuation quotient exact receipt matches")


if __name__ == "__main__":
    main()
