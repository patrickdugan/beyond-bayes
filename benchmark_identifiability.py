"""Exact synthetic controls for ACE identifiability; no trained-model results."""
from __future__ import annotations

import argparse
from hashlib import sha256
from itertools import product
import json
from pathlib import Path

from identifiability import (
    Contract, Slot, Snapshot, compatible_worlds, credal_target_interval, diagnose, target_separation,
)


def paths_fixture(world: tuple[int, ...], flipped: tuple[int, ...] = (),
                  shared: bool = False) -> Snapshot:
    """Three edge-disjoint a--b_i--t paths, optionally sharing a fault root."""
    variables = ("a", "b0", "b1", "b2", "t")
    edges = [("a", f"b{i}") for i in range(3)] + [(f"b{i}", "t") for i in range(3)]
    slots = (Slot("anchor", "external", ("a",)),) + tuple(
        Slot(f"edge{i}", "common" if shared and i < 3 else f"source{i}", edge)
        for i, edge in enumerate(edges))
    snapshot = Snapshot(Contract(variables, slots, ("external",), 1)).observe("anchor", world[0])
    values = dict(zip(variables, world))
    for i, (left, right) in enumerate(edges):
        snapshot = snapshot.observe(f"edge{i}", values[left] ^ values[right] ^ int(i in flipped))
    return snapshot


def clones_fixture(truth: int) -> Snapshot:
    slots = tuple(Slot(f"copy{i}", "one-common-source", ("q",)) for i in range(90))
    slots += tuple(Slot(f"independent{i}", f"good{i}", ("q",)) for i in range(10))
    snapshot = Snapshot(Contract(("q",), slots, (), 1))
    for slot in slots:
        snapshot = snapshot.observe(slot.id, truth ^ int(slot.root == "one-common-source"))
    return snapshot


def _scored(snapshot: Snapshot, target: str, truth: int, assumptions_hold: bool) -> dict:
    finding = diagnose(snapshot, target)
    return {"assumptions_hold": assumptions_hold, "truth": truth,
            "status": finding["status"], "value": finding["value"],
            "compatible_world_count": finding["compatible_world_count"],
            "wrong_identification": finding["status"] == "identified" and finding["value"] != truth,
            "authorizes_action": finding["authorizes_action"]}


def run_benchmark() -> dict:
    path_cases = path_errors = path_abstentions = 0
    for world in product((0, 1), repeat=5):
        for flipped in ((), *((i,) for i in range(6))):
            result = _scored(paths_fixture(world, flipped), "t", world[-1], True)
            path_cases += 1
            path_errors += result["wrong_identification"]
            path_abstentions += result["status"] != "identified"

    retention_cases = removed_truths = wrong_identifications = comparator_mismatches = 0
    for count in range(1, 6):
        slots = tuple(Slot(str(i), str(i), ("q",)) for i in range(count))
        for k in range(count + 1):
            for reports in product((None, 0, 1), repeat=count):
                snapshot = Snapshot(Contract(("q",), slots, (), k))
                for slot, report in zip(slots, reports):
                    if report is not None:
                        snapshot = snapshot.observe(slot.id, report)
                finding = diagnose(snapshot, "q")
                worlds = compatible_worlds(snapshot)
                if worlds:
                    lo, hi = credal_target_interval(snapshot, "q")
                    comparator_mismatches += ((lo == hi) != (finding["status"] == "identified"))
                    if lo == hi:
                        comparator_mismatches += int(lo) != finding["value"]
                for truth in (0, 1):
                    if sum(report is not None and report != truth for report in reports) <= k:
                        retention_cases += 1
                        removed_truths += (truth,) not in worlds
                        wrong_identifications += (finding["status"] == "identified"
                                                  and finding["value"] != truth)

    symmetric = Snapshot(Contract(("a", "q"), (Slot("parity", "r", ("a", "q")),)))
    symmetric = symmetric.observe("parity", 0)
    independent = paths_fixture((0, 0, 0, 0, 0))
    shared = paths_fixture((0, 0, 0, 0, 0), (0, 1, 2), True)
    hidden_common = paths_fixture((0, 0, 0, 0, 0), (0, 1, 2), False)
    erasures = Snapshot(Contract(("q",), tuple(Slot(str(i), str(i), ("q",)) for i in range(3)), (), 1))
    erasures = erasures.observe("0", 0)
    bad_anchor = Snapshot(Contract(("q",), (Slot("anchor", "external", ("q",)),), ("external",)))
    bad_anchor = bad_anchor.observe("anchor", 1)
    conflict = Snapshot(Contract(("q",), (Slot("left", "x", ("q",)), Slot("right", "y", ("q",))), ("x", "y")))
    conflict = conflict.observe("left", 0).observe("right", 1)
    scenarios = {
        "ninety_percent_wrong_cloned_reports": _scored(clones_fixture(0), "q", 0, True),
        "parity_without_anchor": _scored(symmetric, "q", 0, True),
        "edge_disjoint_paths_shared_fault_root": _scored(shared, "t", 0, True),
        "anchor_revoked": _scored(independent.revoke("external"), "t", 0, True),
        "two_of_three_reports_missing": _scored(erasures, "q", 0, True),
        "invalid_trusted_anchor_boundary": _scored(bad_anchor, "q", 0, False),
        "unmodelled_common_cause_boundary": _scored(hidden_common, "t", 0, False),
        "contradictory_trusted_observations": _scored(conflict, "q", 0, False),
    }
    root = Path(__file__).resolve().parent
    return {
        "schema": "ace-identifiability-exact-benchmark-v1",
        "base_commit": "c91a758fbf9793368648b002b11778013e7cb69f",
        "source_sha256": {name: sha256((root / name).read_bytes()).hexdigest()
                          for name in ("identifiability.py", "benchmark_identifiability.py")},
        "scope": "Finite binary constraints with externally supplied fault groups; no model or human evaluation.",
        "path_recovery": {"cases": path_cases, "wrong_identifications": path_errors,
                          "unresolved": path_abstentions},
        "corruption_and_erasure_retention": {"admissible_world_transcripts": retention_cases,
                                           "truths_removed": removed_truths,
                                           "wrong_identifications": wrong_identifications,
                                           "matched_credal_disagreements": comparator_mismatches},
        "scenarios": scenarios,
        "source_group_separation": {
            "independent_paths": target_separation(independent, "t"),
            "shared_source_paths": target_separation(shared, "t"),
            "unanchored_parity": target_separation(symmetric, "q"),
            "ninety_wrong_clones": target_separation(clones_fixture(0), "q"),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--output", type=Path)
    group.add_argument("--check", type=Path)
    args = parser.parse_args()
    result = run_benchmark()
    if args.check:
        if json.loads(args.check.read_text("utf-8")) != result:
            raise SystemExit("receipt mismatch")
        print("Exact receipt replay matched")
    elif args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf-8")
    else:
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
