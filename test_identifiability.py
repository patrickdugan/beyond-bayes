"""Adversarial exact tests; all trust/fault assumptions are synthetic fixtures."""
from dataclasses import replace
from fractions import Fraction
from itertools import combinations, product
import json
import random
from pathlib import Path
import unittest

from identifiability import (
    Contract, Event, Slot, Snapshot, WorkLimit, compatible_worlds,
    credal_target_interval, diagnose, recommend_audit, verify_receipt, target_separation,
)
from benchmark_identifiability import clones_fixture, paths_fixture, run_benchmark


def independent_reference(snapshot):
    """Separate oracle: discard each allowed root subset, then satisfy all rows."""
    observations, revoked = snapshot.replay()
    contract = snapshot.contract
    roots = sorted({s.root for s in contract.slots} - set(contract.trusted_roots))
    worlds = set()
    for count in range(contract.max_faulty_roots + 1):
        for discarded in combinations(roots, count):
            ignored = set(discarded) | set(revoked)
            rows = [s for s in contract.slots if s.root not in ignored and s.id in observations]
            for bits in product((0, 1), repeat=len(contract.variables)):
                values = dict(zip(contract.variables, bits))
                if all(sum(values[v] for v in row.variables) % 2 == observations[row.id] for row in rows):
                    worlds.add(bits)
    return tuple(sorted(worlds))


class IdentifiabilityTests(unittest.TestCase):
    def test_ninety_percent_wrong_reports_recover_by_root(self):
        for truth in (0, 1):
            finding = diagnose(clones_fixture(truth), "q")
            self.assertEqual((finding["status"], finding["value"]), ("identified", truth))
            self.assertFalse(finding["authorizes_action"])

    def test_duplicate_reports_do_not_create_new_roots(self):
        for count in (1, 90):
            slots = tuple(Slot(str(i), "one", ("q",)) for i in range(count)) + (Slot("other", "two", ("q",)),)
            snapshot = Snapshot(Contract(("q",), slots, (), 1))
            for slot in slots:
                snapshot = snapshot.observe(slot.id, int(slot.root == "one"))
            self.assertEqual(diagnose(snapshot, "q")["status"], "undetermined")

    def test_unanchored_parity_has_complement_witness(self):
        snapshot = Snapshot(Contract(("a", "b"), (Slot("e", "r", ("a", "b")),))).observe("e", 1)
        result = diagnose(snapshot, "b")
        self.assertEqual(result["status"], "undetermined")
        self.assertEqual(set(result["witnesses"]), {"0", "1"})
        self.assertEqual(result["witnesses"]["0"], [1, 0])
        self.assertEqual(result["witnesses"]["1"], [0, 1])

    def test_all_worlds_and_one_edge_corruptions_recover(self):
        cases = 0
        for world in product((0, 1), repeat=5):
            for flipped in ((), *((i,) for i in range(6))):
                finding = diagnose(paths_fixture(world, flipped), "t")
                self.assertEqual((finding["status"], finding["value"]), ("identified", world[-1]))
                cases += 1
        self.assertEqual(cases, 224)

    def test_edge_disjoint_is_insufficient_with_shared_source(self):
        snapshot = paths_fixture((0, 0, 0, 0, 0), (0, 1, 2), True)
        self.assertIn((0, 0, 0, 0, 0), compatible_worlds(snapshot))
        self.assertEqual(diagnose(snapshot, "t")["status"], "undetermined")

    def test_unmodelled_common_cause_can_break_identification(self):
        snapshot = paths_fixture((0, 0, 0, 0, 0), (0, 1, 2), False)
        self.assertNotIn((0, 0, 0, 0, 0), compatible_worlds(snapshot))
        self.assertEqual(diagnose(snapshot, "t")["value"], 1)

    def test_false_trusted_anchor_boundary(self):
        snapshot = Snapshot(Contract(("q",), (Slot("a", "external", ("q",)),), ("external",)))
        snapshot = snapshot.observe("a", 1)
        self.assertEqual(diagnose(snapshot, "q")["value"], 1)
        self.assertNotIn((0,), compatible_worlds(snapshot))

    def test_contradiction_never_becomes_vacuous_certainty(self):
        contract = Contract(("q",), (Slot("a", "a", ("q",)), Slot("b", "b", ("q",))), ("a", "b"))
        snapshot = Snapshot(contract).observe("a", 0).observe("b", 1)
        finding = diagnose(snapshot, "q")
        self.assertEqual(finding["status"], "model_conflict")
        self.assertIsNone(finding["value"])
        self.assertFalse(finding["authorizes_action"])
        with self.assertRaises(ValueError):
            credal_target_interval(snapshot, "q")
        self.assertIsNone(recommend_audit(snapshot, "q", 10))

    def test_missing_slots_are_erasures(self):
        contract = Contract(("q",), tuple(Slot(str(i), str(i), ("q",)) for i in range(3)), (), 1)
        snapshot = Snapshot(contract).observe("0", 0)
        self.assertEqual(diagnose(snapshot, "q")["status"], "undetermined")
        self.assertEqual(diagnose(snapshot, "q")["missing_slots"], ["1", "2"])
        self.assertEqual(len(compatible_worlds(Snapshot(contract))), 2)

    def test_revocation_widens_worlds_and_invalidates_receipt(self):
        before = paths_fixture((0, 0, 0, 0, 0))
        receipt = diagnose(before, "t")
        verify_receipt(receipt, before, expected_contract_digest=before.contract.digest,
                       expected_history_digest=before.digest, expected_target="t")
        after = before.revoke("external")
        self.assertTrue(set(compatible_worlds(before)) <= set(compatible_worlds(after)))
        self.assertEqual(diagnose(after, "t")["status"], "undetermined")
        self.assertEqual(after.contract.max_faulty_roots, 1)
        self.assertEqual(after.events[:-1], before.events)
        with self.assertRaises(ValueError):
            verify_receipt(receipt, after, expected_contract_digest=after.contract.digest,
                           expected_history_digest=after.digest, expected_target="t")
        with self.assertRaises(ValueError):
            verify_receipt(receipt, before, expected_contract_digest=before.contract.digest,
                           expected_history_digest=after.digest, expected_target="t")

    def test_receipt_detects_every_field_tampering(self):
        snapshot = paths_fixture((0, 0, 0, 0, 0))
        receipt = diagnose(snapshot, "t")
        for key in receipt:
            tampered = dict(receipt)
            tampered[key] = "tampered"
            with self.assertRaises(ValueError):
                verify_receipt(tampered, snapshot, expected_contract_digest=snapshot.contract.digest,
                               expected_history_digest=snapshot.digest, expected_target="t")
        with self.assertRaises(ValueError):
            verify_receipt(dict(receipt, value=False), snapshot,
                           expected_contract_digest=snapshot.contract.digest,
                           expected_history_digest=snapshot.digest, expected_target="t")

    def test_model_change_requires_new_pin(self):
        original = paths_fixture((0, 0, 0, 0, 0))
        changed = Snapshot(replace(original.contract, max_faulty_roots=2), original.events)
        self.assertNotEqual(original.contract.digest, changed.contract.digest)
        with self.assertRaises(ValueError):
            verify_receipt(diagnose(changed, "t"), changed,
                           expected_contract_digest=original.contract.digest,
                           expected_history_digest=changed.digest, expected_target="t")

    def test_current_verdict_is_not_continuation_sufficient(self):
        contract = Contract(("q",), (Slot("a", "a", ("q",)), Slot("b", "b", ("q",))), ("a", "b"))
        left, right = Snapshot(contract).observe("a", 0), Snapshot(contract).observe("b", 0)
        self.assertEqual(diagnose(left, "q")["value"], diagnose(right, "q")["value"])
        self.assertEqual(diagnose(left.revoke("a"), "q")["status"], "undetermined")
        self.assertEqual(diagnose(right.revoke("a"), "q")["status"], "identified")

    def test_no_reuse_or_reinstatement(self):
        contract = Contract(("q",), (Slot("a", "root", ("q",)), Slot("b", "root", ("q",))))
        snapshot = Snapshot(contract).observe("a", 0)
        with self.assertRaises(ValueError):
            snapshot.observe("a", 0)
        revoked = snapshot.revoke("root")
        with self.assertRaises(ValueError):
            revoked.observe("b", 1)
        with self.assertRaises(ValueError):
            revoked.revoke("root")
        with self.assertRaises(ValueError):
            snapshot.revoke("unknown")
        with self.assertRaises(ValueError):
            snapshot.observe("unknown", 0)

    def test_cheapest_resolving_audit_avoids_nuisance(self):
        contract = Contract(("a", "q", "n"), (
            Slot("relation", "logic", ("a", "q")), Slot("anchor", "audit", ("a",), 2),
            Slot("nuisance", "audit", ("n",), 1)), ("logic", "audit"))
        snapshot = Snapshot(contract).observe("relation", 1)
        self.assertIsNone(recommend_audit(snapshot, "q", 1))
        recommendation = recommend_audit(snapshot, "q", 2)
        self.assertEqual(recommendation["slot"], "anchor")
        self.assertEqual(recommendation["branches"]["0"]["value"], 1)
        self.assertEqual(recommendation["branches"]["1"]["value"], 0)
        self.assertFalse(recommendation["authorizes_action"])
        self.assertEqual(len(snapshot.events), 1)

    def test_audit_can_be_untrusted_under_same_fault_cap(self):
        contract = Contract(("q",), tuple(Slot(str(i), str(i), ("q",)) for i in range(3)), (), 1)
        snapshot = Snapshot(contract).observe("0", 0).observe("1", 1)
        query = recommend_audit(snapshot, "q", 1)
        self.assertEqual(query["slot"], "2")
        self.assertEqual(query["branches"]["0"]["value"], 0)
        self.assertEqual(query["branches"]["1"]["value"], 1)

    def test_audit_clone_cannot_resolve_shared_bias(self):
        contract = Contract(("q",), (Slot("a", "r", ("q",)), Slot("b", "s", ("q",)),
                                      Slot("copy", "r", ("q",))), (), 1)
        snapshot = Snapshot(contract).observe("a", 0).observe("b", 1)
        self.assertIsNone(recommend_audit(snapshot, "q", 10))

    def test_independent_reference_all_reports_and_revocations(self):
        slots = (Slot("anchor", "trusted", ("a",)), Slot("e0", "shared", ("a", "b")),
                 Slot("e1", "shared", ("b", "c")), Slot("e2", "other", ("a", "c")))
        for k in (0, 1, 2):
            contract = Contract(("a", "b", "c"), slots, ("trusted",), k)
            for readings in product((None, 0, 1), repeat=4):
                snapshot = Snapshot(contract)
                for slot, reading in zip(slots, readings):
                    if reading is not None:
                        snapshot = snapshot.observe(slot.id, reading)
                for state in (snapshot, snapshot.revoke("trusted"), snapshot.revoke("shared")):
                    self.assertEqual(compatible_worlds(state), independent_reference(state))

    def test_full_credal_comparator_agrees_with_identification(self):
        for values in product((None, 0, 1), repeat=3):
            contract = Contract(("q",), tuple(Slot(str(i), str(i), ("q",)) for i in range(3)), (), 1)
            snapshot = Snapshot(contract)
            for slot, value in zip(contract.slots, values):
                if value is not None:
                    snapshot = snapshot.observe(slot.id, value)
            finding = diagnose(snapshot, "q")
            lower, upper = credal_target_interval(snapshot, "q")
            self.assertEqual(lower == upper, finding["status"] == "identified")
            if lower == upper:
                self.assertEqual(lower, Fraction(finding["value"]))

    def test_invalid_inputs_fail_closed(self):
        for value in (True, False, 0.0, "0", None, -1, 2):
            with self.assertRaises(ValueError):
                Event("observe", "a", value)
        for cost in (True, 0, -1, 1.0):
            with self.assertRaises(ValueError):
                Slot("a", "r", ("q",), cost)
        with self.assertRaises(ValueError):
            Contract(("q", "q"), ())
        with self.assertRaises(ValueError):
            Contract(("q",), (Slot("a", "r", ("x",)),))
        with self.assertRaises(ValueError):
            Contract(("q",), (), ("unknown",))
        with self.assertRaises(ValueError):
            Contract(("q",), (), (), True)
        with self.assertRaises(ValueError):
            Slot("a", "r", ("q", "q"))
        with self.assertRaises(ValueError):
            diagnose(Snapshot(Contract(("q",), ())), "unknown")

    def test_resource_limit_is_not_model_conflict(self):
        with self.assertRaises(WorkLimit):
            Contract(tuple(str(i) for i in range(13)), ())
        variables = tuple(str(i) for i in range(12))
        slots = tuple(Slot(str(i), str(i), ("0",)) for i in range(128))
        snapshot = Snapshot(Contract(variables, slots))
        with self.assertRaises(WorkLimit):
            recommend_audit(snapshot, "0", 1)

    def test_source_group_distance_threshold(self):
        good = target_separation(paths_fixture((0, 0, 0, 0, 0)), "t")
        shared = target_separation(paths_fixture((0, 0, 0, 0, 0), (0, 1, 2), True), "t")
        self.assertEqual(good["minimum_root_distance"], 3)
        self.assertTrue(good["uniformly_identifiable_under_declared_model"])
        self.assertEqual(shared["minimum_root_distance"], 1)
        self.assertFalse(shared["uniformly_identifiable_under_declared_model"])
        self.assertEqual(target_separation(clones_fixture(0), "q")["minimum_root_distance"], 11)

    def test_separation_anchor_and_empty_model_boundaries(self):
        contract = Contract(("q",), (Slot("a", "a", ("q",)), Slot("b", "b", ("q",))), ("a", "b"))
        snapshot = Snapshot(contract).observe("a", 0)
        self.assertEqual(target_separation(snapshot, "q")["status"], "fixed_by_trusted_observations")
        conflict = target_separation(snapshot.observe("b", 1), "q")
        self.assertEqual(conflict["status"], "trusted_model_conflict")
        self.assertFalse(conflict["uniformly_identifiable_under_declared_model"])

    def test_constructed_collision_contains_opposite_compatible_worlds(self):
        for shared in (True, False):
            for k in range(4):
                source = paths_fixture((0, 1, 0, 1, 0), shared=shared)
                snapshot = Snapshot(replace(source.contract, max_faulty_roots=k), source.events)
                result = target_separation(snapshot, "t")
                collision = result["synthetic_collision"]
                if collision is not None:
                    replay = Snapshot(snapshot.contract)
                    for slot, value in collision["reports"].items():
                        replay = replay.observe(slot, value)
                    worlds = independent_reference(replay)
                    left, right = map(tuple, collision["worlds"])
                    self.assertIn(left, worlds)
                    self.assertIn(right, worlds)
                    self.assertNotEqual(left[-1], right[-1])
                    self.assertEqual(diagnose(replay, "t")["status"], "undetermined")

    def test_distance_matches_pairwise_independent_oracle(self):
        slots = (Slot("a", "trusted", ("a",)), Slot("x", "shared", ("a", "b")),
                 Slot("y", "shared", ("b", "c")), Slot("z", "other", ("a", "c")))
        for mask in product((0, 1), repeat=4):
            snapshot = Snapshot(Contract(("a", "b", "c"), slots, ("trusted",), 1))
            for slot, present in zip(slots, mask):
                if present:
                    snapshot = snapshot.observe(slot.id, 0)
            wide = Snapshot(replace(snapshot.contract, max_faulty_roots=2), snapshot.events)
            candidates = independent_reference(wide)
            observed, _ = snapshot.replay()
            distances = []
            for left, right in combinations(candidates, 2):
                if left[-1] == right[-1]:
                    continue
                a, b = dict(zip(snapshot.contract.variables, left)), dict(zip(snapshot.contract.variables, right))
                roots = {slot.root for slot in slots if slot.id in observed and slot.root != "trusted"
                         and sum(a[v] for v in slot.variables) % 2 != sum(b[v] for v in slot.variables) % 2}
                distances.append(len(roots))
            self.assertEqual(target_separation(snapshot, "c")["minimum_root_distance"],
                             min(distances) if distances else None)

    def test_distance_threshold_matches_exhaustive_transcripts(self):
        rng = random.Random(1030)
        variables = ("a", "b", "q")
        terms = tuple((v,) for v in variables) + tuple(combinations(variables, 2))
        for _ in range(40):
            count = rng.randint(1, 5)
            slots = tuple(Slot(str(i), str(rng.randrange(3)), rng.choice(terms))
                          for i in range(count))
            trusted = ()
            if rng.choice((False, True)):
                slots += (Slot("anchor", "external", (rng.choice(variables),)),)
                trusted = ("external",)
            root_count = len({slot.root for slot in slots} - set(trusted))
            contract = Contract(variables, slots, trusted, rng.randrange(root_count + 1))
            ambiguous = False
            reference_state = None
            for bits in product((0, 1), repeat=count):
                snapshot = Snapshot(contract)
                if trusted:
                    snapshot = snapshot.observe("anchor", 0)
                for i, bit in enumerate(bits):
                    snapshot = snapshot.observe(str(i), bit)
                worlds = independent_reference(snapshot)
                ambiguous |= len({world[-1] for world in worlds}) > 1
                reference_state = snapshot
            separation = target_separation(reference_state, "q")
            self.assertEqual(separation["uniformly_identifiable_under_declared_model"],
                             not ambiguous)

    def test_committed_benchmark_replays_exactly(self):
        path = Path(__file__).parent / "results" / "identifiability_v1.json"
        self.assertEqual(json.loads(path.read_text("utf-8")), run_benchmark())


if __name__ == "__main__":
    unittest.main()
