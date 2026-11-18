"""Exact finite and independent-oracle tests for continuation-state audits."""
import random
import unittest
from itertools import combinations

from continuation_quotient import (
    FiniteMachine, audit_projection, delayed_swap_machine, quotient_partition,
    repair_tags, revocable_support_machine, shortest_witness,
)


class ContinuationQuotientTests(unittest.TestCase):
    def test_ds3_revoke_memory_and_repair(self):
        machine = revocable_support_machine(3)
        report = audit_projection(machine, machine.outputs)
        self.assertEqual((report["minimal_output_classes"], report["minimal_output_bits"]), (8, 3))
        self.assertFalse(report["behaviorally_sufficient"])
        self.assertFalse(report["incrementally_realizable"])
        self.assertEqual(report["additional_bits_for_online_repair"], 3)
        self.assertEqual(report["additional_bits_for_output_only"], 3)
        self.assertFalse(report["authorizes_action"])
        self.assertIsNotNone(report["first_output_collision"])
        self.check_repair(machine, machine.outputs)
        for a, b in combinations(range(8), 2):
            self.assertIsNotNone(shortest_witness(machine, a, b))

    def test_revoke_root_at_various_sizes(self):
        for roots in range(1, 6):
            machine = revocable_support_machine(roots)
            report = audit_projection(machine, machine.outputs)
            self.assertEqual(report["minimal_output_classes"], 2**roots)
            self.assertEqual(report["minimal_output_bits"], roots)
            self.assertEqual(report["additional_bits_for_online_repair"], roots if roots >= 2 else 0)
            self.check_repair(machine, machine.outputs)

    def test_bpd_present_vs_delayed_observer(self):
        machine = delayed_swap_machine()
        self.assertEqual(len(set(quotient_partition(machine, horizon=0))), 2)
        self.assertEqual(len(set(quotient_partition(machine, horizon=1))), 4)
        report = audit_projection(machine, machine.outputs)
        self.assertEqual(report["minimal_output_classes"], 4)
        self.assertEqual(report["additional_bits_for_online_repair"], 1)
        self.assertEqual(report["first_output_collision"]["events"], ["tick"])
        self.check_repair(machine, machine.outputs)

    def test_output_equivalence_does_not_ensure_label_updater(self):
        machine = FiniteMachine(
            states=("s0", "s1", "s2"), actions=("step",),
            outputs=("constant", "constant", "constant"),
            transitions=((2,), (0,), (2,)))
        labels = ("same", "same", "different")
        result = audit_projection(machine, labels)
        self.assertTrue(result["behaviorally_sufficient"])
        self.assertFalse(result["incrementally_realizable"])
        self.assertIsNone(result["first_output_collision"])
        self.assertEqual(result["additional_bits_for_output_only"], 0)
        self.assertEqual(result["additional_bits_for_online_repair"], 1)
        self.assertEqual(result["first_update_collision"]["event"], "step")
        self.assertIsNone(shortest_witness(machine, 0, 1))
        self.assertEqual(shortest_witness(machine, 0, 1, retained_labels=labels), ("step",))
        self.check_repair(machine, labels)

    def test_full_bitmap_is_a_realizable_baseline(self):
        machine = revocable_support_machine(3)
        report = audit_projection(machine, machine.states)
        self.assertTrue(report["behaviorally_sufficient"])
        self.assertTrue(report["incrementally_realizable"])
        self.assertEqual(report["additional_bits_for_online_repair"], 0)

    def test_revise_roots_semantics_matches_ace_snapshot_example(self):
        from identifiability import Contract, Slot, Snapshot, diagnose
        contract = Contract(("q",), (Slot("a", "a", ("q",)), Slot("b", "b", ("q",))),
                            ("a", "b"), 0)
        left = Snapshot(contract).observe("a", 0)
        right = Snapshot(contract).observe("b", 0)
        self.assertEqual(diagnose(left, "q")["status"], "identified")
        self.assertEqual(diagnose(right, "q")["status"], "identified")
        self.assertEqual(diagnose(left.revoke("a"), "q")["status"], "undetermined")
        self.assertEqual(diagnose(right.revoke("a"), "q")["status"], "identified")
        # Under this externally declared k=0 and trusted-root premise, the
        # revocable-support machine is a sound finite abstraction of the fixture.
        machine = revocable_support_machine(2)
        self.assertEqual(machine.outputs[1], machine.outputs[2])
        self.assertNotEqual(machine.outputs[machine.transitions[1][0]],
                            machine.outputs[machine.transitions[2][0]])

    def test_independent_pair_bfs_matches_full_refinement(self):
        rng = random.Random(20261118)
        for _ in range(36):
            n = rng.randrange(2, 7)
            a = rng.randrange(0, 4)
            machine = FiniteMachine(
                states=tuple(f"s{i}" for i in range(n)),
                actions=tuple(f"e{i}" for i in range(a)),
                outputs=tuple(str(rng.randrange(3)) for _ in range(n)),
                transitions=tuple(tuple(rng.randrange(n) for _ in range(a)) for _ in range(n)),
            )
            part = quotient_partition(machine)
            for i, j in combinations(range(n), 2):
                self.assertEqual(part[i] == part[j], shortest_witness(machine, i, j) is None)
            labels = tuple(str(rng.randrange(3)) for _ in range(n))
            part2 = quotient_partition(machine, retained_labels=labels)
            for i, j in combinations(range(n), 2):
                self.assertEqual(part2[i] == part2[j],
                                 shortest_witness(machine, i, j, retained_labels=labels) is None)
            self.check_repair(machine, labels)

    def test_horizon_prefixes_match_independent_words(self):
        machine = revocable_support_machine(3)
        def words(depth):
            if depth == 0:
                return [()]
            return [()] + [(a,) + tail for a in range(len(machine.actions)) for tail in words(depth - 1)]
        def observation(s, word):
            for action in word:
                s = machine.transitions[s][action]
            return machine.outputs[s]
        for h in range(4):
            part = quotient_partition(machine, horizon=h)
            for i, j in combinations(range(8), 2):
                expected = all(observation(i, w) == observation(j, w) for w in words(h))
                self.assertEqual(part[i] == part[j], expected)

    def test_finite_contract_validation(self):
        with self.assertRaises(ValueError):
            FiniteMachine(("s",), ("a",), ("ok",), ((1,),))
        with self.assertRaises(ValueError):
            FiniteMachine(("s", "s"), (), ("ok", "ok"), ((), ()))
        with self.assertRaises(ValueError):
            quotient_partition(revocable_support_machine(), horizon=-1)
        with self.assertRaises(ValueError):
            audit_projection(revocable_support_machine(), ("only",))
        with self.assertRaises(ValueError):
            revocable_support_machine(0)

    def check_repair(self, machine, labels):
        tags = repair_tags(machine, labels)
        repaired = tuple((label, tag) for label, tag in zip(labels, tags))
        for i, j in combinations(range(len(machine.states)), 2):
            if repaired[i] == repaired[j]:
                self.assertEqual(machine.outputs[i], machine.outputs[j])
                for action in range(len(machine.actions)):
                    self.assertEqual(repaired[machine.transitions[i][action]],
                                     repaired[machine.transitions[j][action]])


if __name__ == "__main__":
    unittest.main()
