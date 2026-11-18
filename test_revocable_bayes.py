"""BB-CQ-02 exact likelihood, provenance and finite continuation tests."""
from fractions import Fraction as Q
from itertools import combinations, product
import random
import unittest

from continuation_quotient import audit_projection, quotient_partition, shortest_witness
from revocable_bayes import (
    PRIORS, ECA04_ORIGINAL_MODEL_SHA256, Slot, Event, Ledger,
    posterior_counts, posterior_full_replay, posterior_label,
    static_revocation_machine, prospective_machine,
)


class RevocableBayesTests(unittest.TestCase):
    def test_exact_original_complementary_likelihood(self):
        self.assertEqual(posterior_counts(0, 0), PRIORS)
        for n in range(7):
            for bits in product((0, 1), repeat=n):
                for parity in (0, 1):
                    pairs = tuple((j % 2, bits[j] ^ parity) for j in range(n))
                    matches = sum(label == report for label, report in pairs)
                    self.assertEqual(posterior_full_replay(pairs), posterior_counts(matches, n))
        rng = random.Random(20261118)
        for _ in range(60):
            pairs = tuple((rng.randrange(2), rng.randrange(2)) for _ in range(12))
            m = sum(a == b for a, b in pairs)
            self.assertEqual(posterior_full_replay(pairs), posterior_counts(m, 12))
        self.assertEqual(len(ECA04_ORIGINAL_MODEL_SHA256), 64)
        with self.assertRaises(ValueError):
            posterior_counts(2, 1)
        with self.assertRaises(ValueError):
            posterior_counts(True, 1)
        with self.assertRaises(ValueError):
            posterior_full_replay(((True, 0),))

    def test_full_replay_equals_group_summary_for_histories(self):
        slots = tuple(Slot(f"slot-{i}", f"group-{i // 2}", i % 2) for i in range(10))
        rng = random.Random(92026)
        for _ in range(90):
            ledger = Ledger(slots)
            sequence = []
            for i in range(10):
                sequence.append(("observe", f"slot-{i}", rng.randrange(2)))
            for i in range(5):
                sequence.append(("revoke", f"group-{i}", None))
            rng.shuffle(sequence)
            for kind, name, value in sequence:
                try:
                    ledger = ledger.observe(name, value) if kind == "observe" else ledger.revoke(name)
                except ValueError:
                    # Reports arriving after their root was revoked are illegal.
                    continue
                self.assertEqual(ledger.grouped_posterior(), ledger.full_posterior())
                self.assertFalse(ledger.authorizes_action)
            by_group = ledger.grouped_counts()
            self.assertEqual(set(by_group), {f"group-{i}" for i in range(5)})

    def test_provenance_retains_future_revocation_information(self):
        slots = (Slot("a", "a", 1), Slot("b", "b", 0), Slot("c", "c", 1))
        first = Ledger(slots).observe("a", 0).observe("b", 0).observe("c", 1)
        second = Ledger(slots).observe("a", 1).observe("b", 1).observe("c", 1)
        self.assertEqual(first.full_posterior(), second.full_posterior())
        self.assertNotEqual(first.revoke("a").full_posterior(),
                            second.revoke("a").full_posterior())
        self.assertNotEqual(first.grouped_counts(), second.grouped_counts())
        self.assertFalse(first.authorizes_action)

    def test_immutable_ledger_contract_errors_and_revocation(self):
        slots = (Slot("x", "same", 1), Slot("y", "same", 0),
                 Slot("z", "other", 1))
        ledger = Ledger(slots).observe("x", 1).observe("z", 0)
        self.assertEqual(ledger.grouped_counts()["same"], (1, 1, False))
        revoked = ledger.revoke("same")
        self.assertEqual(revoked.grouped_counts()["same"], (0, 0, True))
        self.assertEqual(revoked.active_pairs(), ((1, 0),))
        self.assertEqual(ledger.active_pairs(), ((1, 1), (1, 0)))
        for fn in (lambda: ledger.observe("x", 0),
                   lambda: revoked.observe("y", 0),
                   lambda: revoked.revoke("same"),
                   lambda: revoked.revoke("alien"),
                   lambda: revoked.observe("alien", 0),
                   lambda: Ledger((slots[0], slots[0])),
                   lambda: Slot("v", "g", True),
                   lambda: Event("revoke", "a", 0)):
            with self.assertRaises(ValueError):
                fn()

    def test_static_revision_finite_minimality(self):
        expected_present = [0, 3, 6, 10, 15, 21]
        expected_extra_bits = [0, 0, 1, 3, 4, 5]
        for n in range(1, 6):
            machine = static_revocation_machine(n)
            report = audit_projection(machine, machine.outputs)
            self.assertEqual(len(machine.states), 3**n)
            self.assertEqual(len(set(machine.outputs)), expected_present[n])
            self.assertEqual(report["minimal_output_classes"], 3**n)
            self.assertEqual(report["minimal_output_bits"], (3**n - 1).bit_length())
            self.assertEqual(report["additional_bits_for_online_repair"], expected_extra_bits[n])
            self.assertFalse(report["authorizes_action"])
            if n > 1:
                self.assertFalse(report["behaviorally_sufficient"])
            for state in machine.states[::max(1, len(machine.states) // 7)]:
                m = state.count("1")
                count = len(state) - state.count("2")
                self.assertEqual(machine.outputs[machine.states.index(state)],
                                 posterior_label(posterior_counts(m, count)))

    def test_raw_source_history_vs_static_machine(self):
        machine = static_revocation_machine(3)
        slots = tuple(Slot(f"s{i}", f"r{i}", i % 2) for i in range(3))
        for statuses in product(range(3), repeat=3):
            ledger = Ledger(slots)
            for i, s in enumerate(statuses):
                if s != 2:
                    ledger = ledger.observe(f"s{i}", (i % 2) ^ (1 - s))
            for i, s in enumerate(statuses):
                if s == 2:
                    ledger = ledger.revoke(f"r{i}")
            state_name = "".join(map(str, statuses))
            self.assertEqual(
                machine.outputs[machine.states.index(state_name)],
                posterior_label(ledger.full_posterior()))
            for i in range(3):
                if statuses[i] != 2:
                    nxt = machine.transitions[machine.states.index(state_name)][i]
                    self.assertEqual(machine.outputs[nxt],
                                     posterior_label(ledger.revoke(f"r{i}").full_posterior()))

    def test_one_step_current_posterior_collision(self):
        machine = static_revocation_machine(3)
        i = machine.states.index("011")
        j = machine.states.index("101")
        self.assertEqual(machine.outputs[i], machine.outputs[j])
        self.assertEqual(shortest_witness(machine, i, j), ("revoke:0",))
        self.assertNotEqual(machine.outputs[machine.transitions[i][0]],
                            machine.outputs[machine.transitions[j][0]])

    def test_prospective_observe_revoke_and_illegal_sink(self):
        machine = prospective_machine(3)
        report = audit_projection(machine, machine.outputs)
        self.assertEqual(len(machine.states), 65)
        self.assertEqual(report["minimal_output_classes"], 65)
        self.assertEqual(report["minimal_output_bits"], 7)
        self.assertEqual(len(set(machine.outputs)), 11)
        current = machine.states.index("000")
        act = machine.actions.index("observe:0:1")
        after = machine.transitions[current][act]
        self.assertEqual(machine.states[after], "200")
        sink = machine.transitions[after][act]
        self.assertEqual(machine.states[sink], "INVALID")
        self.assertEqual(machine.transitions[sink][act], sink)
        revoke = machine.actions.index("revoke:0")
        revoked = machine.transitions[current][revoke]
        self.assertEqual(machine.states[revoked], "300")
        self.assertEqual(machine.states[machine.transitions[revoked][act]], "INVALID")
        self.assertFalse(report["behaviorally_sufficient"])

    def test_independent_bfs_oracle_finite_contract(self):
        for fn in (lambda: static_revocation_machine(3), lambda: prospective_machine(2)):
            machine = fn()
            part = quotient_partition(machine)
            for i, j in combinations(range(len(machine.states)), 2):
                self.assertEqual(part[i] == part[j],
                                 shortest_witness(machine, i, j) is None)
        with self.assertRaises(ValueError):
            static_revocation_machine(6)
        with self.assertRaises(ValueError):
            prospective_machine(4)


if __name__ == "__main__":
    unittest.main()
