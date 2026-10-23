import unittest
from ace import (BernoulliEProcess, EvidenceConflict, ProvenanceLedger,
                 Report, SupportGraph, UncertifiedIndependence, minimax_regret, surviving_models)


class TestProvenance(unittest.TestCase):
    def test_duplicate_reports_do_not_compound(self):
        ledger = ProvenanceLedger()
        for i in range(50):
            ledger.add(Report(str(i), 'root', 2.0))
        self.assertEqual(ledger.independent_origin_count(), 1)
        self.assertEqual(ledger.evidence_factor(), 2.0)

    def test_conflicting_copy_fails_closed(self):
        ledger = ProvenanceLedger()
        ledger.add(Report('a', 'root', 2.0))
        ledger.add(Report('b', 'root', 3.0))
        with self.assertRaises(EvidenceConflict):
            ledger.evidence_factor()

    def test_distinct_roots_require_certification(self):
        ledger = ProvenanceLedger()
        ledger.add(Report('a', 'rootA', 2.0))
        ledger.add(Report('b', 'rootB', 3.0))
        with self.assertRaises(UncertifiedIndependence):
            ledger.evidence_factor()
        self.assertEqual(ledger.evidence_factor(conditional_independence_certified=True), 6.0)


class TestSequentialEvidence(unittest.TestCase):
    def test_e_ratio(self):
        proc = BernoulliEProcess(.5, .7)
        proc.observe(1)
        self.assertAlmostEqual(proc.evidence, 1.4)
        proc.observe(0)
        self.assertAlmostEqual(proc.evidence, .84)

    def test_persistent_rejection(self):
        proc = BernoulliEProcess(.5, .7)
        for i in range(20):
            proc.observe(1)
        self.assertTrue(proc.rejected)
        for i in range(100):
            proc.observe(0)
        self.assertTrue(proc.rejected)

    def test_surviving_models(self):
        live = surviving_models([1]*30, {'fair': .5, 'biased': .7}, alternative_p=.7)
        self.assertEqual(list(live), ['biased'])


class TestChannelCuts(unittest.TestCase):
    def test_shared_aggregator_is_one_point_of_failure(self):
        graph = SupportGraph(['witness-A', 'witness-B'])
        graph.add_path('witness-A', 'wire', 'claim')
        graph.add_path('witness-B', 'wire', 'claim')
        self.assertEqual(graph.minimum_channel_cut('claim'), 1)

    def test_separate_channel_resists_one_intermediary_attack(self):
        graph = SupportGraph(['witness-A', 'witness-B', 'witness-C'])
        graph.add_path('witness-A', 'wire', 'claim')
        graph.add_path('witness-B', 'wire', 'claim')
        graph.add_path('witness-C', 'independent', 'claim')
        self.assertEqual(graph.minimum_channel_cut('claim'), 2)

    def test_cycles_forbidden(self):
        graph = SupportGraph(['witness'])
        graph.add_path('witness', 'aggregator', 'claim')
        with self.assertRaises(ValueError):
            graph.add_path('claim', 'witness')


class TestDecisions(unittest.TestCase):
    def test_minimax_regret(self):
        action, regrets = minimax_regret({
            'calm': {'deploy': .10, 'watch': .25},
            'turbulent': {'deploy': .60, 'watch': .25},
        })
        self.assertEqual(action, 'watch')
        self.assertAlmostEqual(regrets['deploy'], .35)
        self.assertAlmostEqual(regrets['watch'], .15)

    def test_empty_models(self):
        with self.assertRaises(ValueError):
            minimax_regret({})


if __name__ == '__main__':
    unittest.main()
