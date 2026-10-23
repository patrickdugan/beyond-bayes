from itertools import combinations
import math
import random
import unittest

from ace import SupportGraph


class TestFlowCuts(unittest.TestCase):
    def test_shared_aggregator(self):
        graph = SupportGraph(['a', 'b'])
        graph.add_path('a', 'wire', 'claim')
        graph.add_path('b', 'wire', 'claim')
        self.assertEqual(1, graph.minimum_channel_cut('claim'))
        self.assertEqual(2, graph.minimum_channel_cut('claim', corruptible=['a', 'b']))
        self.assertEqual(math.inf, graph.minimum_channel_cut('claim', corruptible=[]))

    def test_no_path(self):
        graph = SupportGraph(['a', 'b'])
        graph.add_path('a', 'wire')
        self.assertEqual(0, graph.minimum_channel_cut('claim'))

    def test_duplicate_path_invariant(self):
        graph = SupportGraph(['a', 'b', 'c'])
        graph.add_path('a', 'wire1', 'claim')
        graph.add_path('b', 'wire2', 'claim')
        start = graph.minimum_channel_cut('claim')
        graph.add_path('a', 'wire1', 'claim')
        self.assertEqual(start, graph.minimum_channel_cut('claim'))
        graph.add_path('c', 'wire3', 'claim')
        self.assertGreaterEqual(graph.minimum_channel_cut('claim'), start)

    def test_dinic_matches_exhaustive_hitting_set_on_random_dags(self):
        rng = random.Random(102)
        for _ in range(500):
            all_nodes = ['a', 'b', 'c', 'd', 'e', 'f', 'claim']
            graph = SupportGraph(['a', 'b'])
            for i in range(len(all_nodes) - 1):
                for j in range(i + 1, len(all_nodes)):
                    if rng.random() < .25:
                        graph.add_path(all_nodes[i], all_nodes[j])
            allowed = [node for node in all_nodes[:-1] if rng.random() < .7]
            flow = graph.minimum_channel_cut('claim', corruptible=allowed)
            exhaustive = graph.minimum_channel_cut_bruteforce('claim', corruptible=allowed)
            self.assertEqual(flow, exhaustive)

    def test_many_paths_scalable(self):
        graph = SupportGraph([f'r{i}' for i in range(60)])
        for i in range(60):
            graph.add_path(f'r{i}', f'ch{i}', 'claim')
        self.assertEqual(60, graph.minimum_channel_cut('claim'))


if __name__ == '__main__':
    unittest.main()
