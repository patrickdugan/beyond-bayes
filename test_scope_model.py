"""Exhaustive short root-scope accounting paths, independent of the SQLite quorum."""
import itertools
import unittest
from test_scope import identity_fixture
from pathlib import Path
import tempfile
from scope import ScopeState, ScopeGrant, ScopeError, child_id, transition
from witnessed import GENESIS_DIGEST

class ScopeModelTests(unittest.TestCase):
    def test_all_small_allocations_and_unique_children(self):
        with tempfile.TemporaryDirectory() as td:
            policy, *_ = identity_fixture(Path(td), units=4)
            frontier = [(ScopeState(), GENESIS_DIGEST, 0, [])]
            visited = 0
            for depth in range(5):
                new = []
                for state, prev, seq, trace in frontier:
                    visited += 1
                    self.assertEqual(state.allocated, sum(g.child_units for g in trace))
                    self.assertLessEqual(state.allocated, policy.total_units)
                    self.assertEqual(len(state.child_ids), len(trace))
                    for index,amount in itertools.product(range(3), range(1,5)):
                        nonce=f'short-case-{index:05d}-scope'
                        grant=ScopeGrant(policy.commitment, seq+1, prev,nonce,
                                         child_id(policy,nonce),'0'*64,amount,
                                         state.allocated+amount)
                        try:
                            next_state=transition(state,grant,policy)
                        except ScopeError:
                            continue
                        self.assertEqual(next_state.allocated,state.allocated+amount)
                        self.assertLessEqual(next_state.allocated,policy.total_units)
                        new.append((next_state,grant.digest,seq+1,trace+[grant]))
                frontier=new
            self.assertGreater(visited,70)

    def test_quorum_intersections(self):
        for n in range(2,8):
            for f in range(n):
                for q in range(1,n+1):
                    if 2*q<=n+f:continue
                    quorums=[set(c) for c in itertools.combinations(range(n),q)]
                    for left in quorums:
                        for right in quorums:
                            self.assertGreater(len(left & right),f)

if __name__=='__main__':unittest.main()
