"""ACE v0.9 root-budget tests on four separately journaled Ed25519 replicas."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import hashlib
import shutil
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from anchor import AnchorIdentity
from campaign import CampaignPolicy, CampaignReplica, CampaignQuorum, CampaignError, SCALE
from campaign_certificate import campaign_context, export_attempt
from clustered import Cluster, ClusterPlan
from conditional import ConditionalNull
from clustered_certificate import ActionIntent, AuthorizationPolicyV2, export_clustered_certificate
from provenance import SignedObservation
from test_witnessed import setup
from witnessed import GENESIS_DIGEST, _key_hex
from scope import (ScopePolicy, ScopeReplica, ScopeQuorum, ScopeActionGate,
                   ScopeError, ScopeGrant, ScopeCertificate, ScopeState,
                   child_id, transition, verify_certificate, verify_history,
                   check_child_policy, action_scope_context, unpack_policy,
                   unpack_certificate)


def identity_fixture(root: Path, *, units=50_000_000_000, principal='root-org-A',
                     resource='high-risk-agent-actions'):
    keys = [Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
            f'ACE-scope-key-{i}'.encode()).digest()) for i in range(4)]
    ids = tuple(AnchorIdentity(f'root-{i}', _key_hex(k)) for i, k in enumerate(keys))
    policy = ScopePolicy('root-scope-2026-alpha', principal, resource, units, ids, 1, 3)
    replicas = [ScopeReplica(policy, f'root-{i}', k, root / f'root-{i}.sqlite')
                for i, k in enumerate(keys)]
    return policy, keys, replicas, ScopeQuorum(policy, replicas)


def child_fixture(root: Path, parent: ScopePolicy, *, nonce: str, units: int):
    keys = [Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
            f'ACE-scope-child-{nonce}-{i}'.encode()).digest()) for i in range(4)]
    ids = tuple(AnchorIdentity(f'child-{i}', _key_hex(k)) for i, k in enumerate(keys))
    policy = CampaignPolicy(child_id(parent, nonce), units, ids, 1, 3)
    replicas = [CampaignReplica(policy, f'child-{i}', k, root / f'{nonce}-{i}.sqlite')
                for i, k in enumerate(keys)]
    return policy, keys, replicas, CampaignQuorum(policy, replicas)


def scoped_attempt(quorum: CampaignQuorum, parent: ScopePolicy, grant: ScopeGrant):
    """Reserve *before* emitting signed synthetic sensor measurements."""
    protocol, keys, witnesspolicy, logkey, witnesskeys, witnesses, log = setup(n=12)
    plan = ClusterPlan(protocol, tuple(Cluster(f'cluster-{i // 2}', (
             protocol.slots[i].slot_id, protocol.slots[i + 1].slot_id))
             for i in range(0, 12, 2)), ConditionalNull.iid(.8, .2), 0, .01)
    view = quorum.current()
    units = 10_000_000_000
    action = ActionIntent(protocol.challenge, 'test-action', parent.resource_id,
        {'amount': 1, 'network': 'regtest',
         'ace_campaign': campaign_context(quorum.policy, previous_digest=view.head,
               sequence=view.sequence + 1, alpha_units=units,
               spent_units=view.state.spent + units),
         'ace_scope': action_scope_context(parent, grant)})
    auth = AuthorizationPolicyV2(protocol.commitment, witnesspolicy.commitment,
                                  plan.commitment, action.commitment)
    reserved = quorum.reserve(challenge=action.challenge, protocol=protocol.commitment,
                              witness_policy=witnesspolicy.commitment,
                              cluster_plan=plan.commitment, v2_policy=auth.commitment,
                              action=action.commitment, alpha_units=units)
    for i, slot in enumerate(protocol.slots):
        report = SignedObservation.issue(protocol, slot.slot_id, 0, keys[i])
        log.append(report)
        for w in witnesses[:3]:
            w.receive(report)
    head, proof = log.seal()
    endorsements = [w.endorse(head, log.entries) for w in witnesses[:3]]
    v2 = export_clustered_certificate(log, head, endorsements, proof, plan=plan, action=action)
    finalized = quorum.finalize(reserved, v2_certificate=v2,
                                 authorized=v2['claimed_decision_v2']['authorized'])
    return export_attempt(reserved, finalized, v2)


class ScopeBudgetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.policy, self.keys, self.replicas, self.quorum = identity_fixture(self.root)

    def child(self, i: int, *, units=10_000_000_000):
        nonce = f'child-nonce-{i:05d}-test'
        return nonce, child_fixture(self.root, self.policy, nonce=nonce, units=units)

    def test_exact_parent_accounting_and_unrefundable_children(self):
        for i in range(5):
            nonce, (child, _, _, _) = self.child(i)
            ticket = self.quorum.allocate(child, nonce)
            self.assertTrue(verify_certificate(ticket, self.policy))
            self.assertEqual(ticket.grant.allocated_units, 10_000_000_000*(i+1))
        current = self.quorum.current()
        self.assertEqual(current.state.allocated, self.policy.total_units)
        self.assertEqual(len(current.state.child_ids), 5)
        self.assertEqual(verify_history(current.history, self.policy,
                         expected_head=current.head), current.state)
        nonce, (child, _, _, _) = self.child(5)
        with self.assertRaises(ScopeError):
            self.quorum.allocate(child, nonce)
        # Discarding a child's database cannot recover the root allocation.
        self.assertEqual(self.quorum.current().state.allocated, self.policy.total_units)

    def test_duplicate_child_denied_even_after_child_restart(self):
        nonce, (child, _, _, _) = self.child(0)
        first = self.quorum.allocate(child, nonce)
        with self.assertRaises(ScopeError):
            self.quorum.allocate(child, nonce)
        self.assertEqual(self.quorum.current().head, first.grant.digest)

    def test_policy_binding_across_resource_principal_and_roster(self):
        nonce, (child, _, _, _) = self.child(0)
        ticket = self.quorum.allocate(child, nonce)
        check_child_policy(self.policy, ticket.grant, child)
        self.assertEqual(unpack_policy(self.policy.canonical()), self.policy)
        self.assertEqual(unpack_certificate(ticket.canonical()), ticket)
        other_parent = replace(self.policy, resource_id='another-high-risk-resource')
        with self.assertRaises(ScopeError):
            check_child_policy(other_parent, ticket.grant, child)
        with self.assertRaises(ScopeError):
            self.quorum.allocate(replace(child, campaign_id='unscoped-child-identity'), nonce)
        with self.assertRaises(ScopeError):
            check_child_policy(self.policy, ticket.grant,
                               replace(child, total_units=5_000_000_000))

    def test_certificate_signature_and_external_head_checks(self):
        nonce, (child, _, _, _) = self.child(0)
        cert = self.quorum.allocate(child, nonce)
        bad_vote = replace(cert.votes[0], signature_hex='0'*128)
        self.assertFalse(verify_certificate(replace(cert, votes=(bad_vote,)+cert.votes[1:]), self.policy))
        self.assertFalse(verify_certificate(replace(cert, votes=cert.votes[:2]), self.policy))
        altered = replace(cert.grant, child_units=9_000_000_000)
        self.assertFalse(verify_certificate(replace(cert, grant=altered), self.policy))
        with self.assertRaises(ScopeError):
            verify_history((cert,), self.policy, expected_head='f'*64)
        self.assertEqual(verify_history((cert,), self.policy, expected_head=cert.grant.digest).allocated,
                         10_000_000_000)

    def test_reject_two_parent_rollback_and_succeed_with_one(self):
        backups=[]
        for i in range(2):
            path = self.root/f'root-{i}.sqlite'
            backup = self.root/f'snapshot-{i}.sqlite'
            shutil.copyfile(path, backup)
            backups.append((path, backup))
        nonce, (child, _, _, _) = self.child(0)
        self.quorum.allocate(child, nonce)
        shutil.copyfile(*reversed(backups[0]))
        self.assertEqual(self.quorum.current().state.allocated, 10_000_000_000)
        shutil.copyfile(*reversed(backups[1]))
        with self.assertRaises(ScopeError):
            self.quorum.current()
        nonce, (child, _, _, _) = self.child(1)
        with self.assertRaises(ScopeError):
            self.quorum.allocate(child, nonce)

    def test_partial_grant_commit_suspends_and_recovers_identical_record(self):
        nonce, (child, _, _, _) = self.child(0)
        originals = [self.replicas[i].vote for i in (2, 3)]
        for i in (2, 3):
            self.replicas[i].vote = lambda _grant: (_ for _ in ()).throw(ScopeError('replica unavailable'))
        with self.assertRaises(ScopeError):
            self.quorum.allocate(child, nonce)
        with self.assertRaises(ScopeError):
            self.quorum.current()
        for i, fn in zip((2, 3), originals):
            self.replicas[i].vote = fn
        event = self.replicas[0].history()[0][0]
        approvals = tuple(r.vote(event) for r in self.replicas)
        self.assertTrue(verify_certificate(ScopeCertificate(event, approvals), self.policy))
        self.assertEqual(self.quorum.current().head, event.digest)

    def test_scoped_action_gate_checks_live_grant_and_uses_child_replay(self):
        nonce, (child, _, _, child_quorum) = self.child(0)
        grant = self.quorum.allocate(child, nonce)
        wrapper = scoped_attempt(child_quorum, self.policy, grant.grant)
        gate = ScopeActionGate(self.quorum, child_quorum,
                               expected_principal=self.policy.principal_id,
                               expected_resource=self.policy.resource_id)
        result = gate.check_and_consume(wrapper, expected_v2_epoch=0,
                                        expected_v2_previous_digest=GENESIS_DIGEST)
        self.assertTrue(result.authorized)
        self.assertEqual(child_quorum.current().state.stage, 'consumed')
        with self.assertRaises(CampaignError):
            gate.check_and_consume(wrapper, expected_v2_epoch=0,
                                   expected_v2_previous_digest=GENESIS_DIGEST)

    def test_cross_scope_and_tampered_binding_fail_before_child_consumption(self):
        nonce, (child, _, _, child_quorum) = self.child(0)
        grant = self.quorum.allocate(child, nonce)
        wrapper = scoped_attempt(child_quorum, self.policy, grant.grant)
        with self.assertRaises(ScopeError):
            ScopeActionGate(self.quorum, child_quorum, expected_principal='attacker',
                            expected_resource=self.policy.resource_id)
        gate = ScopeActionGate(self.quorum, child_quorum,
                               expected_principal=self.policy.principal_id,
                               expected_resource=self.policy.resource_id)
        changed = deepcopy(wrapper)
        changed['v2_certificate']['action_intent']['parameters']['ace_scope']['grant_digest'] = 'f'*64
        with self.assertRaises(ScopeError):
            gate.check_and_consume(changed, expected_v2_epoch=0,
                                   expected_v2_previous_digest=GENESIS_DIGEST)
        self.assertEqual(child_quorum.current().state.stage, 'authorized')
        misrouted = deepcopy(wrapper)
        misrouted['v2_certificate']['action_intent']['resource'] = 'unapproved-resource'
        with self.assertRaises(ScopeError):
            gate.check_and_consume(misrouted, expected_v2_epoch=0,
                                   expected_v2_previous_digest=GENESIS_DIGEST)
        gate.check_and_consume(wrapper, expected_v2_epoch=0,
                               expected_v2_previous_digest=GENESIS_DIGEST)

if __name__ == '__main__':
    unittest.main()
