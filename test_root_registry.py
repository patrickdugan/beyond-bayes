"""Adversarial root registry tests: enrollment, closing proofs, rollover, rollback."""
from __future__ import annotations
from dataclasses import replace
from pathlib import Path
import hashlib
import shutil
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from anchor import AnchorIdentity
from witnessed import _key_hex, GENESIS_DIGEST
from scope import ScopePolicy, ScopeReplica, ScopeQuorum
from root_registry import (RegistryPolicy, InstrumentIdentity, RegistryError, RegistryReplica,
                           RegistryQuorum, RegistryCertificate, RegistryEvent,
                           unpack_event, unpack_policy, unpack_certificate, verify_history, verify_certificate)
from test_scope import child_fixture


def key(label):return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def registry_fixture(path):
    keys=[key(f'v10-registry-{i}') for i in range(4)]
    admin=key('v10-admin'); instrument=key('v10-device')
    ids=tuple(AnchorIdentity(f'registry-{i}',_key_hex(k)) for i,k in enumerate(keys))
    policy=RegistryPolicy('ace-global-root-directory-2026',_key_hex(admin),ids,1,3,
                          (InstrumentIdentity('instrument-alpha',_key_hex(instrument),1),))
    replicas=[RegistryReplica(policy,f'registry-{i}',k,path/f'registry-{i}.sqlite') for i,k in enumerate(keys)]
    return policy,admin,instrument,replicas,RegistryQuorum(policy,replicas)


def scope_fixture(path,identifier,budget):
    keys=[key(f'v10-scope-{identifier}-{i}') for i in range(4)]
    ids=tuple(AnchorIdentity(f'root-{i}',_key_hex(k)) for i,k in enumerate(keys))
    policy=ScopePolicy(identifier+'-scope','org-demo','protected-action',budget,ids,1,3)
    replicas=[ScopeReplica(policy,f'root-{i}',k,path/f'{identifier}-root-{i}.sqlite') for i,k in enumerate(keys)]
    return policy, ScopeQuorum(policy,replicas)


class RootRegistryTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.path=Path(tmp.name)
        self.policy,self.admin,self.device,self.replicas,self.reg=registry_fixture(self.path)
        self.root,self.root_quorum=scope_fixture(self.path,'root-alpha-2026',50_000_000_000)

    def test_enrollment_and_signed_history(self):
        cert=self.reg.enroll(self.root,50_000_000_000,self.admin)
        self.assertTrue(verify_certificate(cert,self.policy))
        self.assertEqual(unpack_event(cert.event.canonical()),cert.event)
        self.assertEqual(unpack_policy(self.policy.canonical()),self.policy)
        self.assertEqual(unpack_certificate(cert.canonical()),cert)
        view=self.reg.current()
        self.assertEqual(view.state.active[('org-demo','protected-action')].scope,self.root)
        self.assertEqual(verify_history(view.certificates,self.policy,view.head),view.state)
        with self.assertRaises(RegistryError):
            verify_history(view.certificates,self.policy,'f'*64)

    def test_second_root_reset_fails_and_admin_required(self):
        self.reg.enroll(self.root,50_000_000_000,self.admin)
        other,_=scope_fixture(self.path,'root-beta-2026',50_000_000_000)
        with self.assertRaises(RegistryError):self.reg.enroll(other,50_000_000_000,self.admin)
        with self.assertRaises(RegistryError):self.reg.rollover(self.root_quorum,other,key('attacker-admin'))
        with self.assertRaises(RegistryError):self.reg.enroll(self.root,50_000_000_000,self.admin)
        self.assertEqual(self.reg.current().sequence,1)

    def test_rollover_carries_spent_budget_and_forbids_reusing_scope_id(self):
        self.reg.enroll(self.root,50_000_000_000,self.admin)
        child,_keys,_replicas,_quorum=child_fixture(self.path,self.root,nonce='child-budget-00001',units=20_000_000_000)
        self.root_quorum.allocate(child,'child-budget-00001')
        second,second_quorum=scope_fixture(self.path,'root-beta-2026',30_000_000_000)
        cert=self.reg.rollover(self.root_quorum,second,self.admin)
        self.assertEqual(cert.event.lifetime_allocated,20_000_000_000)
        state=self.reg.current().state.active[('org-demo','protected-action')]
        self.assertEqual(state.lifetime_allocated,20_000_000_000)
        self.assertEqual(state.scope,second)
        with self.assertRaises(RegistryError):
            self.reg.require_active(self.root,expected_principal='org-demo',expected_resource='protected-action')
        with self.assertRaises(RegistryError):
            self.reg.rollover(second_quorum,self.root,self.admin)
        too_large,_=scope_fixture(self.path,'root-overcap-2026',31_000_000_000)
        with self.assertRaises(RegistryError):self.reg.rollover(second_quorum,too_large,self.admin)
        third,_=scope_fixture(self.path,'root-gamma-2026',25_000_000_000)
        self.reg.rollover(second_quorum,third,self.admin)
        self.assertEqual(self.reg.current().state.active[('org-demo','protected-action')].lifetime_allocated,20_000_000_000)

    def test_reject_unsigned_or_tampered_closing_history(self):
        self.reg.enroll(self.root,50_000_000_000,self.admin)
        child,_,_,_=child_fixture(self.path,self.root,nonce='child-budget-00002',units=20_000_000_000)
        self.root_quorum.allocate(child,'child-budget-00002')
        second,_=scope_fixture(self.path,'root-next-2026',30_000_000_000)
        first=self.reg.current();closing=self.root_quorum.current()
        proto=RegistryEvent(self.policy.commitment,2,first.head,'rollover',second,
                            self.root.commitment,closing.head,(),50_000_000_000,20_000_000_000)
        with self.assertRaises(RegistryError):self.reg._publish(proto,self.admin)
        self.assertEqual(self.reg.current().sequence,1)

    def test_one_rollback_safe_two_suspends_and_replay_fork(self):
        self.reg.enroll(self.root,50_000_000_000,self.admin)
        backups=[]
        for i in range(2):
            path=self.path/f'registry-{i}.sqlite';back=self.path/f'old-registry-{i}.sqlite'
            shutil.copyfile(path,back);backups.append((path,back))
        second,_=scope_fixture(self.path,'root-second-2026',50_000_000_000)
        cert=self.reg.rollover(self.root_quorum,second,self.admin)
        shutil.copyfile(backups[0][1],backups[0][0])
        self.assertEqual(self.reg.current().head,cert.event.digest)
        shutil.copyfile(backups[1][1],backups[1][0])
        with self.assertRaises(RegistryError):self.reg.current()
        third,_=scope_fixture(self.path,'root-third-2026',50_000_000_000)
        with self.assertRaises(RegistryError):self.reg.rollover(self.root_quorum,third,self.admin)

    def test_malicious_or_duplicate_votes_fail(self):
        cert=self.reg.enroll(self.root,50_000_000_000,self.admin)
        self.assertFalse(verify_certificate(replace(cert,administrator_signature='0'*128),self.policy))
        self.assertFalse(verify_certificate(replace(cert,votes=cert.votes[:2]),self.policy))
        self.assertFalse(verify_certificate(replace(cert,votes=(cert.votes[0],)*3),self.policy))
        self.assertFalse(verify_certificate(replace(cert,event=replace(cert.event,cap_units=49_000_000_000)),self.policy))

if __name__=='__main__':unittest.main()
