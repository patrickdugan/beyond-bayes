"""Signed-before-sampling ordering tests with an explicitly simulated device."""
from __future__ import annotations
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import tempfile
import shutil
import unittest

from campaign_certificate import campaign_context
from clustered import Cluster,ClusterPlan
from clustered_certificate import ActionIntent,AuthorizationPolicyV2
from conditional import ConditionalNull
from measurement_start import (StartReplica,StartQuorum,StartError,SimulatedInstrument,
                               StartRecord,StartCertificate,TimedObservation,
                               verify_certificate,verify_history,verify_observations,
                               unpack_certificate,unpack_observation)
from root_registry import RegistryError
from scope import action_scope_context
from test_root_registry import registry_fixture,scope_fixture
from test_scope import child_fixture
from test_witnessed import setup
from witnessed import _check_sig
from provenance import _encoding


def started_fixture(path,*,instrument='instrument-alpha',samples=4,scope_identifier='root-alpha-2026'):
    policy,admin,instrument_key,registry_replicas,registry=registry_fixture(path)
    scope,root=scope_fixture(path,scope_identifier,50_000_000_000)
    registry.enroll(scope,50_000_000_000,admin)
    nonce='child-start-nonce-2026'
    cp,ck,cr,child=child_fixture(path,scope,nonce=nonce,units=10_000_000_000)
    grant=root.allocate(cp,nonce)
    protocol,keys,witnesspolicy,logkey,witnesskeys,witnesses,log=setup(n=4)
    plan=ClusterPlan(protocol,tuple(Cluster(f'cluster-{i}',(s.slot_id,)) for i,s in enumerate(protocol.slots)),ConditionalNull.iid(.8,.2),0,.01)
    cv=child.current()
    action=ActionIntent(protocol.challenge,'measure-and-test',scope.resource_id,
             {'ace_campaign':campaign_context(cp,previous_digest=cv.head,sequence=cv.sequence+1,
                     alpha_units=10_000_000_000,spent_units=10_000_000_000),
              'ace_scope':action_scope_context(scope,grant.grant),
              'ace_registry':registry.policy.commitment})
    auth=AuthorizationPolicyV2(protocol.commitment,witnesspolicy.commitment,plan.commitment,action.commitment)
    reserved=child.reserve(challenge=protocol.challenge,protocol=protocol.commitment,
                       witness_policy=witnesspolicy.commitment,cluster_plan=plan.commitment,
                       v2_policy=auth.commitment,action=action.commitment,alpha_units=10_000_000_000)
    signing=[StartReplica(registry,root,child,x.id,x.key,path/f'start-{x.id}.sqlite') for x in registry_replicas]
    starts=StartQuorum(registry,root,child,signing)
    device=SimulatedInstrument(policy.enrolled_instrument(instrument),instrument_key,policy)
    binding=starts.make_binding(protocol=protocol.commitment,witness_policy=witnesspolicy.commitment,
                cluster_plan=plan.commitment,v2_policy=auth.commitment,action=action.commitment,
                instrument_id=instrument,counter_start=device.counter,max_samples=samples,
                experiment_nonce='exp-nonce-signer-2026')
    return locals()


class StartWitnessTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.path=Path(tmp.name)
        self.f=started_fixture(self.path)

    def issue(self):
        f=self.f
        arm=f['device'].arm(f['binding'])
        cert=f['starts'].issue(f['binding'],arm)
        return cert

    def test_prestart_rejected_and_witnessed_device_receipt_accepted(self):
        f=self.f
        with self.assertRaises(StartError):f['device'].sample(f['protocol'],f['protocol'].slots[0].slot_id,0,f['keys'][0])
        cert=self.issue()
        self.assertTrue(verify_certificate(cert,f['policy']))
        f['device'].activate(cert)
        readings=[f['device'].sample(f['protocol'],s.slot_id,0,f['keys'][i]) for i,s in enumerate(f['protocol'].slots)]
        self.assertEqual(len(verify_observations(cert,readings,f['protocol'],f['policy'])),4)
        self.assertEqual(unpack_certificate(cert.canonical()),cert)
        self.assertEqual(unpack_observation(readings[0].canonical()),readings[0])
        with self.assertRaises(StartError):f['device'].sample(f['protocol'],f['protocol'].slots[0].slot_id,0,f['keys'][0])
        v=f['starts'].current()
        self.assertEqual(verify_history(v.history,f['policy'],v.head),v.state)

    def test_preexisting_source_report_cannot_be_used_as_instrument_measurement(self):
        # A preexisting report has a valid SOURCE signature. It lacks an instrument
        # counter and a witnessed binding; the new admission verifier rejects it.
        f=self.f
        from provenance import SignedObservation
        report=SignedObservation.issue(f['protocol'],f['protocol'].slots[0].slot_id,0,f['keys'][0])
        cert=self.issue()
        from measurement_start import TimedObservation
        fake=TimedObservation(cert.record.digest,'instrument-alpha',1,1,report,'0'*128)
        with self.assertRaises(StartError):verify_observations(cert,[fake],f['protocol'],f['policy'])

    def test_instrument_and_start_tampering_rejected(self):
        f=self.f;cert=self.issue();f['device'].activate(cert)
        reading=f['device'].sample(f['protocol'],f['protocol'].slots[0].slot_id,0,f['keys'][0])
        mutations=[replace(reading,counter=2),replace(reading,start_digest='f'*64),
                   replace(reading,epoch=2),replace(reading,signature_hex='0'*128),
                   replace(reading,instrument_id='attacker')]
        for edit in mutations:
            with self.subTest(edit=edit), self.assertRaises(StartError):verify_observations(cert,[edit],f['protocol'],f['policy'])
        with self.assertRaises(StartError):verify_observations(cert,[reading,reading],f['protocol'],f['policy'])
        altered=replace(cert.record.binding,action='f'*64)
        self.assertFalse(verify_certificate(replace(cert,record=replace(cert.record,binding=altered)),f['policy']))
        self.assertFalse(verify_certificate(replace(cert,votes=cert.votes[:2]),f['policy']))

    def test_child_reservation_and_root_scope_required_at_witness(self):
        f=self.f
        bad=replace(f['binding'],reservation='f'*64)
        with self.assertRaises(StartError):f['starts'].issue(bad,f['device'].arm(bad))
        second,second_quorum=scope_fixture(self.path,'root-beta-2026',40_000_000_000)
        f['registry'].rollover(f['root'],second,f['admin'])
        with self.assertRaises(StartError):f['starts'].issue(f['binding'],f['device'].arm(f['binding']))

    def test_replays_duplicate_nonce_and_counter_reuse_fail(self):
        f=self.f;cert=self.issue()
        with self.assertRaises(StartError):f['starts'].issue(f['binding'],f['device'].arm(f['binding']))
        # Start counter cannot be rolled backwards by restoring only the device.
        f['device'].activate(cert)
        f['device'].close()
        b2=replace(f['binding'],experiment_nonce='experiment-second-2026')
        with self.assertRaises(StartError):f['starts'].issue(b2,f['device'].arm(b2))

    def test_one_rollback_safe_two_fail_closed(self):
        f=self.f
        backups=[]
        for i in range(2):
            r=f['signing'][i]
            src=Path(r.db_path);backup=self.path/f'backup-{i}.sqlite'
            shutil.copyfile(src,backup);backups.append((src,backup))
        cert=self.issue()
        shutil.copyfile(backups[0][1],backups[0][0])
        self.assertEqual(f['starts'].current().head,cert.record.digest)
        shutil.copyfile(backups[1][1],backups[1][0])
        with self.assertRaises(StartError):f['starts'].current()

if __name__=='__main__':unittest.main()
