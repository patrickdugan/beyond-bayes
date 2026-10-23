"""Adversarial tests for independently replayed ACE v2 log certificates."""
from __future__ import annotations
from copy import deepcopy
from dataclasses import replace
from itertools import product
import json
import math
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

from certificates import InvalidCertificate
from clustered import Cluster, ClusterPlan
from clustered_certificate import (
    ActionIntent, AuthorizationPolicyV2, export_clustered_certificate,
    verify_clustered_certificate, unpack_cluster_plan, unpack_action,
)
from clustered_action_gate import ClusteredActionGate
from conditional import ConditionalNull, ConditionalRow, anytime_robust_max_log_e
from independent_cluster_verifier import _independent_score
from provenance import SignedObservation
from test_witnessed import setup, bit_reports
from witnessed import GENESIS_DIGEST, export_witnessed_certificate


def build_case(*, bits=None, cluster_size=2, budget=0, model=None, alpha=.05,
               incomplete=(), conflicting=()):
    protocol,keys,policy,logkey,wkeys,ws,log=setup(n=12)
    clusters=tuple(Cluster(f'group-{i//cluster_size}',
                   tuple(p.slot_id for p in protocol.slots[i:i+cluster_size]))
                   for i in range(0,12,cluster_size))
    plan=ClusterPlan(protocol,clusters,model or ConditionalNull.iid(.8,.2),budget,alpha)
    action=ActionIntent(protocol.challenge,'release-test-action','unit-test-vault',
                        {'amount':3,'network':'regtest'})
    bits=bits or [0]*(12//cluster_size)
    for i,slot in enumerate(protocol.slots):
        if i in incomplete:continue
        report=SignedObservation.issue(protocol,slot.slot_id,bits[i//cluster_size],keys[i])
        log.append(report)
        for w in ws[:3]:w.receive(report)
    for i in conflicting:
        report=SignedObservation.issue(protocol,protocol.slots[i].slot_id,
                    1-bits[i//cluster_size],keys[i])
        log.append(report)
        for w in ws[:3]:w.receive(report)
    head,proof=log.seal()
    approvals=[w.endorse(head,log.entries) for w in ws[:3]]
    cert=export_clustered_certificate(log,head,approvals,proof,
                                       plan=plan,action=action)
    auth=AuthorizationPolicyV2(protocol.commitment,policy.commitment,
                                plan.commitment,action.commitment)
    pins=dict(expected_protocol=protocol.commitment,expected_policy=policy.commitment,
              expected_cluster_plan=plan.commitment,expected_v2_policy=auth.commitment,
              expected_action=action.commitment,expected_challenge=protocol.challenge,
              expected_epoch=0,expected_previous_digest=GENESIS_DIGEST)
    return cert,pins,plan,action,(protocol,keys,policy,logkey,wkeys,ws,log,head)


class VersionedCertificateTests(unittest.TestCase):
    def test_witnessed_v2_authorizes_and_replays(self):
        cert,pins,plan,action,_=build_case()
        self.assertTrue(verify_clustered_certificate(cert,**pins).authorized)
        self.assertEqual(cert['claimed_decision_v2']['cluster_bits'],[0]*6)
        self.assertEqual(cert['witnessed_log_v1']['claimed_decision']['accepted_slots'],12)
        self.assertEqual(verify_clustered_certificate(cert,**pins).admitted_clusters,6)

    def test_v2_denies_even_if_legacy_v1_authorizes(self):
        cert,pins,_,_,_=build_case(alpha=1e-8)
        self.assertTrue(cert['witnessed_log_v1']['claimed_decision']['authorized'])
        self.assertFalse(cert['claimed_decision_v2']['authorized'])
        self.assertFalse(verify_clustered_certificate(cert,**pins).authorized)
        changed=deepcopy(cert)
        changed['claimed_decision_v2']['authorized']=True
        with self.assertRaises(InvalidCertificate):
            verify_clustered_certificate(changed,**pins)

    def test_cross_version_bundles_fully_rejected(self):
        cert,pins,_,_,_=build_case()
        for v in [cert['witnessed_log_v1'],{'schema':'ACE-witnessed-clustered-certificate-v1',
                                           **{k:v for k,v in cert.items() if k!='schema'}}]:
            with self.assertRaises(InvalidCertificate):
                verify_clustered_certificate(v,**pins)

    def test_every_trust_anchor_pin_is_required(self):
        cert,pins,_,_,_=build_case()
        for name in ('expected_protocol','expected_policy','expected_cluster_plan',
                     'expected_v2_policy','expected_action'):
            changed={**pins,name:'0'*64}
            with self.subTest(name=name), self.assertRaises(InvalidCertificate):
                verify_clustered_certificate(cert,**changed)
            changed={**pins,name:''}
            with self.subTest(name=name,absence=True), self.assertRaises(InvalidCertificate):
                verify_clustered_certificate(cert,**changed)
        with self.assertRaises(InvalidCertificate):
            verify_clustered_certificate(cert,**{**pins,'expected_challenge':'fake'})

    def test_payload_model_roster_budget_alpha_membership_tamper(self):
        cert,pins,_,_,_=build_case()
        edits=[
            lambda c:c['cluster_plan']['clusters'][0]['slot_ids'].append('slot-11'),
            lambda c:c['cluster_plan']['clusters'].reverse(),
            lambda c:c['cluster_plan']['conditional_null']['rows'][0].update(low=.7),
            lambda c:c['cluster_plan']['conditional_null']['rows'][0].update(bet_q=.1),
            lambda c:c['cluster_plan'].update(corruption_budget_clusters=2),
            lambda c:c['cluster_plan'].update(alpha=.1),
            lambda c:c['cluster_plan']['conditional_null'].update(version=99),
            lambda c:c['cluster_plan'].update(extra='injected'),
            lambda c:c['authorization_policy_v2'].update(cluster_plan_commitment='0'*64),
            lambda c:c['authorization_policy_v2'].update(action_commitment='0'*64),
            lambda c:c.update(authorization_policy_commitment='0'*64),
            lambda c:c['action_intent']['parameters'].update(amount=5),
            lambda c:c['action_intent'].update(operation='other-action'),
            lambda c:c['action_intent'].update(resource='mainnet-bitcoin'),
            lambda c:c['action_intent'].update(challenge='other-random-challenge'),
            lambda c:c['action_intent'].update(extra='injected'),
        ]
        for i,edit in enumerate(edits):
            changed=deepcopy(cert);edit(changed)
            with self.subTest(case=i),self.assertRaises(InvalidCertificate):
                verify_clustered_certificate(changed,**pins)

    def test_mutated_checkpoint_log_quorum_epoch_or_challenge_fails(self):
        cert,pins,_,_,_=build_case()
        edits=[
            lambda c:c['witnessed_log_v1']['complete_log'][0].update(bit=1),
            lambda c:c['witnessed_log_v1']['complete_log'][0].update(signature_hex='ff'*64),
            lambda c:c['witnessed_log_v1']['complete_log'].pop(),
            lambda c:c['witnessed_log_v1']['endorsements'].pop(),
            lambda c:c['witnessed_log_v1']['signed_head']['head'].update(epoch=1),
            lambda c:c['witnessed_log_v1']['signed_head']['head'].update(root_hex='0'*64),
            lambda c:c['witnessed_log_v1']['protocol'].update(challenge='another-challenge'),
        ]
        for i,edit in enumerate(edits):
            changed=deepcopy(cert);edit(changed)
            with self.subTest(case=i),self.assertRaises(InvalidCertificate):
                verify_clustered_certificate(changed,**pins)
        for key,value in [('expected_epoch',1),('expected_previous_digest','ff'*32)]:
            with self.assertRaises(InvalidCertificate):
                verify_clustered_certificate(cert,**{**pins,key:value})

    def test_mutated_decision_claims_and_unexpected_fields_fail(self):
        cert,pins,_,_,_=build_case()
        edits=[
            lambda c:c['claimed_decision_v2'].update(authorized=False),
            lambda c:c['claimed_decision_v2'].update(robust_max_log_e=math.nan),
            lambda c:c['claimed_decision_v2'].update(robust_max_log_e=0),
            lambda c:c['claimed_decision_v2'].update(cluster_bits=[0]*5+[1]),
            lambda c:c['claimed_decision_v2'].update(admitted_clusters=True),
            lambda c:c['claimed_decision_v2'].update(missing_clusters=2),
            lambda c:c['claimed_decision_v2'].update(conflicting_clusters=['group-0']),
            lambda c:c['claimed_decision_v2'].update(equivocated_slots=['unit-0']),
            lambda c:c['claimed_decision_v2'].update(quarantined_reports=1),
            lambda c:c.update(unexpected='extension'),
        ]
        for i,edit in enumerate(edits):
            changed=deepcopy(cert);edit(changed)
            with self.subTest(case=i),self.assertRaises(InvalidCertificate):
                verify_clustered_certificate(changed,**pins)

    def test_missing_signed_member_is_erasure_and_replays(self):
        cert,pins,plan,_,_=build_case(incomplete={1,3,5,7,9,11})
        self.assertEqual(cert['claimed_decision_v2']['cluster_bits'],[None]*6)
        self.assertFalse(verify_clustered_certificate(cert,**pins).authorized)

    def test_signed_member_conflict_fails_even_after_early_threshold(self):
        cert,pins,_,_,_=build_case(conflicting=(0,))
        self.assertFalse(verify_clustered_certificate(cert,**pins).authorized)
        self.assertEqual(cert['claimed_decision_v2']['equivocated_slots'],['unit-0'])
        self.assertFalse(cert['witnessed_log_v1']['claimed_decision']['authorized'])

    def test_two_individuals_disagree_within_cluster(self):
        cert,pins,_,_,_=build_case(bits=[0,0,0,0,0,0])
        # Generate genuine source disagreement through a fully new witnessed log.
        p,keys,policy,logkey,wkeys,ws,log=setup(n=12)
        clusters=tuple(Cluster(f'g{i}',(p.slots[2*i].slot_id,p.slots[2*i+1].slot_id))
                       for i in range(6))
        plan=ClusterPlan(p,clusters,ConditionalNull.iid(.8,.2),0)
        action=ActionIntent(p.challenge,'release-test-action','unit-test-vault',{})
        for i,s in enumerate(p.slots):
            bit=1 if i==1 else 0
            rep=SignedObservation.issue(p,s.slot_id,bit,keys[i]);log.append(rep)
            for w in ws[:3]:w.receive(rep)
        head,consistency=log.seal();endors=[w.endorse(head,log.entries) for w in ws[:3]]
        cert=export_clustered_certificate(log,head,endors,consistency,plan=plan,action=action)
        pol=AuthorizationPolicyV2(p.commitment,policy.commitment,plan.commitment,action.commitment)
        pins=dict(expected_protocol=p.commitment,expected_policy=policy.commitment,
                  expected_cluster_plan=plan.commitment,expected_v2_policy=pol.commitment,
                  expected_action=action.commitment,expected_challenge=p.challenge,
                  expected_epoch=0,expected_previous_digest=GENESIS_DIGEST)
        result=verify_clustered_certificate(cert,**pins)
        self.assertFalse(result.authorized)
        self.assertEqual(cert['claimed_decision_v2']['conflicting_clusters'],['g0'])

    def test_clone_report_neutral_but_log_root_binds_clone(self):
        a,pa,_,_,_=build_case()
        b,pb,plan,action,ctx=build_case()
        protocol,keys,policy,logkey,wkeys,ws,log,head=ctx
        # Reseal only after appending a report already in the log.
        report=log.entries[0];log.append(report)
        head2,cp=log.seal()
        end=[w.endorse(head2,log.entries) for w in ws[:3]]
        cert=export_clustered_certificate(log,head2,end,cp,plan=plan,action=action,
                                          previous_head=head.head)
        self.assertEqual(cert['claimed_decision_v2']['cluster_bits'],b['claimed_decision_v2']['cluster_bits'])
        self.assertEqual(cert['claimed_decision_v2']['robust_max_log_e'],b['claimed_decision_v2']['robust_max_log_e'])
        p2={**pb,'expected_epoch':1,'expected_previous_digest':head.head.digest}
        self.assertTrue(verify_clustered_certificate(cert,**p2).authorized)
        with self.assertRaises(InvalidCertificate):
            verify_clustered_certificate(cert,**pb)

    def test_v2_sqlite_gate_spends_nonce_and_persists_anchor(self):
        cert,pins,_,_,_=build_case()
        with tempfile.TemporaryDirectory() as tmp:
            gate=ClusteredActionGate(Path(tmp)/'spent.sqlite')
            args={k:v for k,v in pins.items() if k not in ('expected_epoch','expected_previous_digest')}
            first=gate.verify_and_consume(cert,**args)
            self.assertTrue(first.authorized)
            self.assertEqual(gate.anchor(pins['expected_policy']),
                             (0,first.checkpoint_digest))
            with self.assertRaisesRegex(InvalidCertificate,'consumed'):
                gate.verify_and_consume(cert,**args)
            with self.assertRaises(InvalidCertificate):
                gate.verify_and_consume(cert['witnessed_log_v1'],**args)

    def test_denied_checkpoint_progresses_before_later_authorization(self):
        p,keys,policy,logkey,wkeys,ws,log=setup(n=12)
        plan=ClusterPlan(p,tuple(Cluster(f'g{i}',tuple(s.slot_id for s in p.slots[i:i+2]))
                                  for i in range(0,12,2)),ConditionalNull.iid(.8,.2),0)
        action=ActionIntent(p.challenge,'release-test-action','sandbox',{})
        pol=AuthorizationPolicyV2(p.commitment,policy.commitment,plan.commitment,action.commitment)
        args=dict(expected_protocol=p.commitment,expected_policy=policy.commitment,
                  expected_cluster_plan=plan.commitment,expected_v2_policy=pol.commitment,
                  expected_action=action.commitment,expected_challenge=p.challenge)
        first=SignedObservation.issue(p,p.slots[0].slot_id,0,keys[0])
        log.append(first)
        for w in ws[:3]:w.receive(first)
        h0,c0=log.seal();e0=[w.endorse(h0,log.entries) for w in ws[:3]]
        cert0=export_clustered_certificate(log,h0,e0,c0,plan=plan,action=action)
        self.assertFalse(verify_clustered_certificate(cert0,**args,expected_epoch=0,
                             expected_previous_digest=GENESIS_DIGEST).authorized)
        with tempfile.TemporaryDirectory() as tmp:
            gate=ClusteredActionGate(Path(tmp)/'state.db')
            denied=gate.verify_and_consume(cert0,**args)
            self.assertFalse(denied.authorized)
            for i in range(1,12):
                report=SignedObservation.issue(p,p.slots[i].slot_id,0,keys[i]);log.append(report)
                for w in ws[:3]:w.receive(report)
            h1,c1=log.seal();e1=[w.endorse(h1,log.entries) for w in ws[:3]]
            cert1=export_clustered_certificate(log,h1,e1,c1,plan=plan,action=action,previous_head=h0.head)
            self.assertTrue(gate.verify_and_consume(cert1,**args).authorized)
            with self.assertRaises(InvalidCertificate):gate.verify_and_consume(cert1,**args)

    def test_cli_offline_and_duplicate_json_keys(self):
        cert,pins,_,_,_=build_case()
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'cert.json';path.write_text(json.dumps(cert))
            cmd=[sys.executable, str(Path(__file__).with_name('verify_clustered.py')),str(path)]
            for key,value in pins.items():
                cmd+=['--'+key.replace('_','-'),str(value)]
            run=subprocess.run(cmd,capture_output=True,text=True,check=False)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertTrue(json.loads(run.stdout)['authorized'])
            path.write_text('{"schema": "x", "schema": "y"}')
            run=subprocess.run(cmd,capture_output=True,text=True,check=False)
            self.assertEqual(run.returncode,1)
            self.assertIn('duplicate JSON object key',run.stderr)


class IndependentVerifierDifferentialTests(unittest.TestCase):
    def test_exhaustive_all_short_ternary_traces_two_models(self):
        _,_,p,_,_=build_case()
        models=[ConditionalNull.iid(.8,.2),ConditionalNull.markov(
            initial=(.7,.85),after_zero=(.6,.8),after_one=(.8,.95),bet_q=.2)]
        for model in models:
            plan=ClusterPlan(p.protocol,p.clusters,model,0)
            for n in range(0,6):
                for seq in product((0,1,None),repeat=n):
                    for budget in (0,1,2):
                        active=replace(plan,corruption_budget_clusters=budget)
                        known=anytime_robust_max_log_e(seq,budget,model)
                        observed=_independent_score(seq,active)
                        self.assertAlmostEqual(observed,known,places=11)

    def test_state_history_updates_from_clean_candidates(self):
        _,_,plan,_,_=build_case()
        model=ConditionalNull.markov(initial=(.8,.9),after_zero=(.65,.77),
                                     after_one=(.85,.98),bet_q=.2)
        plan=replace(plan,null=model,corruption_budget_clusters=1)
        obs=(0,1,None,0,0,1,0)
        self.assertAlmostEqual(_independent_score(obs,plan),
                     anytime_robust_max_log_e(obs,1,model),places=12)


if __name__=='__main__': unittest.main()
