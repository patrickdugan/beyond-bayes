"""Offline synthetic replay, tampering, and JSON canonicality checks."""
from __future__ import annotations
from copy import deepcopy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from certificates import InvalidCertificate
from campaign_certificate import campaign_context
from demo_campaign import generate
from verify_campaign import replay
from campaign import CampaignError

class PinnedCampaignVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle,cls.pins=generate()

    def test_independent_replay(self):
        value=replay(self.bundle,self.pins)
        self.assertEqual(value['reserved_alpha'],.01)
        self.assertEqual(value['total_alpha_spent'],.01)
        self.assertTrue(value['authorized'])

    def test_tampering_breaks_commitment(self):
        ops=[
            lambda b:b['consumption']['record']['payload'].update(finalization_digest='f'*64),
            lambda b:b['consumption']['record'].update(sequence=1),
            lambda b:b['consumption']['votes'][0].update(signature_hex='0'*128),
            lambda b:b['campaign_policy'].update(total_units=999),
            lambda b:b['attempt']['v2_certificate']['action_intent']['parameters']['ace_campaign'].update(alpha_units=50_000_000_000),
            lambda b:b['attempt']['v2_certificate']['action_intent']['parameters']['ace_campaign'].update(spent_units=20_000_000_000),
            lambda b:b['attempt']['v2_certificate']['action_intent']['parameters']['ace_campaign'].update(campaign_commitment='f'*64),
            lambda b:b['attempt']['reservation']['record']['payload'].update(alpha_units=50_000_000_000),
            lambda b:b['attempt']['v2_certificate']['cluster_plan'].update(alpha=.05),
            lambda b:b['attempt']['finalization']['record']['payload'].update(authorized=False),
            lambda b:b['attempt']['finalization']['record'].update(previous_digest='f'*64),
            lambda b:b.update(schema='ACE-campaign-authorization-v1'),
        ]
        for i,op in enumerate(ops):
            b=deepcopy(self.bundle);op(b)
            with self.subTest(i=i),self.assertRaises((InvalidCertificate,CampaignError)):
                replay(b,self.pins)

    def test_unpinned_alphas_and_campaign_ids_rejected(self):
        edits=[
          ('campaign_commitment','f'*64),('reservation_digest','f'*64),
          ('finalization_digest','f'*64),('consumption_digest','f'*64),
          ('previous_campaign_digest','f'*64),('previous_spent_units',5),
          ('v2_previous_digest','f'*64),('v2_epoch',5),
        ]
        for key,value in edits:
            p={**self.pins,key:value}
            with self.subTest(pin=key),self.assertRaises((InvalidCertificate,CampaignError)):
                replay(self.bundle,p)
        no_pins={**self.pins};no_pins.pop('campaign_policy')
        with self.assertRaises(InvalidCertificate):replay(self.bundle,no_pins)

    def test_checked_in_cross_process_fixture_matches(self):
        root=Path(__file__).resolve().parent
        self.assertEqual(json.loads((root/'vectors/v08_campaign_demo.json').read_text()),self.bundle)
        self.assertEqual(json.loads((root/'vectors/v08_campaign_pins.json').read_text()),self.pins)

    def test_demo_is_bitwise_deterministic_and_cli_replays(self):
        b2,p2=generate()
        self.assertEqual(b2,self.bundle)
        self.assertEqual(p2,self.pins)
        with tempfile.TemporaryDirectory() as td:
            a=Path(td)/'cert.json';p=Path(td)/'pins.json'
            a.write_text(json.dumps(self.bundle,sort_keys=True))
            p.write_text(json.dumps(self.pins,sort_keys=True))
            proc=subprocess.run([sys.executable,'verify_campaign.py',str(a),'--pins',str(p)],
                                capture_output=True,text=True,check=False)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertTrue(json.loads(proc.stdout)['authorized'])
            a.write_text('{"schema":1,"schema":2}')
            proc=subprocess.run([sys.executable,'verify_campaign.py',str(a),'--pins',str(p)],
                                capture_output=True,text=True,check=False)
            self.assertEqual(proc.returncode,1)
            self.assertIn('duplicate JSON key',proc.stderr)

if __name__=='__main__':unittest.main()
