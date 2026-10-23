"""Pinned offline parent-root replay and certificate tamper cases."""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest
from demo_scope import generate
from verify_scope import replay
from scope import ScopeError

class ScopeVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle, cls.pins = generate()

    def test_full_offline_replay_and_deterministic_vectors(self):
        result = replay(self.bundle, self.pins)
        self.assertTrue(result['valid_grant'])
        self.assertEqual(result['allocated_units'], 10_000_000_000)
        self.assertEqual((self.bundle,self.pins), generate())
        root = Path(__file__).resolve().parent/'vectors'
        self.assertEqual(json.loads((root/'v09_root_grant.json').read_text()), self.bundle)
        self.assertEqual(json.loads((root/'v09_root_pins.json').read_text()), self.pins)

    def test_tamper_cert_and_pin_policies(self):
        edits = [
            lambda b: b['scope_history'][0]['votes'][0].update(signature_hex='0'*128),
            lambda b: b['scope_history'][0]['grant'].update(child_units=11_000_000_000),
            lambda b: b['scope_history'][0]['grant'].update(previous_digest='f'*64),
            lambda b: b['child_policy'].update(total_units=5_000_000_000),
            lambda b: b.update(schema='ACE-root-grant-demo-v0'),
            lambda b: b['scope_history'].clear(),
        ]
        for op in edits:
            b=deepcopy(self.bundle)
            op(b)
            with self.subTest(op=op), self.assertRaises((ScopeError,ValueError)):
                replay(b,self.pins)
        for key,value in [('scope_commitment','f'*64),('trusted_head','f'*64),
                          ('child_commitment','f'*64),('grant_digest','f'*64),
                          ('principal_id','evil'),('resource_id','attacker-resource')]:
            with self.subTest(pin=key), self.assertRaises(ScopeError):
                replay(self.bundle,{**self.pins,key:value})

    def test_cli_replay_duplicate_key_and_missing_pins(self):
        with tempfile.TemporaryDirectory() as t:
            b=Path(t)/'bundle.json';p=Path(t)/'pins.json'
            b.write_text(json.dumps(self.bundle,sort_keys=True))
            p.write_text(json.dumps(self.pins,sort_keys=True))
            cmd=[sys.executable,'verify_scope.py',str(b),'--pins',str(p)]
            done=subprocess.run(cmd,cwd=Path(__file__).resolve().parent,capture_output=True,text=True)
            self.assertEqual(done.returncode,0,done.stderr)
            self.assertTrue(json.loads(done.stdout)['valid_grant'])
            b.write_text('{"schema":"A","schema":"B"}')
            done=subprocess.run(cmd,cwd=Path(__file__).resolve().parent,capture_output=True,text=True)
            self.assertEqual(done.returncode,1)
            self.assertIn('duplicate JSON key',done.stderr)

if __name__ == '__main__':unittest.main()
