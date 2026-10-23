"""Offline replay, signed counter vector, malformed JSON and cross-scope attacks."""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

from demo_measurement import generate
from verify_measurement import replay,StartError
from root_registry import RegistryError
from scope import ScopeError
from certificates import InvalidCertificate


class OfflineMeasurementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle,cls.pins=generate()

    def test_pinned_offline_replay_and_deterministic_vectors(self):
        result=replay(self.bundle,self.pins)
        self.assertTrue(result['verified'])
        self.assertEqual(result['samples'],4)
        self.assertEqual((self.bundle,self.pins),generate())
        vectors=Path(__file__).resolve().parent/'vectors'
        self.assertEqual(json.loads((vectors/'v10_measurement.json').read_text()),self.bundle)
        self.assertEqual(json.loads((vectors/'v10_measurement_pins.json').read_text()),self.pins)

    def test_context_tampering(self):
        edits=[
            lambda b:b['registry_history'][0]['event']['new_scope'].update(total_units=1),
            lambda b:b['registry_history'][0]['administrator_signature'].__class__,
            lambda b:b['registry_history'][0].update(administrator_signature='0'*128),
            lambda b:b['scope_history'][0]['grant'].update(child_units=1),
            lambda b:b['reservation_certificate']['record']['payload'].update(alpha_units=1),
            lambda b:b['start_history'][0]['record']['binding'].update(reservation='f'*64),
            lambda b:b['start_history'][0]['record'].update(arm_signature='0'*128),
            lambda b:b['start_history'][0]['votes'][0].update(signature_hex='0'*128),
            lambda b:b['v2_certificate']['action_intent'].update(operation='malicious'),
            lambda b:b['instrument_measurements'][0].update(counter=2),
            lambda b:b['instrument_measurements'][0].update(start_digest='f'*64),
            lambda b:b['instrument_measurements'][0]['report'].update(bit=1),
            lambda b:b['instrument_measurements'][0].update(signature_hex='0'*128),
            lambda b:b['v2_certificate']['witnessed_log_v1']['complete_log'].pop(),
            lambda b:b['instrument_measurements'].pop(),
            lambda b:b['instrument_measurements'].append(deepcopy(b['instrument_measurements'][-1])),
        ]
        for i,op in enumerate(edits):
            if i==1:continue
            b=deepcopy(self.bundle);op(b)
            with self.subTest(i=i),self.assertRaises((StartError,ScopeError,RegistryError,InvalidCertificate,ValueError,TypeError)):
                replay(b,self.pins)

    def test_wrong_pin_rejection(self):
        for key in self.pins:
            pins=dict(self.pins)
            if key=='expected_v2_epoch':pins[key]=1
            else:pins[key]='f'*64
            with self.subTest(pin=key),self.assertRaises((StartError,ScopeError,RegistryError,InvalidCertificate,ValueError,TypeError)):
                replay(self.bundle,pins)

    def test_cli_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);f=root/'cert.json';p=root/'pins.json'
            f.write_text(json.dumps(self.bundle));p.write_text(json.dumps(self.pins))
            args=[sys.executable,'verify_measurement.py',str(f),'--pins',str(p)]
            done=subprocess.run(args,cwd=Path(__file__).resolve().parent,capture_output=True,text=True)
            self.assertEqual(done.returncode,0,done.stderr)
            self.assertTrue(json.loads(done.stdout)['verified'])
            f.write_text('{"schema":"X","schema":"Y"}')
            done=subprocess.run(args,cwd=Path(__file__).resolve().parent,capture_output=True,text=True)
            self.assertNotEqual(done.returncode,0)
            self.assertIn('duplicate JSON key',done.stderr)

if __name__=='__main__':unittest.main()
