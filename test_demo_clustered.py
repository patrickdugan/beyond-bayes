"""Reproducible full v2 demo, pinned CLI, and single-use replay."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

from demo_clustered import generate
from clustered_certificate import verify_clustered_certificate


class DemoClusteredTest(unittest.TestCase):
    def test_demo_pinned_and_deterministic(self):
        first,pins=generate()
        second,pins2=generate()
        self.assertEqual(first,second)
        self.assertEqual(pins,pins2)
        fixture=Path(__file__).with_name('vectors')
        self.assertEqual(first,json.loads((fixture/'v07_fixture.json').read_text()))
        self.assertEqual(pins,json.loads((fixture/'v07_pins.json').read_text()))
        self.assertTrue(verify_clustered_certificate(first,**pins).authorized)

    def test_cli_transaction_rejects_second_consumption(self):
        cert,pins=generate()
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'cert.json';p.write_text(json.dumps(cert))
            db=Path(tmp)/'gate.db'
            cmd=[sys.executable,str(Path(__file__).with_name('verify_clustered.py')),
                 str(p),'--consume-db',str(db)]
            for key,value in pins.items():
                cmd+=['--'+key.replace('_','-'),str(value)]
            first=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(first.returncode,0,first.stderr)
            replay=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(replay.returncode,1)
            self.assertIn('consumed',replay.stderr)

if __name__=='__main__':unittest.main()
