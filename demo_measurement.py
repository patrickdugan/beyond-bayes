"""Deterministic synthetic signed measurement acquisition and pinned replay."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import tempfile

from clustered_certificate import export_clustered_certificate
from measurement_start import verify_observations
from test_measurement_start import started_fixture
from verify_measurement import SCHEMA,replay
from witnessed import GENESIS_DIGEST



def build_bundle(f,readings,v2):
    registry=f['registry'].current();scope=f['root'].current();start=f['starts'].current()
    bundle={'schema':SCHEMA,'registry_policy':f['policy'].canonical(),
            'registry_history':[x.canonical() for x in registry.certificates],
            'scope_policy':f['scope'].canonical(),
            'scope_history':[x.canonical() for x in scope.history],
            'campaign_policy':f['cp'].canonical(),
            'reservation_certificate':f['reserved'].canonical(),
            'start_history':[x.canonical() for x in start.history],
            'instrument_measurements':[r.canonical() for r in readings],
            'v2_certificate':v2}
    pins={'registry_commitment':f['policy'].commitment,'registry_head':registry.head,
          'scope_commitment':f['scope'].commitment,'scope_head':scope.head,
          'campaign_commitment':f['cp'].commitment,
          'reservation_digest':f['reserved'].record.digest,
          'start_head':start.head,'v2_policy':f['auth'].commitment,
          'action':f['action'].commitment,
          'expected_v2_epoch':0,'expected_v2_previous_digest':GENESIS_DIGEST}
    return bundle,pins


def generate():
    with tempfile.TemporaryDirectory() as directory:
        f=started_fixture(Path(directory))
        device=f['device'];starts=f['starts'];binding=f['binding'];protocol=f['protocol'];log=f['log']
        receipt=starts.issue(binding,device.arm(binding))
        device.activate(receipt)
        readings=[]
        for i,slot in enumerate(protocol.slots):
            reading=device.sample(protocol,slot.slot_id,0,f['keys'][i])
            readings.append(reading)
            log.append(reading.report)
            for witness in f['witnesses'][:3]:witness.receive(reading.report)
        signed,consistency=log.seal()
        endorsements=[w.endorse(signed,log.entries) for w in f['witnesses'][:3]]
        v2=export_clustered_certificate(log,signed,endorsements,consistency,
                                        plan=f['plan'],action=f['action'])
        bundle,pins=build_bundle(f,readings,v2)
        replay(bundle,pins)
        return bundle,pins


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--pins',type=Path,required=True)
    args=ap.parse_args()
    bundle,pins=generate()
    args.output.write_text(json.dumps(bundle,indent=2,sort_keys=True)+'\n')
    args.pins.write_text(json.dumps(pins,indent=2,sort_keys=True)+'\n')
    print(f'Wrote {len(bundle["instrument_measurements"])} signed samples.')

if __name__=='__main__':main()
