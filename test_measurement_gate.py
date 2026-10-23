"""Live end-to-end v0.10 authorization consume, including stale-scope attack."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from campaign_certificate import export_attempt
from clustered_certificate import export_clustered_certificate
from demo_measurement import build_bundle
from measurement_start import MeasuredRegistryActionGate,StartError
from test_measurement_start import started_fixture
from test_root_registry import scope_fixture
from witnessed import GENESIS_DIGEST
from root_registry import RegistryError
from campaign import CampaignError


def issued_bundle(f):
    device=f['device'];b=f['binding']
    cert=f['starts'].issue(b,device.arm(b))
    device.activate(cert);readings=[]
    for i,slot in enumerate(f['protocol'].slots):
        t=device.sample(f['protocol'],slot.slot_id,0,f['keys'][i])
        readings.append(t);f['log'].append(t.report)
        for w in f['witnesses'][:3]:w.receive(t.report)
    signed,proof=f['log'].seal()
    endorsements=[w.endorse(signed,f['log'].entries) for w in f['witnesses'][:3]]
    v2=export_clustered_certificate(f['log'],signed,endorsements,proof,plan=f['plan'],action=f['action'])
    finalized=f['child'].finalize(f['reserved'],v2_certificate=v2,authorized=v2['claimed_decision_v2']['authorized'])
    bundle,pins=build_bundle(f,readings,v2)
    return export_attempt(f['reserved'],finalized,v2),bundle,pins


class MeasuredGateTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.f=started_fixture(self.root)

    def gate(self):
        f=self.f
        return MeasuredRegistryActionGate(f['registry'],f['root'],f['child'],f['starts'])

    def test_correctly_witnessed_decision_is_consumed_once(self):
        campaign,measurement,pins=issued_bundle(self.f)
        decision=self.gate().check_and_consume(campaign,measurement,pins,
                     expected_v2_epoch=0,expected_v2_previous_digest=GENESIS_DIGEST)
        self.assertTrue(decision.authorized)
        self.assertIsNotNone(decision.consumption_certificate)
        with self.assertRaises((CampaignError,StartError)):
            self.gate().check_and_consume(campaign,measurement,pins,
                         expected_v2_epoch=0,expected_v2_previous_digest=GENESIS_DIGEST)

    def test_a_stale_root_rollover_blocks_even_valid_old_receipts(self):
        campaign,measurement,pins=issued_bundle(self.f)
        nxt,_=scope_fixture(self.root,'root-new-scope-2026',40_000_000_000)
        self.f['registry'].rollover(self.f['root'],nxt,self.f['admin'])
        with self.assertRaises((RegistryError,StartError)):
            self.gate().check_and_consume(campaign,measurement,pins,
                         expected_v2_epoch=0,expected_v2_previous_digest=GENESIS_DIGEST)

    def test_binding_cannot_be_replaced_before_consumption(self):
        campaign,measurement,pins=issued_bundle(self.f)
        tampered=deepcopy(measurement)
        tampered['instrument_measurements'][0]['report']['bit']=1
        with self.assertRaises((ValueError,StartError)):
            self.gate().check_and_consume(campaign,tampered,pins,
                         expected_v2_epoch=0,expected_v2_previous_digest=GENESIS_DIGEST)
        self.assertEqual(self.f['child'].current().state.stage,'authorized')

if __name__=='__main__':unittest.main()
