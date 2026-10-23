"""Synthetic source-signature/campaign-anchor demo. PRIVATE TEST KEYS ONLY."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import tempfile

from campaign_certificate import CampaignActionGate
from campaign import GENESIS_DIGEST
from test_campaign import attempt, fixture


def generate() -> tuple[dict,dict]:
    with tempfile.TemporaryDirectory() as raw:
        policy,_,_,quorum=fixture(Path(raw),deterministic=True)
        attempt_bundle,pins,reserve,finalize=attempt(quorum,alpha=.01)
        consumption=CampaignActionGate(quorum).check_and_consume(attempt_bundle,
                     expected_v2_epoch=0,expected_v2_previous_digest=GENESIS_DIGEST)
        assert consumption.authorized
        assert consumption.consumption_certificate is not None
        bundle={'schema':'ACE-campaign-demo-v1','campaign_policy':policy.canonical(),
                'attempt':attempt_bundle,'consumption':consumption.consumption_certificate.canonical()}
        trusted={'campaign_policy':policy.canonical(),
                 'campaign_commitment':policy.commitment,
                 'reservation_digest':reserve.record.digest,
                 'finalization_digest':finalize.record.digest,
                 'consumption_digest':consumption.consumption_certificate.record.digest,
                 'previous_campaign_digest':GENESIS_DIGEST,
                 'previous_spent_units':0,
                 'v2_epoch':0,'v2_previous_digest':GENESIS_DIGEST}
        return bundle,trusted


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--pins',type=Path,required=True)
    options=parser.parse_args()
    b,p=generate()
    options.output.write_text(json.dumps(b,sort_keys=True,indent=2,allow_nan=False)+'\n')
    options.pins.write_text(json.dumps(p,sort_keys=True,indent=2,allow_nan=False)+'\n')
    print(json.dumps({'bundle':str(options.output),'pins':str(options.pins),
                      'campaign_commitment':p['campaign_commitment'],
                      'consumption_digest':p['consumption_digest']}))

if __name__=='__main__':main()
