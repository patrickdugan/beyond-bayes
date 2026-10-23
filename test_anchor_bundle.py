"""Independent ACE anchor-certificate decoding and tamper rejection."""
from __future__ import annotations

from copy import deepcopy
import unittest

from demo_anchor import make_demo
from verify_anchor import verify_anchor_bundle, InvalidAnchorBundle


class AnchorBundleTests(unittest.TestCase):
    def setUp(self):
        self.bundle=make_demo()
        self.pins={'expected_policy':self.bundle['certificate']['record']['policy_commitment'],
                   'expected_witness_id':'notary-0',
                   'expected_sequence':1,
                   'expected_previous_digest':self.bundle['certificate']['record']['previous_digest']}

    def verify(self,bundle=None):
        return verify_anchor_bundle(self.bundle if bundle is None else bundle,**self.pins)

    def test_valid_certificate_against_caller_pins(self):
        cert=self.verify()
        self.assertEqual(cert.record.sequence,1)
        self.assertEqual(len(cert.votes),4)

    def test_pinned_policy_mismatch_rejected(self):
        pins=dict(self.pins,expected_policy='aa'*32)
        with self.assertRaisesRegex(InvalidAnchorBundle,'externally pinned'):
            verify_anchor_bundle(self.bundle,**pins)

    def test_bad_pinned_predecessor_rejected(self):
        pins=dict(self.pins,expected_previous_digest='bb'*32)
        with self.assertRaises(InvalidAnchorBundle):
            verify_anchor_bundle(self.bundle,**pins)

    def test_modified_state_rejected(self):
        b=deepcopy(self.bundle)
        b['certificate']['state_hex']='7b7d'  # {}
        with self.assertRaises(InvalidAnchorBundle):self.verify(b)

    def test_duplicate_vote_rejected(self):
        b=deepcopy(self.bundle)
        b['certificate']['votes']=[b['certificate']['votes'][0]]*4
        with self.assertRaises(InvalidAnchorBundle):self.verify(b)

    def test_policy_substitution_rejected(self):
        b=deepcopy(self.bundle)
        b['anchor_policy']['quorum']=2
        with self.assertRaises(InvalidAnchorBundle):self.verify(b)

    def test_unknown_fields_rejected(self):
        b=deepcopy(self.bundle)
        b['anchor_policy']['foreign']=True
        with self.assertRaises(InvalidAnchorBundle):self.verify(b)


if __name__=='__main__':unittest.main()
