import sqlite3
from contextlib import closing
import tempfile
from pathlib import Path
import unittest

from durable_witness import DurableWitness
from test_witnessed import setup, bit_reports
from witnessed import GENESIS_DIGEST, SignedHead, Head, WitnessError, snapshot_log_root, _encoding


class DurableWitnessTests(unittest.TestCase):
    def test_process_restart_remembers_signed_receipts(self):
        p,keys,policy,logkey,wkeys,ws,log=setup()
        with tempfile.TemporaryDirectory() as tmp:
            db=Path(tmp)/'honest.sqlite'
            witness=DurableWitness(policy,p,'notary-0',wkeys[0],db)
            signed=bit_reports(p,keys,[0])[0]
            receipt=witness.receive(signed)
            self.assertEqual(receipt.target_epoch,0)
            restarted=DurableWitness(policy,p,'notary-0',wkeys[0],db)
            head,_=log.seal()
            with self.assertRaisesRegex(WitnessError,'missing witnessed'):
                restarted.endorse(head,log.entries)
            # Append the previously acknowledged report and re-sign same epoch.
            # (A sample log must be built independently to model the attack.)
            corrected=Head(policy.commitment,p.commitment,0,1,
                           snapshot_log_root([signed]),GENESIS_DIGEST)
            corrected_signed=SignedHead(corrected,
                logkey.sign(_encoding(corrected.canonical())).hex())
            endorsed=restarted.endorse(corrected_signed,[signed])
            self.assertEqual(endorsed.head_digest,corrected.digest)

    def test_process_restart_forbids_same_epoch_split_view(self):
        p,keys,policy,logkey,wkeys,ws,log=setup()
        with tempfile.TemporaryDirectory() as tmp:
            db=Path(tmp)/'signer.sqlite'
            witness=DurableWitness(policy,p,'notary-0',wkeys[0],db)
            first,_=log.seal()
            witness.endorse(first,[])
            alternate=Head(policy.commitment,p.commitment,0,1,
                           snapshot_log_root(bit_reports(p,keys,[0])),GENESIS_DIGEST)
            alternate_signed=SignedHead(alternate,
                logkey.sign(_encoding(alternate.canonical())).hex())
            restart=DurableWitness(policy,p,'notary-0',wkeys[0],db)
            with self.assertRaisesRegex(WitnessError,'same witness refuses'):
                restart.endorse(alternate_signed,bit_reports(p,keys,[0]))
            late=restart.receive(bit_reports(p,keys,[0])[0])
            self.assertEqual(late.target_epoch,1)

    def test_mutated_journal_fails_closed(self):
        p,keys,policy,logkey,wkeys,ws,log=setup()
        with tempfile.TemporaryDirectory() as tmp:
            db=Path(tmp)/'signer.sqlite'
            witness=DurableWitness(policy,p,'notary-0',wkeys[0],db)
            witness.receive(bit_reports(p,keys,[0])[0])
            with closing(sqlite3.connect(db)) as connection, connection:
                connection.execute('UPDATE states SET state = ? WHERE witness = ?',
                                   (b'{}','notary-0'))
            with self.assertRaisesRegex(WitnessError,'snapshot signature'):
                DurableWitness(policy,p,'notary-0',wkeys[0],db)

    def test_durable_witness_must_use_correct_identity_key(self):
        p,keys,policy,logkey,wkeys,ws,log=setup()
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(WitnessError):
                DurableWitness(policy,p,'notary-0',wkeys[1],Path(tmp)/'bad.sqlite')


if __name__=='__main__':unittest.main()
