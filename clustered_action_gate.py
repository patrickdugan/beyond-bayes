"""SQLite one-shot v2 action gate over a monotonically pinned witnessed log.

This gate shares the legacy anchors and consumed tables for replay hygiene,
while permitting only v2 certificates. The store itself must be protected by
an external monotonic anchor against full-file rollback. Running the actual
action atomically with a committed nonce is an integration requirement.
"""
from __future__ import annotations
from contextlib import closing
from pathlib import Path
import sqlite3

from certificates import InvalidCertificate
from witnessed import GENESIS_DIGEST
from relying_party import ActionGate
from clustered_certificate import verify_clustered_certificate, VerifiedClusteredDecision


class ClusteredActionGate(ActionGate):
    def __init__(self,db_path:str|Path):
        super().__init__(db_path)

    def verify_and_consume(self, bundle:dict, *,expected_protocol:str,
                           expected_policy:str,expected_cluster_plan:str,
                           expected_v2_policy:str,expected_action:str,
                           expected_challenge:str) -> VerifiedClusteredDecision:
        with closing(sqlite3.connect(self.db_path,timeout=15,isolation_level=None)) as db:
            db.execute('PRAGMA busy_timeout = 15000')
            db.execute('BEGIN IMMEDIATE')
            try:
                last=db.execute('SELECT last_epoch,last_digest FROM anchors WHERE policy_commitment=?',
                                (expected_policy,)).fetchone()
                epoch=0 if last is None else int(last[0])+1
                prior=GENESIS_DIGEST if last is None else str(last[1])
                consumed=db.execute('SELECT 1 FROM consumed WHERE challenge=?',
                                    (expected_challenge,)).fetchone()
                if consumed:
                    raise InvalidCertificate('action nonce already consumed')
                result=verify_clustered_certificate(bundle,
                    expected_protocol=expected_protocol,expected_policy=expected_policy,
                    expected_cluster_plan=expected_cluster_plan,
                    expected_v2_policy=expected_v2_policy,
                    expected_action=expected_action,
                    expected_challenge=expected_challenge,
                    expected_epoch=epoch,expected_previous_digest=prior)
                db.execute('INSERT INTO anchors(policy_commitment,last_epoch,last_digest) VALUES(?,?,?) '
                    'ON CONFLICT(policy_commitment) DO UPDATE SET '
                    'last_epoch=excluded.last_epoch,last_digest=excluded.last_digest',
                    (expected_policy,result.epoch,result.checkpoint_digest))
                if result.authorized:
                    db.execute('INSERT INTO consumed(challenge,protocol_commitment,policy_commitment,head_digest) '
                               'VALUES(?,?,?,?)',
                               (expected_challenge,expected_protocol,expected_policy,
                                result.checkpoint_digest))
                db.execute('COMMIT')
                return result
            except BaseException:
                db.execute('ROLLBACK')
                raise
