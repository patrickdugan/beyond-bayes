"""Local transactional checkpoint pinning and one-use action admission.

SQLite transactions provide process-safe atomic consumption while the database
is intact. An attacker who can roll back or replace the entire local database
can defeat freshness; production deployment needs an external monotonic anchor
or hardware-backed antirollback storage and an atomic action executor.
"""
from __future__ import annotations

from pathlib import Path
from contextlib import closing
import sqlite3

from certificates import InvalidCertificate
from witnessed import (GENESIS_DIGEST, VerifiedDecision,
                        verify_witnessed_certificate)


class ActionGate:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        with closing(sqlite3.connect(self.db_path, timeout=15)) as db, db:
            db.execute('PRAGMA busy_timeout = 15000')
            db.execute('CREATE TABLE IF NOT EXISTS anchors ('
                       'policy_commitment TEXT PRIMARY KEY, '
                       'last_epoch INTEGER NOT NULL, last_digest TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS consumed ('
                       'challenge TEXT PRIMARY KEY, protocol_commitment TEXT NOT NULL, '
                       'policy_commitment TEXT NOT NULL, head_digest TEXT NOT NULL)')

    def verify_and_consume(self, bundle: dict, *, expected_protocol: str,
                           expected_policy: str, expected_challenge: str) -> VerifiedDecision:
        """Verify fresh extension, persist checkpoint, and spend action nonce.

        `authorized=True` commits a spent nonce BEFORE returning control to the
        caller. Caller must bind a specific action to that nonce out-of-band.
        On denied decisions, advance the checkpoint anchor but keep nonce fresh.
        """
        with closing(sqlite3.connect(self.db_path,timeout=15,isolation_level=None)) as db:
            db.execute('PRAGMA busy_timeout = 15000')
            db.execute('BEGIN IMMEDIATE')
            try:
                latest = db.execute('SELECT last_epoch,last_digest FROM anchors '
                                    'WHERE policy_commitment = ?',
                                    (expected_policy,)).fetchone()
                epoch = 0 if latest is None else latest[0] + 1
                previous = GENESIS_DIGEST if latest is None else latest[1]
                used = db.execute('SELECT 1 FROM consumed WHERE challenge = ?',
                                  (expected_challenge,)).fetchone()
                if used is not None:
                    raise InvalidCertificate('action challenge already consumed')
                decision = verify_witnessed_certificate(
                    bundle, expected_protocol=expected_protocol,
                    expected_policy=expected_policy,
                    expected_challenge=expected_challenge,
                    expected_epoch=epoch,
                    expected_previous_digest=previous)
                db.execute('INSERT INTO anchors(policy_commitment,last_epoch,last_digest) '
                           'VALUES(?,?,?) ON CONFLICT(policy_commitment) DO UPDATE SET '
                           'last_epoch=excluded.last_epoch,last_digest=excluded.last_digest',
                           (expected_policy,decision.epoch,decision.checkpoint_digest))
                if decision.authorized:
                    db.execute('INSERT INTO consumed(challenge,protocol_commitment,'
                               'policy_commitment,head_digest) VALUES(?,?,?,?)',
                               (expected_challenge,expected_protocol,expected_policy,
                                decision.checkpoint_digest))
                db.execute('COMMIT')
                return decision
            except BaseException:
                db.execute('ROLLBACK')
                raise

    def anchor(self, policy_commitment: str) -> tuple[int,str] | None:
        with closing(sqlite3.connect(self.db_path)) as db:
            result=db.execute('SELECT last_epoch,last_digest FROM anchors '
                              'WHERE policy_commitment=?',(policy_commitment,)).fetchone()
        return (int(result[0]),str(result[1])) if result else None
