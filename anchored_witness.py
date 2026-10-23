"""ACE v0.5 anchored witness, fail-closed across whole-store rollbacks.

The external quorum is independently durable. Signer state can be restored
from the latest quorum-backed snapshot. Changes are never released until the
external quorum durably commits them. A partially completed anchor transition
can suspend signing until the replicas are repaired or reconciled.
"""
from __future__ import annotations

from contextlib import closing
import sqlite3
from pathlib import Path

from anchor import AnchorQuorum, AnchorError, state_digest
from durable_witness import DurableWitness
from provenance import Protocol, SignedObservation
from witnessed import Witness, WitnessPolicy, SignedHead, WitnessError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class AnchoredWitness(DurableWitness):
    def __init__(self, policy: WitnessPolicy, protocol: Protocol,
                 witness_id: str, private_key: Ed25519PrivateKey,
                 db_path: str | Path, anchors: AnchorQuorum):
        if anchors.policy.witness_id!=witness_id or \
           anchors.policy.witness_policy_commitment!=policy.commitment or \
           anchors.policy.protocol_commitment!=protocol.commitment:
            raise AnchorError('anchor policy differs from witness manifest')
        from witnessed import _key_hex
        if anchors.policy.witness_public_key_hex!=_key_hex(private_key):
            raise AnchorError('anchor is pinned to a different signing key')
        self.anchors=anchors
        super().__init__(policy,protocol,witness_id,private_key,db_path)
        with closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                self._reconcile(db)
                db.execute('COMMIT')
            except BaseException:
                db.execute('ROLLBACK')
                raise

    def _stored_snapshot(self,db) -> tuple[bytes,bytes] | None:
        row=db.execute('SELECT state,signature FROM states WHERE witness=?',
                       (self.witness_id,)).fetchone()
        return row if row is not None else None

    def _reconcile(self, db):
        remote=self.anchors.current()
        local=self._stored_snapshot(db)
        if remote is None:
            # Bootstrap only a clean witness. An unanchored historical state
            # would allow the first checkpoint to certify a rollback.
            self._load(db)
            if self._seen or self._last_head is not None or self._signed_epochs:
                raise AnchorError('nonempty legacy witness requires trusted migration')
            self._store(db)
            local=self._stored_snapshot(db)
            assert local is not None
            return self.anchors.advance(*local,previous=None)
        # The remote quorum is the trusted monotonic source of truth. In
        # particular, restore a rolled-back but correctly signed local DB.
        if local != (remote.state,remote.state_signature):
            db.execute('INSERT INTO states(witness,state,signature) VALUES(?,?,?) '
                       'ON CONFLICT(witness) DO UPDATE SET '
                       'state=excluded.state,signature=excluded.signature',
                       (self.witness_id,remote.state,remote.state_signature))
        self._load(db)
        return remote

    def _transition(self, operation, *args):
        with closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                parent=self._reconcile(db)
                outcome=operation(self,*args)
                self._store(db)
                raw,sig=self._stored_snapshot(db)
                if state_digest(raw,sig)!=parent.record.state_digest:
                    self.anchors.advance(raw,sig,parent)
                db.execute('COMMIT')
                return outcome
            except BaseException:
                db.execute('ROLLBACK')
                raise

    def receive(self, report: SignedObservation):
        return self._transition(Witness.receive,report)

    def endorse(self, signed: SignedHead, reports: list[SignedObservation]):
        return self._transition(Witness.endorse,signed,reports)
