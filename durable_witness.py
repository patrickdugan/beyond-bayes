"""SQLite-transactional ACE witness with signed state snapshots.

The witness persists every receipt and endorsement BEFORE returning it.
Recovery from process crashes is supported. The SQLite database itself is
NOT rollback resistant: an adversary who restores an older DB plus WAL can
make the signer forget a previously issued signature. Deployers need a
monotonic remote anchor/TEE counter and protected signing keys.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import asdict
from pathlib import Path
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from provenance import Protocol, SignedObservation, _encoding
from witnessed import (Head, SignedHead, Witness, WitnessError, WitnessPolicy,
                        _check_sig, _typed_report, unpack_head)


class DurableWitness(Witness):
    def __init__(self, policy: WitnessPolicy, protocol: Protocol,
                 witness_id: str, private_key: Ed25519PrivateKey,
                 db_path: str | Path):
        super().__init__(policy, protocol, witness_id, private_key)
        self.db_path = str(db_path)
        with closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS states ('
                       'witness TEXT PRIMARY KEY, '
                       'state BLOB NOT NULL, signature BLOB NOT NULL)')
            self._load(db)
            db.execute('COMMIT')

    def _connect(self):
        db=sqlite3.connect(self.db_path,timeout=15,isolation_level=None)
        db.execute('PRAGMA busy_timeout = 15000')
        db.execute('PRAGMA synchronous = FULL')
        return db

    def _snapshot(self) -> dict:
        return {
            'schema':'ACE-witness-state-v1',
            'witness_id':self.witness_id,
            'policy_commitment':self.policy.commitment,
            'protocol_commitment':self.protocol.commitment,
            'seen':{d:asdict(report) for d,report in sorted(self._seen.items())},
            'last_entries':[v.hex() for v in self._last_entries],
            'last_head':self._last_head.canonical() if self._last_head else None,
            'signed_epochs':{str(e):d for e,d in sorted(self._signed_epochs.items())},
        }

    def _load(self, db) -> None:
        row=db.execute('SELECT state,signature FROM states WHERE witness=?',
                       (self.witness_id,)).fetchone()
        if row is None:
            self._seen={}
            self._last_entries=()
            self._last_head=None
            self._signed_epochs={}
            return
        raw,sig=row
        if not _check_sig(self.policy.witness_keys()[self.witness_id],sig.hex(),raw):
            raise WitnessError('bad witness snapshot signature')
        try:
            import json
            d=json.loads(raw)
            if not isinstance(d,dict) or set(d) != {
                'schema','witness_id','policy_commitment','protocol_commitment',
                'seen','last_entries','last_head','signed_epochs'
            } or d['schema']!='ACE-witness-state-v1' or \
                d['witness_id']!=self.witness_id or \
                d['policy_commitment']!=self.policy.commitment or \
                d['protocol_commitment']!=self.protocol.commitment:
                raise WitnessError('unexpected witness state')
            if not isinstance(d['seen'],dict) or not isinstance(d['last_entries'],list) or \
                not isinstance(d['signed_epochs'],dict):
                raise WitnessError('bad persisted witness state')
            from witnessed import report_digest, _verify_reports
            from merklelog import merkle_root
            seen={}
            for key,value in d['seen'].items():
                report=_typed_report(value)
                if report_digest(report)!=key:
                    raise WitnessError('persisted receipt digest mismatch')
                seen[key]=report
            _verify_reports(self.protocol,list(seen.values()))
            entries=tuple(bytes.fromhex(v) for v in d['last_entries'])
            last=None if d['last_head'] is None else unpack_head(d['last_head'])
            epochs={int(e):digest for e,digest in d['signed_epochs'].items()}
            if any(type(k) is not int or k<0 for k in epochs) or \
                (last is None and (epochs or entries)) or \
                (last is not None and (len(entries)!=last.size or
                                      merkle_root(entries).hex()!=last.root_hex or
                                      set(epochs)!=set(range(last.epoch+1)) or
                                      epochs.get(last.epoch)!=last.digest)):
                raise WitnessError('inconsistent persisted epoch history')
            self._seen=seen
            self._last_entries=entries
            self._last_head=last
            self._signed_epochs=epochs
        except (KeyError,ValueError,TypeError,UnicodeError,AttributeError) as exc:
            raise WitnessError('corrupt persisted witness state') from exc

    def _store(self, db) -> None:
        raw=_encoding(self._snapshot())
        signature=self._key.sign(raw)
        db.execute('INSERT INTO states(witness,state,signature) VALUES(?,?,?) '
                   'ON CONFLICT(witness) DO UPDATE SET '
                   'state=excluded.state,signature=excluded.signature',
                   (self.witness_id,raw,signature))

    def receive(self, report: SignedObservation):
        with closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                self._load(db)
                receipt=super().receive(report)
                self._store(db)
                db.execute('COMMIT')
                return receipt
            except BaseException:
                db.execute('ROLLBACK')
                raise

    def endorse(self, signed: SignedHead, reports: list[SignedObservation]):
        with closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                self._load(db)
                endorsement=super().endorse(signed,reports)
                self._store(db)
                db.execute('COMMIT')
                return endorsement
            except BaseException:
                db.execute('ROLLBACK')
                raise
