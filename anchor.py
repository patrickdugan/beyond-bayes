"""ACE v0.5: independently persisted, signed witness-state checkpoint anchors.

A quorum certificate prevents a local witness's valid-but-old SQLite snapshot
from authorizing a second signature. Each anchor replica has an independent
Ed25519 identity and SQLite database, and persists its vote BEFORE returning.

Scope: at most f replicas are Byzantine or lose monotonic state, with
2*quorum > n+f. The witness signing key must remain protected. Bootstrap must
occur while the original witness state is trusted. Deliberately fail closed
when a partly applied transition cannot be reconstructed at quorum.

This is a deterministic local protocol model, not a network BFT deployment.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from provenance import _digest, _encoding
from witnessed import GENESIS_DIGEST, WitnessError, _check_hex256, _check_sig, _key_hex


class AnchorError(WitnessError):
    pass


@dataclass(frozen=True)
class AnchorIdentity:
    replica_id: str
    public_key_hex: str

    def canonical(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class AnchorPolicy:
    witness_id: str
    witness_public_key_hex: str
    witness_policy_commitment: str
    protocol_commitment: str
    replicas: tuple[AnchorIdentity, ...]
    max_faulty: int
    quorum: int

    def __post_init__(self):
        n = len(self.replicas)
        ids = [r.replica_id for r in self.replicas]
        keys = [r.public_key_hex for r in self.replicas]
        if (not self.witness_id or not _check_hex256(self.witness_policy_commitment)
            or not _check_hex256(self.protocol_commitment)
            or any(type(v) is not str or not v for v in ids)
            or len(set(ids)) != n or len(set(keys)) != n
            or any(not _valid_key(k) for k in keys + [self.witness_public_key_hex])
            or type(self.max_faulty) is not int or type(self.quorum) is not int
            or self.max_faulty < 0 or self.max_faulty >= n or not (0 < self.quorum <= n)
            or 2*self.quorum <= n + self.max_faulty):
            raise AnchorError('unsafe or malformed anchor quorum policy')

    @property
    def commitment(self) -> str:
        return _digest(self.canonical())

    def canonical(self) -> dict:
        return {'domain':'ACE:anchor-policy:v1','witness_id':self.witness_id,
                'witness_public_key_hex':self.witness_public_key_hex,
                'witness_policy_commitment':self.witness_policy_commitment,
                'protocol_commitment':self.protocol_commitment,
                'replicas':[r.canonical() for r in self.replicas],
                'max_faulty':self.max_faulty,'quorum':self.quorum}

    def keys(self) -> dict[str,str]:
        return {r.replica_id:r.public_key_hex for r in self.replicas}


def _valid_key(value: str) -> bool:
    try:
        return type(value) is str and len(bytes.fromhex(value)) == 32
    except ValueError:
        return False


def state_digest(raw: bytes, sig: bytes) -> str:
    return hashlib.sha256(b'ACE:anchored-state:v1\x00' + len(raw).to_bytes(8,'big')
                          + raw + sig).hexdigest()


def validate_state(policy: AnchorPolicy, raw: bytes, signature: bytes) -> None:
    if not isinstance(raw, bytes) or not isinstance(signature, bytes) or len(raw)>16_000_000 or \
            not _check_sig(policy.witness_public_key_hex, signature.hex(), raw):
        raise AnchorError('invalid witness-signed snapshot')
    try:
        data=json.loads(raw)
    except (ValueError,UnicodeDecodeError) as e:
        raise AnchorError('malformed witness snapshot') from e
    if not isinstance(data,dict) or data.get('schema')!='ACE-witness-state-v1' or \
       data.get('witness_id') != policy.witness_id or \
       data.get('policy_commitment') != policy.witness_policy_commitment or \
       data.get('protocol_commitment') != policy.protocol_commitment or \
       _encoding(data)!=raw:
        raise AnchorError('snapshot identity or canonical encoding mismatch')


@dataclass(frozen=True)
class AnchorRecord:
    policy_commitment: str
    witness_id: str
    sequence: int
    previous_digest: str
    state_digest: str

    def __post_init__(self):
        if (type(self.sequence) is not int or self.sequence < 0 or not self.witness_id
            or not all(_check_hex256(v) for v in (self.policy_commitment,
                                                  self.previous_digest,self.state_digest))):
            raise AnchorError('malformed anchor record')

    def canonical(self) -> dict:
        return {'domain':'ACE:anchor-record:v1','policy_commitment':self.policy_commitment,
                'witness_id':self.witness_id,'sequence':self.sequence,
                'previous_digest':self.previous_digest,'state_digest':self.state_digest}

    @property
    def digest(self) -> str:
        return _digest(self.canonical())


@dataclass(frozen=True)
class AnchorVote:
    replica_id: str
    record_digest: str
    signature_hex: str

    def canonical(self) -> dict:
        return asdict(self)

    def body(self) -> dict:
        return {'domain':'ACE:anchor-vote:v1','replica_id':self.replica_id,
                'record_digest':self.record_digest}


@dataclass(frozen=True)
class AnchorCertificate:
    record: AnchorRecord
    state: bytes
    state_signature: bytes
    votes: tuple[AnchorVote,...]

    def canonical(self) -> dict:
        return {'record':self.record.canonical(),'state_hex':self.state.hex(),
                'state_signature_hex':self.state_signature.hex(),
                'votes':[v.canonical() for v in self.votes]}


def verify_anchor_certificate(cert: AnchorCertificate, policy: AnchorPolicy) -> bool:
    if not isinstance(cert,AnchorCertificate):
        return False
    r=cert.record
    if r.policy_commitment!=policy.commitment or r.witness_id!=policy.witness_id or \
       r.state_digest!=state_digest(cert.state,cert.state_signature) or \
       (r.sequence == 0 and r.previous_digest != GENESIS_DIGEST):
        return False
    try:
        validate_state(policy,cert.state,cert.state_signature)
    except (AnchorError,ValueError,TypeError):
        return False
    seen=set()
    keys=policy.keys()
    for vote in cert.votes:
        if not isinstance(vote,AnchorVote) or vote.replica_id not in keys or \
           vote.replica_id in seen or vote.record_digest!=r.digest or \
           not _check_sig(keys[vote.replica_id],vote.signature_hex,_encoding(vote.body())):
            return False
        seen.add(vote.replica_id)
    return len(seen)>=policy.quorum


def _decode_record(raw: bytes) -> AnchorRecord:
    d=json.loads(raw)
    if not isinstance(d,dict) or set(d)!={'domain','policy_commitment','witness_id',
                                          'sequence','previous_digest','state_digest'} or \
       d['domain']!='ACE:anchor-record:v1':
        raise AnchorError('malformed persisted anchor record')
    return AnchorRecord(d['policy_commitment'],d['witness_id'],d['sequence'],
                        d['previous_digest'],d['state_digest'])


class AnchorReplica:
    """Independent durable one-vote-per-successor store (one witness per policy)."""
    def __init__(self, policy: AnchorPolicy, replica_id: str,
                 key: Ed25519PrivateKey, db_path: str | Path):
        if policy.keys().get(replica_id) != _key_hex(key):
            raise AnchorError('replica ID/key absent from pinned roster')
        self.policy=policy
        self.replica_id=replica_id
        self._key=key
        self.db_path=str(db_path)
        with closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS records ('
                       'policy TEXT NOT NULL, seq INTEGER NOT NULL, '
                       'record BLOB NOT NULL, state BLOB NOT NULL, '
                       'witness_sig BLOB NOT NULL, vote_sig BLOB NOT NULL, '
                       'PRIMARY KEY(policy,seq))')
            db.execute('COMMIT')

    def _connect(self):
        db=sqlite3.connect(self.db_path,timeout=15,isolation_level=None)
        db.execute('PRAGMA busy_timeout=15000')
        db.execute('PRAGMA synchronous=FULL')
        return db

    def _rows(self, db):
        rows=db.execute('SELECT seq,record,state,witness_sig,vote_sig FROM records '
                        'WHERE policy=? ORDER BY seq', (self.policy.commitment,)).fetchall()
        previous=GENESIS_DIGEST
        for idx,(seq,encoded,state,sig,vote_sig) in enumerate(rows):
            try:
                record=_decode_record(encoded)
            except (TypeError,ValueError,KeyError) as e:
                raise AnchorError('corrupt anchor journal') from e
            if seq != idx or record.sequence!=idx or record.previous_digest!=previous or \
               record.policy_commitment!=self.policy.commitment or \
               record.witness_id!=self.policy.witness_id or \
               record.state_digest!=state_digest(state,sig):
                raise AnchorError('broken anchor chain or snapshot digest')
            validate_state(self.policy,state,sig)
            vote=AnchorVote(self.replica_id,record.digest,vote_sig.hex())
            if not _check_sig(self.policy.keys()[self.replica_id],vote.signature_hex,
                              _encoding(vote.body())):
                raise AnchorError('bad replica journal signature')
            previous=record.digest
        return rows

    def read(self) -> tuple[AnchorRecord,bytes,bytes,AnchorVote] | None:
        with closing(self._connect()) as db:
            rows=self._rows(db)
        if not rows: return None
        _,encoded,state,sig,vote_sig=rows[-1]
        record=_decode_record(encoded)
        return record,state,sig,AnchorVote(self.replica_id,record.digest,vote_sig.hex())

    def vote(self, record: AnchorRecord, state: bytes, signature: bytes) -> AnchorVote:
        if record.policy_commitment!=self.policy.commitment or \
           record.witness_id!=self.policy.witness_id or \
           record.state_digest!=state_digest(state,signature):
            raise AnchorError('vote targets wrong witness or snapshot')
        validate_state(self.policy,state,signature)
        with closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                rows=self._rows(db)
                if rows and record.sequence==rows[-1][0] and \
                   rows[-1][1]==_encoding(record.canonical()) and \
                   rows[-1][2]==state and rows[-1][3]==signature:
                    db.execute('COMMIT')
                    return AnchorVote(self.replica_id,record.digest,rows[-1][4].hex())
                previous=_decode_record(rows[-1][1]).digest if rows else GENESIS_DIGEST
                if record.sequence!=len(rows) or record.previous_digest!=previous:
                    raise AnchorError('replica refuses skipped, stale or conflicting successor')
                vote=AnchorVote(self.replica_id,record.digest,self._key.sign(
                    _encoding({'domain':'ACE:anchor-vote:v1','replica_id':self.replica_id,
                               'record_digest':record.digest})).hex())
                db.execute('INSERT INTO records(policy,seq,record,state,witness_sig,vote_sig) '
                           'VALUES(?,?,?,?,?,?)',(self.policy.commitment,record.sequence,
                            _encoding(record.canonical()),state,signature,
                            bytes.fromhex(vote.signature_hex)))
                db.execute('COMMIT')
                return vote
            except BaseException:
                db.execute('ROLLBACK')
                raise


class AnchorQuorum:
    def __init__(self, policy: AnchorPolicy, replicas: list[AnchorReplica]):
        if len(replicas)!=len(policy.replicas) or \
           {r.replica_id for r in replicas} != set(policy.keys()) or \
           any(r.policy.commitment!=policy.commitment for r in replicas):
            raise AnchorError('replica group differs from committed anchor policy')
        self.policy=policy
        self.replicas=tuple(replicas)

    def current(self) -> AnchorCertificate | None:
        """Require a quorum at the *highest observed* anchor sequence.

        If a transition was partially stored, suspend until repaired instead
        of accepting the lower (and potentially stale) certificate.
        """
        seen=[]
        for replica in self.replicas:
            try:
                seen.append(replica.read())
            except (AnchorError,sqlite3.Error,OSError):
                continue
        if len(seen)<self.policy.quorum:
            raise AnchorError('insufficient live anchor replicas for freshness read')
        with_heads=[x for x in seen if x is not None]
        if not with_heads: return None
        max_seq=max(x[0].sequence for x in with_heads)
        highest=[x for x in with_heads if x[0].sequence==max_seq]
        groups={}
        for record,state,sig,vote in highest:
            groups.setdefault(record.digest,[]).append((record,state,sig,vote))
        matching=max(groups.values(),key=len)
        if len(matching)<self.policy.quorum:
            raise AnchorError('unresolved newer or conflicting anchor votes')
        rec,state,sig,_=matching[0]
        cert=AnchorCertificate(rec,state,sig,tuple(x[3] for x in matching))
        if not verify_anchor_certificate(cert,self.policy):
            raise AnchorError('invalid anchor quorum certificate')
        return cert

    def advance(self, state: bytes, signature: bytes,
                previous: AnchorCertificate | None) -> AnchorCertificate:
        validate_state(self.policy,state,signature)
        if previous is not None and not verify_anchor_certificate(previous,self.policy):
            raise AnchorError('invalid parent anchor certificate')
        fresh=self.current()
        if ((fresh is None) != (previous is None)) or \
           (fresh is not None and fresh.record.digest != previous.record.digest):
            raise AnchorError('stale anchor predecessor')
        record=AnchorRecord(self.policy.commitment,self.policy.witness_id,
                            0 if fresh is None else fresh.record.sequence+1,
                            GENESIS_DIGEST if fresh is None else fresh.record.digest,
                            state_digest(state,signature))
        votes=[]
        for replica in self.replicas:
            try:
                votes.append(replica.vote(record,state,signature))
            except (AnchorError,sqlite3.Error,OSError):
                continue
        cert=AnchorCertificate(record,state,signature,tuple(votes))
        if not verify_anchor_certificate(cert,self.policy):
            raise AnchorError('anchor transition failed to obtain durable quorum')
        return cert
