"""ACE v0.8: integer alpha-spending and durable quorum-voted campaign events.

One policy governs a fixed experiment campaign. Event order is:
  reserve (burn alpha before data) -> finalize (bind exactly one v2 certificate)
  -> consume (only for an authorized result, exactly once).
Denials and abandoned reservations keep their alpha expenditure.

Fault assumptions: up to f separately persisted replicas corrupt or rolled back;
2*q > n+f; honest replicas persist a unique successor vote. The simulator
uses independently stored SQLite databases and Ed25519. This is not distributed
consensus across network partitions, nor evidence of conditional test validity.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import sqlite3
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from anchor import AnchorIdentity
from provenance import _digest, _encoding
from witnessed import GENESIS_DIGEST, _check_hex256, _check_sig, _key_hex

SCALE = 10**12  # alpha units are exact; 50_000_000_000 = 5%
SCHEMA = 'ACE-campaign-record-v1'
POLICY_SCHEMA = 'ACE-campaign-policy-v1'
VOTE_DOMAIN = 'ACE:campaign-vote:v1'

class CampaignError(ValueError):
    pass


def _integer(n: object, low: int, high: int) -> bool:
    return type(n) is int and low <= n <= high


def _hex(s: object) -> bool:
    return _check_hex256(s)


def _pubkey(s: object) -> bool:
    try:
        return type(s) is str and len(bytes.fromhex(s)) == 32
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class CampaignPolicy:
    campaign_id: str
    total_units: int
    replicas: tuple[AnchorIdentity, ...]
    max_faulty: int
    quorum: int

    def __post_init__(self):
        n = len(self.replicas)
        ids = [r.replica_id for r in self.replicas]
        keys = [r.public_key_hex for r in self.replicas]
        if (type(self.campaign_id) is not str or len(self.campaign_id) < 16 or
            not _integer(self.total_units, 1, SCALE) or
            n < 1 or not _integer(self.max_faulty, 0, n-1) or
            not _integer(self.quorum, 1, n) or
            2*self.quorum <= n+self.max_faulty or
            len(set(ids)) != n or len(set(keys)) != n or
            any(type(s) is not str or not s for s in ids) or
            any(not _pubkey(k) for k in keys)):
            raise CampaignError('invalid campaign policy or quorum')

    def canonical(self) -> dict:
        return {'schema': POLICY_SCHEMA, 'campaign_id': self.campaign_id,
                'scale': SCALE, 'total_units': self.total_units,
                'replicas': [r.canonical() for r in self.replicas],
                'max_faulty': self.max_faulty, 'quorum': self.quorum}

    @property
    def commitment(self) -> str:
        return _digest(self.canonical())

    def keys(self) -> dict[str, str]:
        return {r.replica_id: r.public_key_hex for r in self.replicas}


def unpack_policy(raw: Any) -> CampaignPolicy:
    if (type(raw) is not dict or set(raw) !=
        {'schema','campaign_id','scale','total_units','replicas','max_faulty','quorum'} or
        raw['schema'] != POLICY_SCHEMA or raw['scale'] != SCALE or
        type(raw['scale']) is not int or type(raw['replicas']) is not list):
        raise CampaignError('malformed campaign policy')
    entries=[]
    for item in raw['replicas']:
        if type(item) is not dict or set(item) != {'replica_id','public_key_hex'}:
            raise CampaignError('malformed replica identity')
        entries.append(AnchorIdentity(item['replica_id'],item['public_key_hex']))
    obj=CampaignPolicy(raw['campaign_id'],raw['total_units'],tuple(entries),
                       raw['max_faulty'],raw['quorum'])
    if obj.canonical()!=raw:
        raise CampaignError('noncanonical campaign policy')
    return obj


RESERVE_FIELDS = {'challenge','protocol','witness_policy','cluster_plan',
                  'v2_policy','action','alpha_units','spent_units'}
FINAL_FIELDS = {'reservation_digest','certificate_digest','authorized'}
CONSUME_FIELDS = {'finalization_digest'}


@dataclass(frozen=True)
class CampaignRecord:
    campaign: str
    sequence: int
    previous_digest: str
    kind: str
    payload: dict

    def __post_init__(self):
        if (not _hex(self.campaign) or not _hex(self.previous_digest) or
            not _integer(self.sequence, 1, 1_000_000_000) or
            type(self.payload) is not dict or
            self.kind not in ('reserve','finalize','consume')):
            raise CampaignError('invalid campaign record fields')
        p=self.payload
        if self.kind=='reserve':
            if (set(p)!=RESERVE_FIELDS or
                type(p['challenge']) is not str or len(p['challenge']) < 16 or
                any(not _hex(p[field]) for field in ('protocol','witness_policy',
                          'cluster_plan','v2_policy','action')) or
                not _integer(p['alpha_units'],1,SCALE-1) or
                not _integer(p['spent_units'],1,SCALE)):
                raise CampaignError('invalid reservation body')
        elif self.kind=='finalize':
            if (set(p)!=FINAL_FIELDS or
                any(not _hex(p[field]) for field in ('reservation_digest','certificate_digest')) or
                type(p['authorized']) is not bool):
                raise CampaignError('invalid finalization body')
        else:
            if set(p)!=CONSUME_FIELDS or not _hex(p['finalization_digest']):
                raise CampaignError('invalid consumption body')

    def canonical(self) -> dict:
        return {'schema': SCHEMA, 'campaign': self.campaign,
                'sequence':self.sequence, 'previous_digest':self.previous_digest,
                'kind':self.kind, 'payload': self.payload}

    @property
    def digest(self) -> str:
        return _digest(self.canonical())


def unpack_record(raw: Any) -> CampaignRecord:
    if type(raw) is not dict or set(raw)!= {'schema','campaign','sequence','previous_digest','kind','payload'} or raw['schema']!=SCHEMA:
        raise CampaignError('unexpected campaign record schema')
    record=CampaignRecord(raw['campaign'],raw['sequence'],raw['previous_digest'],raw['kind'],raw['payload'])
    if record.canonical()!=raw:
        raise CampaignError('noncanonical campaign record')
    return record


@dataclass(frozen=True)
class CampaignVote:
    replica_id: str
    record_digest: str
    signature_hex: str

    def body(self) -> dict:
        return {'domain':VOTE_DOMAIN,'replica_id':self.replica_id,'record_digest':self.record_digest}

    def canonical(self) -> dict:
        return {'replica_id':self.replica_id,'record_digest':self.record_digest,
                'signature_hex':self.signature_hex}


def unpack_vote(raw: Any) -> CampaignVote:
    if type(raw) is not dict or set(raw)!={'replica_id','record_digest','signature_hex'}:
        raise CampaignError('malformed campaign vote')
    return CampaignVote(raw['replica_id'],raw['record_digest'],raw['signature_hex'])


@dataclass(frozen=True)
class CampaignCertificate:
    record: CampaignRecord
    votes: tuple[CampaignVote, ...]

    def canonical(self) -> dict:
        return {'record':self.record.canonical(), 'votes':[v.canonical() for v in self.votes]}


def unpack_certificate(raw: Any) -> CampaignCertificate:
    if type(raw) is not dict or set(raw) != {'record','votes'} or type(raw['votes']) is not list:
        raise CampaignError('malformed campaign certificate')
    return CampaignCertificate(unpack_record(raw['record']),tuple(unpack_vote(v) for v in raw['votes']))


def verify_certificate(cert: CampaignCertificate, policy: CampaignPolicy) -> bool:
    if not isinstance(cert,CampaignCertificate) or cert.record.campaign != policy.commitment:
        return False
    seen=set(); keys=policy.keys()
    for vote in cert.votes:
        if (type(vote.replica_id) is not str or vote.replica_id not in keys or
            vote.replica_id in seen or vote.record_digest!=cert.record.digest or
            not _check_sig(keys[vote.replica_id],vote.signature_hex,_encoding(vote.body()))):
            return False
        seen.add(vote.replica_id)
    return len(seen)>=policy.quorum


@dataclass(frozen=True)
class CampaignState:
    spent: int = 0
    seen: frozenset[str] = frozenset()
    stage: str = 'empty'
    reservation: CampaignRecord | None = None
    finalization: CampaignRecord | None = None


def transition(state: CampaignState, record: CampaignRecord, policy: CampaignPolicy) -> CampaignState:
    """Deterministic state transition checked by every honest anchor replica."""
    if record.campaign!=policy.commitment:
        raise CampaignError('wrong campaign')
    p=record.payload
    if record.kind=='reserve':
        if state.stage not in ('empty','denied','consumed'):
            raise CampaignError('previous attempt has not been finished')
        if p['challenge'] in state.seen:
            raise CampaignError('challenge already reserved in this campaign')
        if state.spent+p['alpha_units']>policy.total_units or p['spent_units']!=state.spent+p['alpha_units']:
            raise CampaignError('campaign risk budget exceeded or incorrectly accounted')
        return CampaignState(p['spent_units'], state.seen|{p['challenge']},'reserved',record,None)
    if record.kind=='finalize':
        if state.stage!='reserved' or state.reservation is None or p['reservation_digest']!=state.reservation.digest:
            raise CampaignError('not the unique pending reservation')
        return CampaignState(state.spent,state.seen,'authorized' if p['authorized'] else 'denied',
                             state.reservation,record)
    if state.stage!='authorized' or state.finalization is None or p['finalization_digest']!=state.finalization.digest:
        raise CampaignError('duplicate or unauthorized consumption')
    return CampaignState(state.spent,state.seen,'consumed',state.reservation,state.finalization)


class CampaignReplica:
    def __init__(self, policy: CampaignPolicy, replica_id: str,
                 key: Ed25519PrivateKey, db_path: str|Path):
        if policy.keys().get(replica_id)!=_key_hex(key):
            raise CampaignError('replica identity does not match signed policy')
        self.policy=policy
        self.id=replica_id
        self.key=key
        self.db_path=str(db_path)
        with closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS campaign_events ('
                       'campaign TEXT NOT NULL, sequence INTEGER NOT NULL, '
                       'event BLOB NOT NULL, vote BLOB NOT NULL, '
                       'PRIMARY KEY(campaign,sequence))')
            db.execute('COMMIT')

    def _connect(self):
        db=sqlite3.connect(self.db_path,timeout=15,isolation_level=None)
        db.execute('PRAGMA busy_timeout=15000')
        db.execute('PRAGMA synchronous=FULL')
        return db

    def _read_in_tx(self,db) -> list[tuple[CampaignRecord,CampaignVote]]:
        raw=db.execute('SELECT sequence,event,vote FROM campaign_events WHERE campaign=? ORDER BY sequence',
                       (self.policy.commitment,)).fetchall()
        state=CampaignState(); previous=GENESIS_DIGEST; output=[]
        for i,(seq,body,sig) in enumerate(raw,1):
            try:
                event=unpack_record(json.loads(body))
            except (TypeError,ValueError,KeyError) as exc:
                raise CampaignError('corrupt durable campaign journal') from exc
            if (seq!=i or event.sequence!=i or event.previous_digest!=previous or
                _encoding(event.canonical())!=body):
                raise CampaignError('broken campaign journal chain')
            state=transition(state,event,self.policy)
            vote=CampaignVote(self.id,event.digest,sig.hex())
            if not _check_sig(self.policy.keys()[self.id],vote.signature_hex,_encoding(vote.body())):
                raise CampaignError('invalid signed campaign journal vote')
            output.append((event,vote)); previous=event.digest
        return output

    def history(self) -> list[tuple[CampaignRecord,CampaignVote]]:
        with closing(self._connect()) as db:
            return self._read_in_tx(db)

    def vote(self,record:CampaignRecord) -> CampaignVote:
        with closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                current=self._read_in_tx(db)
                if record.sequence<=len(current):
                    event,vote=current[record.sequence-1]
                    if event.digest!=record.digest:
                        raise CampaignError('replica already voted for another event')
                    db.execute('COMMIT')
                    return vote
                if record.sequence!=len(current)+1:
                    raise CampaignError('missing predecessor')
                expected=GENESIS_DIGEST if not current else current[-1][0].digest
                if record.previous_digest!=expected:
                    raise CampaignError('fork from a stale predecessor')
                state=CampaignState()
                for event,_ in current:
                    state=transition(state,event,self.policy)
                transition(state,record,self.policy)
                signed=CampaignVote(self.id,record.digest,self.key.sign(_encoding({
                    'domain':VOTE_DOMAIN,'replica_id':self.id,'record_digest':record.digest})).hex())
                db.execute('INSERT INTO campaign_events(campaign,sequence,event,vote) VALUES(?,?,?,?)',
                           (self.policy.commitment,record.sequence,_encoding(record.canonical()),
                            bytes.fromhex(signed.signature_hex)))
                db.execute('COMMIT')
                return signed
            except BaseException:
                db.execute('ROLLBACK')
                raise


@dataclass(frozen=True)
class CampaignView:
    history: tuple[CampaignCertificate, ...]
    state: CampaignState

    @property
    def head(self) -> str:
        return self.history[-1].record.digest if self.history else GENESIS_DIGEST

    @property
    def sequence(self) -> int:
        return len(self.history)


class CampaignQuorum:
    def __init__(self, policy: CampaignPolicy, replicas: list[CampaignReplica]):
        if (len({x.id for x in replicas})!=len(replicas) or
            any(x.policy.commitment!=policy.commitment for x in replicas)):
            raise CampaignError('duplicate or mismatched replica')
        self.policy=policy
        self.replicas=replicas

    def current(self) -> CampaignView:
        histories=[]
        for replica in self.replicas:
            try:
                histories.append(replica.history())
            except (CampaignError,sqlite3.Error,OSError):
                continue
        if len(histories)<self.policy.quorum:
            raise CampaignError('insufficient readable anchor replicas')
        seq=0;certs=[];state=CampaignState(); previous=GENESIS_DIGEST
        while True:
            next_votes={}
            for history in histories:
                if len(history)>seq:
                    record,vote=history[seq]
                    next_votes.setdefault(record.digest,[]).append((record,vote))
            if not next_votes:
                break
            winners=[votes for votes in next_votes.values() if len(votes)>=self.policy.quorum]
            if len(winners)!=1:
                raise CampaignError('unresolved speculative successor or fork; signing suspended')
            # Any conflicting durable vote indicates a fork or defective replica.
            if len(next_votes)>1:
                raise CampaignError('conflicting replica branches; signing suspended')
            members=winners[0]
            event=members[0][0]
            if event.sequence!=seq+1 or event.previous_digest!=previous:
                raise CampaignError('invalid quorum-certified chain')
            cert=CampaignCertificate(event,tuple(vote for _,vote in members))
            if not verify_certificate(cert,self.policy):
                raise CampaignError('invalid quorum signatures')
            state=transition(state,event,self.policy)
            certs.append(cert);previous=event.digest;seq+=1
        return CampaignView(tuple(certs),state)

    def commit(self, kind:str, payload:dict) -> CampaignCertificate:
        view=self.current()
        event=CampaignRecord(self.policy.commitment,view.sequence+1,view.head,kind,payload)
        transition(view.state,event,self.policy)
        votes=[]
        for replica in self.replicas:
            try:
                votes.append(replica.vote(event))
            except (CampaignError,sqlite3.Error,OSError):
                continue
        cert=CampaignCertificate(event,tuple(votes))
        if not verify_certificate(cert,self.policy):
            raise CampaignError('unable to form durable quorum; recovery required')
        # Read back all certified states before returning a successful ticket.
        current=self.current()
        if current.head!=event.digest or current.sequence!=event.sequence:
            raise CampaignError('quorum readback failed')
        return cert

    def reserve(self, *,challenge:str,protocol:str,witness_policy:str,
                cluster_plan:str,v2_policy:str,action:str,alpha_units:int) -> CampaignCertificate:
        view=self.current()
        return self.commit('reserve',{'challenge':challenge,'protocol':protocol,
            'witness_policy':witness_policy,'cluster_plan':cluster_plan,'v2_policy':v2_policy,
            'action':action,'alpha_units':alpha_units,
            'spent_units':view.state.spent+alpha_units})

    def finalize(self,reservation:CampaignCertificate, *,v2_certificate:dict,
                 authorized:bool) -> CampaignCertificate:
        if not verify_certificate(reservation,self.policy) or reservation.record.kind!='reserve':
            raise CampaignError('invalid campaign reservation')
        return self.commit('finalize',{'reservation_digest':reservation.record.digest,
                                      'certificate_digest':_digest(v2_certificate),
                                      'authorized':authorized})

    def consume(self,finalization:CampaignCertificate) -> CampaignCertificate:
        if not verify_certificate(finalization,self.policy) or finalization.record.kind!='finalize':
            raise CampaignError('invalid campaign finalization')
        return self.commit('consume',{'finalization_digest':finalization.record.digest})
