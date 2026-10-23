"""ACE v0.10: pinned, quorum-certified principal/resource root registry.

This is a *local* persistent fault-injection model. The operator's approval
signature and the independently pinned registry key roster are both required.
Rollover closes a signed snapshot of the old scope, carrying its allocations
forward irrevocably; old scopes are rejected by the live registry action gate.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any
import json
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from anchor import AnchorIdentity
from campaign import SCALE
from scope import (ScopePolicy, ScopeQuorum, ScopeActionGate, ScopeError,
                   ScopeCertificate, unpack_policy as unpack_scope_policy,
                   unpack_certificate as unpack_scope_certificate,
                   verify_history as verify_scope_history)
from provenance import _digest, _encoding
from witnessed import GENESIS_DIGEST, _check_sig, _check_hex256, _key_hex

POLICY_SCHEMA='ACE-root-registry-policy-v1'
EVENT_SCHEMA='ACE-root-registry-event-v1'
VOTE_DOMAIN='ACE:root-registry:vote:v1'
APPROVAL_DOMAIN='ACE:root-registry:approval:v1'

class RegistryError(ValueError):
    pass


def _name(v, minimum=1, maximum=128):
    return type(v) is str and minimum <= len(v) <= maximum and all(32 <= ord(c) <= 126 for c in v)


def _pubkey(v):
    if type(v) is not str: return False
    try: return len(bytes.fromhex(v)) == 32
    except ValueError: return False


@dataclass(frozen=True)
class InstrumentIdentity:
    instrument_id: str
    public_key_hex: str
    epoch: int

    def __post_init__(self):
        if not _name(self.instrument_id) or not _pubkey(self.public_key_hex) or type(self.epoch) is not int or self.epoch < 1:
            raise RegistryError('malformed enrolled instrument')

    def canonical(self):
        return {'instrument_id':self.instrument_id,'public_key_hex':self.public_key_hex,'epoch':self.epoch}


@dataclass(frozen=True)
class RegistryPolicy:
    registry_id: str
    administrator_key: str
    replicas: tuple[AnchorIdentity, ...]
    max_faulty: int
    quorum: int
    instruments: tuple[InstrumentIdentity, ...]

    def __post_init__(self):
        n=len(self.replicas)
        if (not _name(self.registry_id,16) or not _pubkey(self.administrator_key) or
            n<1 or type(self.max_faulty) is not int or not 0<=self.max_faulty<n or
            type(self.quorum) is not int or not 1<=self.quorum<=n or
            2*self.quorum<=n+self.max_faulty or
            len({r.replica_id for r in self.replicas})!=n or
            len({r.public_key_hex for r in self.replicas})!=n or
            any(not _pubkey(r.public_key_hex) for r in self.replicas) or
            len({i.instrument_id for i in self.instruments}) != len(self.instruments) or
            len({i.public_key_hex for i in self.instruments}) != len(self.instruments)):
            raise RegistryError('invalid registry roster or quorum')

    def canonical(self):
        return {'schema':POLICY_SCHEMA,'registry_id':self.registry_id,
                'administrator_key':self.administrator_key,
                'replicas':[r.canonical() for r in self.replicas],
                'max_faulty':self.max_faulty,'quorum':self.quorum,
                'instruments':[i.canonical() for i in self.instruments]}

    @property
    def commitment(self): return _digest(self.canonical())

    def keys(self): return {r.replica_id:r.public_key_hex for r in self.replicas}

    def enrolled_instrument(self, instrument_id):
        entries=[i for i in self.instruments if i.instrument_id==instrument_id]
        if len(entries)!=1: raise RegistryError('device absent from independently pinned registry')
        return entries[0]


def unpack_policy(raw):
    if (type(raw) is not dict or set(raw)!={'schema','registry_id','administrator_key','replicas','max_faulty','quorum','instruments'}
        or raw['schema']!=POLICY_SCHEMA or type(raw['replicas']) is not list or type(raw['instruments']) is not list):
        raise RegistryError('registry policy shape')
    if any(type(x) is not dict or set(x)!={'replica_id','public_key_hex'} for x in raw['replicas']):
        raise RegistryError('registry key roster shape')
    if any(type(x) is not dict or set(x)!={'instrument_id','public_key_hex','epoch'} for x in raw['instruments']):
        raise RegistryError('registry instrument roster shape')
    p=RegistryPolicy(raw['registry_id'],raw['administrator_key'],tuple(AnchorIdentity(**x) for x in raw['replicas']),
                     raw['max_faulty'],raw['quorum'],tuple(InstrumentIdentity(**x) for x in raw['instruments']))
    if p.canonical()!=raw: raise RegistryError('noncanonical registry policy')
    return p


@dataclass(frozen=True)
class RegistryEvent:
    registry: str
    sequence: int
    previous_digest: str
    kind: str
    new_scope: ScopePolicy
    old_scope: str
    old_scope_head: str
    closed_history: tuple[ScopeCertificate,...]
    cap_units: int
    lifetime_allocated: int

    def __post_init__(self):
        if (not _check_hex256(self.registry) or not _check_hex256(self.previous_digest) or
            type(self.sequence) is not int or not 1<=self.sequence<=1_000_000_000 or
            self.kind not in ('enroll','rollover') or
            not isinstance(self.new_scope,ScopePolicy) or not _check_hex256(self.old_scope) or
            not _check_hex256(self.old_scope_head) or type(self.cap_units) is not int or
            not 1<=self.cap_units<=SCALE or type(self.lifetime_allocated) is not int or
            not 0<=self.lifetime_allocated<=self.cap_units or
            type(self.closed_history) is not tuple):
            raise RegistryError('invalid registry event')

    def canonical(self):
        return {'schema':EVENT_SCHEMA,'registry':self.registry,'sequence':self.sequence,
                'previous_digest':self.previous_digest,'kind':self.kind,
                'new_scope':self.new_scope.canonical(),'old_scope':self.old_scope,
                'old_scope_head':self.old_scope_head,
                'closed_history':[c.canonical() for c in self.closed_history],
                'cap_units':self.cap_units,'lifetime_allocated':self.lifetime_allocated}

    @property
    def digest(self): return _digest(self.canonical())


def unpack_event(d):
    if type(d) is not dict or set(d)!={'schema','registry','sequence','previous_digest','kind','new_scope',
                         'old_scope','old_scope_head','closed_history','cap_units','lifetime_allocated'} or d['schema']!=EVENT_SCHEMA or type(d['closed_history']) is not list:
        raise RegistryError('invalid registry event schema')
    o=RegistryEvent(d['registry'],d['sequence'],d['previous_digest'],d['kind'],unpack_scope_policy(d['new_scope']),
                    d['old_scope'],d['old_scope_head'],tuple(unpack_scope_certificate(x) for x in d['closed_history']),
                    d['cap_units'],d['lifetime_allocated'])
    if o.canonical()!=d: raise RegistryError('noncanonical registry event')
    return o


def approval_body(event): return {'domain':APPROVAL_DOMAIN,'event_digest':event.digest}

def vote_body(replica_id,event): return {'domain':VOTE_DOMAIN,'replica_id':replica_id,'event_digest':event.digest}


@dataclass(frozen=True)
class RegistryVote:
    replica_id: str
    signature_hex: str
    def canonical(self): return {'replica_id':self.replica_id,'signature_hex':self.signature_hex}


@dataclass(frozen=True)
class RegistryCertificate:
    event: RegistryEvent
    administrator_signature: str
    votes: tuple[RegistryVote,...]
    def canonical(self):
        return {'event':self.event.canonical(),'administrator_signature':self.administrator_signature,
                'votes':[v.canonical() for v in self.votes]}


def unpack_certificate(d):
    if type(d) is not dict or set(d)!={'event','administrator_signature','votes'} or type(d['votes']) is not list:
        raise RegistryError('invalid registry certificate shape')
    if any(type(v) is not dict or set(v)!={'replica_id','signature_hex'} for v in d['votes']):
        raise RegistryError('invalid registry vote shape')
    return RegistryCertificate(unpack_event(d['event']),d['administrator_signature'],
                               tuple(RegistryVote(**v) for v in d['votes']))


def verify_certificate(cert, policy):
    if not isinstance(cert,RegistryCertificate) or cert.event.registry!=policy.commitment:
        return False
    if not _check_sig(policy.administrator_key,cert.administrator_signature,_encoding(approval_body(cert.event))):
        return False
    keys=policy.keys(); seen=set()
    for vote in cert.votes:
        if (vote.replica_id not in keys or vote.replica_id in seen or
            not _check_sig(keys[vote.replica_id],vote.signature_hex,_encoding(vote_body(vote.replica_id,cert.event)))):
            return False
        seen.add(vote.replica_id)
    return len(seen)>=policy.quorum


@dataclass(frozen=True)
class RootRegistration:
    scope: ScopePolicy
    cap_units: int
    lifetime_allocated: int
    epoch: int


@dataclass(frozen=True)
class RegistryState:
    active: dict[tuple[str,str],RootRegistration]
    seen_scope_ids: frozenset[str]


def initial_state(): return RegistryState({},frozenset())


def transition(state,event,policy):
    if event.registry!=policy.commitment: raise RegistryError('wrong registry policy')
    new=event.new_scope; key=(new.principal_id,new.resource_id)
    if new.scope_id in state.seen_scope_ids: raise RegistryError('duplicate root scope identity')
    if key not in state.active:
        if (event.kind!='enroll' or event.old_scope!=GENESIS_DIGEST or
            event.old_scope_head!=GENESIS_DIGEST or event.closed_history or
            event.lifetime_allocated!=0 or new.total_units>event.cap_units):
            raise RegistryError('root enrollment must establish a fresh bounded identity')
        active=RootRegistration(new,event.cap_units,0,1)
    else:
        old=state.active[key]
        if (event.kind!='rollover' or event.old_scope!=old.scope.commitment or
            event.cap_units!=old.cap_units or new.total_units<=0):
            raise RegistryError('rollover must reference the currently enrolled root')
        try:
            closing=verify_scope_history(event.closed_history,old.scope,expected_head=event.old_scope_head)
        except (ScopeError,ValueError,TypeError) as exc:
            raise RegistryError('rollover history is invalid') from exc
        used=old.lifetime_allocated+closing.allocated
        if event.lifetime_allocated!=used or used+new.total_units>old.cap_units:
            raise RegistryError('rollover would reset or exceed lifetime budget')
        active=RootRegistration(new,old.cap_units,used,old.epoch+1)
    updated=dict(state.active); updated[key]=active
    return RegistryState(updated,state.seen_scope_ids|{new.scope_id})


class RegistryReplica:
    def __init__(self,policy,replica_id,key,db_path):
        if policy.keys().get(replica_id)!=_key_hex(key): raise RegistryError('replica identity mismatch')
        self.policy=policy;self.id=replica_id;self.key=key;self.db_path=str(db_path)
        with closing(self._db()) as db:
            db.execute('CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY, event BLOB NOT NULL, admin BLOB NOT NULL, signature BLOB NOT NULL)')

    def _db(self):
        db=sqlite3.connect(self.db_path,isolation_level=None,timeout=15)
        db.execute('PRAGMA synchronous=FULL');db.execute('PRAGMA busy_timeout=15000')
        return db

    def _history(self,db):
        rows=db.execute('SELECT sequence,event,admin,signature FROM events ORDER BY sequence').fetchall()
        state=initial_state();prev=GENESIS_DIGEST;out=[]
        for i,(seq,body,admin,vote) in enumerate(rows,1):
            try: ev=unpack_event(json.loads(body))
            except (TypeError,ValueError,KeyError) as exc: raise RegistryError('bad local event') from exc
            if (seq!=i or ev.sequence!=i or ev.previous_digest!=prev or
                _encoding(ev.canonical())!=body or
                not _check_sig(self.policy.administrator_key,admin.hex(),_encoding(approval_body(ev))) or
                not _check_sig(self.policy.keys()[self.id],vote.hex(),_encoding(vote_body(self.id,ev)))):
                raise RegistryError('invalid durable registry record')
            state=transition(state,ev,self.policy);prev=ev.digest
            out.append((ev,admin.hex(),RegistryVote(self.id,vote.hex())))
        return out

    def history(self):
        with closing(self._db()) as db: return self._history(db)

    def vote(self,ev,admin_signature):
        with closing(self._db()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                if not _check_sig(self.policy.administrator_key,admin_signature,_encoding(approval_body(ev))):
                    raise RegistryError('administrator did not approve registry event')
                history=self._history(db)
                if ev.sequence<=len(history):
                    existing, old_admin, vote=history[ev.sequence-1]
                    if existing.digest!=ev.digest or old_admin!=admin_signature:
                        raise RegistryError('registry equivocation rejected')
                    db.execute('COMMIT');return vote
                if ev.sequence!=len(history)+1 or ev.previous_digest!=(history[-1][0].digest if history else GENESIS_DIGEST):
                    raise RegistryError('registry predecessor missing or forked')
                state=initial_state()
                for x,_,_ in history: state=transition(state,x,self.policy)
                transition(state,ev,self.policy)
                sig=self.key.sign(_encoding(vote_body(self.id,ev))).hex()
                db.execute('INSERT INTO events(sequence,event,admin,signature) VALUES(?,?,?,?)',
                           (ev.sequence,_encoding(ev.canonical()),bytes.fromhex(admin_signature),bytes.fromhex(sig)))
                db.execute('COMMIT');return RegistryVote(self.id,sig)
            except BaseException:
                db.execute('ROLLBACK');raise


@dataclass(frozen=True)
class RegistryView:
    certificates: tuple[RegistryCertificate,...]
    state: RegistryState
    @property
    def head(self):return self.certificates[-1].event.digest if self.certificates else GENESIS_DIGEST
    @property
    def sequence(self):return len(self.certificates)


def verify_history(certificates,policy,expected_head):
    state=initial_state();prev=GENESIS_DIGEST
    for i,cert in enumerate(certificates,1):
        if not verify_certificate(cert,policy) or cert.event.sequence!=i or cert.event.previous_digest!=prev:
            raise RegistryError('invalid registry quorum history')
        state=transition(state,cert.event,policy);prev=cert.event.digest
    if prev!=expected_head:raise RegistryError('registry head differs from independent trusted pin')
    return state


class RegistryQuorum:
    def __init__(self,policy,replicas):
        if len({x.id for x in replicas})!=len(replicas) or any(x.policy.commitment!=policy.commitment or x.id not in policy.keys() for x in replicas):
            raise RegistryError('invalid quorum replica set')
        self.policy=policy;self.replicas=replicas;self._serialization=RLock()

    def current(self):
        histories=[]
        for r in self.replicas:
            try:histories.append(r.history())
            except (RegistryError,sqlite3.Error,OSError):continue
        if len(histories)<self.policy.quorum:raise RegistryError('insufficient registry replicas')
        state=initial_state();prev=GENESIS_DIGEST;certificates=[];seq=0
        while True:
            digests={}
            for hist in histories:
                if len(hist)>seq:
                    event,admin,vote=hist[seq]
                    digests.setdefault((event.digest,admin),[]).append((event,vote))
            if not digests:break
            if len(digests)!=1:raise RegistryError('registry fork or conflicting approvals')
            ((digest,admin),voters),=digests.items()
            if len(voters)<self.policy.quorum:raise RegistryError('unresolved partially signed registry event')
            ev=voters[0][0];cert=RegistryCertificate(ev,admin,tuple(v for _,v in voters))
            if not verify_certificate(cert,self.policy) or ev.sequence!=seq+1 or ev.previous_digest!=prev:
                raise RegistryError('invalid registry voting chain')
            state=transition(state,ev,self.policy)
            certificates.append(cert);prev=digest;seq+=1
        return RegistryView(tuple(certificates),state)

    def _publish(self,event,administrator_key):
        if _key_hex(administrator_key)!=self.policy.administrator_key:
            raise RegistryError('wrong registry administrator')
        signature=administrator_key.sign(_encoding(approval_body(event))).hex()
        votes=[]
        for r in self.replicas:
            try:votes.append(r.vote(event,signature))
            except (RegistryError,sqlite3.Error,OSError):continue
        cert=RegistryCertificate(event,signature,tuple(votes))
        if not verify_certificate(cert,self.policy):
            raise RegistryError('registry quorum could not commit event')
        fresh=self.current()
        if fresh.head!=event.digest or fresh.sequence!=event.sequence:
            raise RegistryError('registry commit is not at certified tip')
        return cert

    def enroll(self,scope,cap_units,administrator_key):
        with self._serialization:
            view=self.current()
            ev=RegistryEvent(self.policy.commitment,view.sequence+1,view.head,'enroll',scope,
                             GENESIS_DIGEST,GENESIS_DIGEST,(),cap_units,0)
            transition(view.state,ev,self.policy)
            return self._publish(ev,administrator_key)

    def rollover(self,old_scope_quorum,new_scope,administrator_key):
        with self._serialization:
            view=self.current();key=(new_scope.principal_id,new_scope.resource_id)
            previous=view.state.active.get(key)
            if previous is None or previous.scope.commitment!=old_scope_quorum.policy.commitment:
                raise RegistryError('old root is no longer active')
            closed=old_scope_quorum.current()
            ev=RegistryEvent(self.policy.commitment,view.sequence+1,view.head,'rollover',new_scope,
                             previous.scope.commitment,closed.head,tuple(closed.history),previous.cap_units,
                             previous.lifetime_allocated+closed.state.allocated)
            transition(view.state,ev,self.policy)
            return self._publish(ev,administrator_key)

    def require_active(self,scope_policy,*,expected_principal,expected_resource):
        view=self.current()
        if scope_policy.principal_id!=expected_principal or scope_policy.resource_id!=expected_resource:
            raise RegistryError('caller principal/resource mismatch')
        registered=view.state.active.get((expected_principal,expected_resource))
        if registered is None or registered.scope.commitment!=scope_policy.commitment:
            raise RegistryError('scope not active in global registry')
        return view


class RegistryActionGate:
    """Local serialized composition. Distributed execution needs shared linearization."""
    def __init__(self,registry,root,child,*,expected_principal,expected_resource):
        self.registry=registry;self.root=root
        self.child_gate=ScopeActionGate(root,child,expected_principal=expected_principal,
                                        expected_resource=expected_resource)
        self.expected_principal=expected_principal;self.expected_resource=expected_resource

    def check_and_consume(self,bundle,*,expected_v2_epoch,expected_v2_previous_digest):
        with self.registry._serialization:
            self.registry.require_active(self.root.policy,expected_principal=self.expected_principal,
                                         expected_resource=self.expected_resource)
            return self.child_gate.check_and_consume(bundle,expected_v2_epoch=expected_v2_epoch,
                                                     expected_v2_previous_digest=expected_v2_previous_digest)
