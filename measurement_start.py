"""ACE v0.10: quorum-witnessed starts and counters for a *simulated* instrument.

Witnesses check the live registry, root grant and child reservation at signing.
A separate signed instrument arm token and signed per-report counter provide
cryptographic provenance ORDER, assuming the enrolled instrument obeys the
acquire-after-arm rule and its key/counter state are protected. Host-controlled
software, future peeking and physical clocks remain outside these guarantees.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
import json
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from campaign import CampaignQuorum
from provenance import Protocol, SignedObservation, _encoding, _digest
from root_registry import RegistryQuorum, RegistryPolicy, RegistryError
from scope import ScopeQuorum, check_child_policy, ScopeError
from witnessed import GENESIS_DIGEST, _key_hex, _check_sig, _check_hex256, report_digest

SCHEMA='ACE-measurement-start-v1'
MEASUREMENT_SCHEMA='ACE-instrument-measurement-v1'
ARM_DOMAIN='ACE:device-arm:v1'
VOTE_DOMAIN='ACE:start-witness:v1'
MEASURE_DOMAIN='ACE:device-observation:v1'

class StartError(ValueError): pass


def _valid_name(s,minlen=1): return type(s) is str and minlen<=len(s)<=128 and all(32<=ord(c)<=126 for c in s)

@dataclass(frozen=True)
class StartBinding:
    registry: str
    registry_head: str
    scope: str
    scope_head: str
    root_grant: str
    campaign: str
    reservation: str
    protocol: str
    witness_policy: str
    cluster_plan: str
    v2_policy: str
    action: str
    instrument_id: str
    epoch: int
    counter_start: int
    max_samples: int
    experiment_nonce: str

    def __post_init__(self):
        hs=(self.registry,self.registry_head,self.scope,self.scope_head,self.root_grant,
            self.campaign,self.reservation,self.protocol,self.witness_policy,self.cluster_plan,self.v2_policy,self.action)
        if (any(not _check_hex256(x) for x in hs) or not _valid_name(self.instrument_id) or
            not _valid_name(self.experiment_nonce,16) or type(self.epoch) is not int or self.epoch<1 or
            type(self.counter_start) is not int or self.counter_start<0 or
            type(self.max_samples) is not int or not 1<=self.max_samples<=1_000_000 or
            self.counter_start+self.max_samples>2**63-1):
            raise StartError('invalid start binding')

    def canonical(self):
        return {'schema':SCHEMA,**asdict(self)}

    @property
    def digest(self):return _digest(self.canonical())


def unpack_binding(raw):
    fields=set(StartBinding.__dataclass_fields__)
    if type(raw) is not dict or set(raw)!=fields|{'schema'} or raw['schema']!=SCHEMA:
        raise StartError('invalid start binding schema')
    binding=StartBinding(**{k:raw[k] for k in fields})
    if binding.canonical()!=raw:raise StartError('noncanonical start binding')
    return binding


def arm_body(binding):return {'domain':ARM_DOMAIN,'start_binding_digest':binding.digest}


@dataclass(frozen=True)
class StartRecord:
    registry: str
    sequence: int
    previous_digest: str
    binding: StartBinding
    arm_signature: str

    def canonical(self):
        return {'schema':'ACE-start-record-v1','registry':self.registry,
                'sequence':self.sequence,'previous_digest':self.previous_digest,
                'binding':self.binding.canonical(),'arm_signature':self.arm_signature}

    @property
    def digest(self):return _digest(self.canonical())


def unpack_record(raw):
    if type(raw) is not dict or set(raw)!={'schema','registry','sequence','previous_digest','binding','arm_signature'} or raw['schema']!='ACE-start-record-v1':
        raise StartError('invalid start event shape')
    rec=StartRecord(raw['registry'],raw['sequence'],raw['previous_digest'],unpack_binding(raw['binding']),raw['arm_signature'])
    if rec.canonical()!=raw:raise StartError('noncanonical start event')
    return rec


def vote_body(replica_id,rec):return {'domain':VOTE_DOMAIN,'replica_id':replica_id,'start_record':rec.digest}

@dataclass(frozen=True)
class StartVote:
    replica_id: str
    signature_hex: str
    def canonical(self):return asdict(self)

@dataclass(frozen=True)
class StartCertificate:
    record: StartRecord
    votes: tuple[StartVote,...]
    def canonical(self):return {'record':self.record.canonical(),'votes':[v.canonical() for v in self.votes]}


def unpack_certificate(raw):
    if type(raw) is not dict or set(raw)!={'record','votes'} or type(raw['votes']) is not list or any(type(v) is not dict or set(v)!={'replica_id','signature_hex'} for v in raw['votes']):
        raise StartError('invalid start certificate shape')
    return StartCertificate(unpack_record(raw['record']),tuple(StartVote(**x) for x in raw['votes']))


def verify_certificate(cert,policy):
    if not isinstance(cert,StartCertificate):return False
    r=cert.record;b=r.binding
    if (r.registry!=policy.commitment or b.registry!=policy.commitment or
        not _check_hex256(r.previous_digest) or type(r.sequence) is not int or r.sequence<1):return False
    try: device=policy.enrolled_instrument(b.instrument_id)
    except RegistryError:return False
    if b.epoch!=device.epoch or not _check_sig(device.public_key_hex,r.arm_signature,_encoding(arm_body(b))):return False
    seen=set();keys=policy.keys()
    for v in cert.votes:
        if v.replica_id not in keys or v.replica_id in seen or not _check_sig(keys[v.replica_id],v.signature_hex,_encoding(vote_body(v.replica_id,r))):return False
        seen.add(v.replica_id)
    return len(seen)>=policy.quorum


@dataclass(frozen=True)
class StartState:
    counter_highwater: dict[str,int]
    nonces: frozenset[str]
    reservations: frozenset[str]


def initial_state():return StartState({},frozenset(),frozenset())


def transition(state,rec,policy):
    b=rec.binding
    if rec.registry!=policy.commitment or b.registry!=policy.commitment:
        raise StartError('wrong signing registry')
    instrument=policy.enrolled_instrument(b.instrument_id)
    if b.epoch!=instrument.epoch or not _check_sig(instrument.public_key_hex,rec.arm_signature,_encoding(arm_body(b))):
        raise StartError('invalid instrument arm token')
    if b.experiment_nonce in state.nonces:
        raise StartError('reused experiment nonce')
    if b.reservation in state.reservations:
        raise StartError('reused risk reservation for another experiment start')
    old=state.counter_highwater.get(b.instrument_id,0)
    if b.counter_start<old:raise StartError('overlapping counter window')
    updated=dict(state.counter_highwater);updated[b.instrument_id]=b.counter_start+b.max_samples
    return StartState(updated,state.nonces|{b.experiment_nonce},state.reservations|{b.reservation})


def verify_history(history,policy,expected_head):
    state=initial_state();previous=GENESIS_DIGEST
    for seq,cert in enumerate(history,1):
        rec=cert.record
        if not verify_certificate(cert,policy) or rec.sequence!=seq or rec.previous_digest!=previous:
            raise StartError('bad attested start chain')
        state=transition(state,rec,policy);previous=rec.digest
    if previous!=expected_head:raise StartError('start head differs from independent pin')
    return state


class StartReplica:
    def __init__(self,registry,root,child,replica_id,key,db_path):
        self.registry=registry;self.root=root;self.child=child;self.id=replica_id;self.key=key;self.db_path=str(db_path)
        if registry.policy.keys().get(replica_id)!=_key_hex(key):raise StartError('unknown start witness identity')
        with closing(self._db()) as db:
            db.execute('CREATE TABLE IF NOT EXISTS starts (sequence INTEGER PRIMARY KEY, body BLOB NOT NULL, vote BLOB NOT NULL)')

    def _db(self):
        db=sqlite3.connect(self.db_path,isolation_level=None,timeout=15)
        db.execute('PRAGMA busy_timeout=15000');db.execute('PRAGMA synchronous=FULL')
        return db

    def _history(self,db):
        rows=db.execute('SELECT sequence,body,vote FROM starts ORDER BY sequence').fetchall()
        state=initial_state();prev=GENESIS_DIGEST;out=[]
        for i,(seq,body,vote) in enumerate(rows,1):
            try:rec=unpack_record(json.loads(body))
            except (KeyError,TypeError,ValueError) as exc:raise StartError('invalid stored start') from exc
            if seq!=i or rec.sequence!=i or rec.previous_digest!=prev or _encoding(rec.canonical())!=body or not _check_sig(self.registry.policy.keys()[self.id],vote.hex(),_encoding(vote_body(self.id,rec))):
                raise StartError('broken durable start chain')
            state=transition(state,rec,self.registry.policy);prev=rec.digest
            out.append((rec,StartVote(self.id,vote.hex())))
        return out

    def history(self):
        with closing(self._db()) as db:return self._history(db)

    def _check_live(self,b):
        v=self.registry.require_active(self.root.policy,expected_principal=self.root.policy.principal_id,
                                       expected_resource=self.root.policy.resource_id)
        if b.registry_head!=v.head or b.scope!=self.root.policy.commitment:
            raise StartError('stale registry head or scope')
        root=self.root.current()
        if b.scope_head!=root.head:
            raise StartError('stale root grant head')
        matches=[x.grant for x in root.history if x.grant.digest==b.root_grant]
        if len(matches)!=1:raise StartError('missing unique root grant')
        try:check_child_policy(self.root.policy,matches[0],self.child.policy)
        except ScopeError as exc:raise StartError('child policy differs from signed grant') from exc
        cv=self.child.current()
        if cv.state.stage!='reserved' or not cv.history or cv.head!=b.reservation or cv.history[-1].record.kind!='reserve':
            raise StartError('child has no live reserved experiment')
        r=cv.history[-1].record
        if (b.campaign!=self.child.policy.commitment or
            r.payload['protocol']!=b.protocol or r.payload['witness_policy']!=b.witness_policy or
            r.payload['cluster_plan']!=b.cluster_plan or r.payload['v2_policy']!=b.v2_policy or
            r.payload['action']!=b.action):
            raise StartError('reservation commitments differ from instrument start')

    def vote(self,rec):
        with closing(self._db()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                history=self._history(db)
                if rec.sequence<=len(history):
                    past,vote=history[rec.sequence-1]
                    if past.digest!=rec.digest:raise StartError('forked start receipt')
                    db.execute('COMMIT');return vote
                if rec.sequence!=len(history)+1 or rec.previous_digest!=(history[-1][0].digest if history else GENESIS_DIGEST):
                    raise StartError('missing start predecessor')
                state=initial_state()
                for ev,_ in history:state=transition(state,ev,self.registry.policy)
                transition(state,rec,self.registry.policy)
                self._check_live(rec.binding)
                sig=self.key.sign(_encoding(vote_body(self.id,rec))).hex()
                db.execute('INSERT INTO starts(sequence,body,vote) VALUES(?,?,?)',
                           (rec.sequence,_encoding(rec.canonical()),bytes.fromhex(sig)))
                db.execute('COMMIT');return StartVote(self.id,sig)
            except BaseException:
                db.execute('ROLLBACK');raise


@dataclass(frozen=True)
class StartView:
    history: tuple[StartCertificate,...]
    state: StartState
    @property
    def sequence(self):return len(self.history)
    @property
    def head(self):return self.history[-1].record.digest if self.history else GENESIS_DIGEST


class StartQuorum:
    def __init__(self,registry,root,child,replicas):
        self.registry=registry;self.root=root;self.child=child;self.replicas=replicas
        if len({r.id for r in replicas})!=len(replicas) or any(r.registry.policy.commitment!=registry.policy.commitment for r in replicas):
            raise StartError('start replica roster mismatch')

    def current(self):
        histories=[]
        for r in self.replicas:
            try:histories.append(r.history())
            except (StartError,sqlite3.Error,OSError):continue
        if len(histories)<self.registry.policy.quorum:raise StartError('insufficient start witnesses')
        certs=[];state=initial_state();prev=GENESIS_DIGEST;seq=0
        while True:
            by={}
            for h in histories:
                if len(h)>seq:
                    rec,vote=h[seq];by.setdefault(rec.digest,[]).append((rec,vote))
            if not by:break
            if len(by)!=1:raise StartError('start witness equivocation')
            ((digest,voters),)=by.items()
            if len(voters)<self.registry.policy.quorum:raise StartError('unresolved partially signed start')
            cert=StartCertificate(voters[0][0],tuple(v for _,v in voters))
            if not verify_certificate(cert,self.registry.policy) or cert.record.sequence!=seq+1 or cert.record.previous_digest!=prev:
                raise StartError('invalid quorum attestation')
            state=transition(state,cert.record,self.registry.policy)
            certs.append(cert);prev=digest;seq+=1
        return StartView(tuple(certs),state)

    def make_binding(self,*,protocol,witness_policy,cluster_plan,v2_policy,action,instrument_id,counter_start,max_samples,experiment_nonce):
        rv=self.registry.require_active(self.root.policy,expected_principal=self.root.policy.principal_id,expected_resource=self.root.policy.resource_id)
        sv=self.root.current();cv=self.child.current()
        if cv.state.stage!='reserved':raise StartError('child experiment is not reserved')
        r=cv.history[-1].record
        if (r.payload['protocol'],r.payload['witness_policy'],r.payload['cluster_plan'],r.payload['v2_policy'],r.payload['action'])!=(protocol,witness_policy,cluster_plan,v2_policy,action):
            raise StartError('start request differs from signed reservation')
        grants=[x.grant for x in sv.history if x.grant.child_policy==self.child.policy.commitment]
        if len(grants)!=1:raise StartError('no unique parent grant')
        check_child_policy(self.root.policy,grants[0],self.child.policy)
        identity=self.registry.policy.enrolled_instrument(instrument_id)
        return StartBinding(self.registry.policy.commitment,rv.head,
                            self.root.policy.commitment,sv.head,grants[0].digest,
                            self.child.policy.commitment,cv.head,protocol,witness_policy,
                            cluster_plan,v2_policy,action,instrument_id,identity.epoch,
                            counter_start,max_samples,experiment_nonce)

    def issue(self,binding,arm_signature):
        with self.registry._serialization:
            view=self.current()
            record=StartRecord(self.registry.policy.commitment,view.sequence+1,view.head,binding,arm_signature)
            transition(view.state,record,self.registry.policy)
            votes=[]
            for r in self.replicas:
                try:votes.append(r.vote(record))
                except (StartError,RegistryError,ScopeError,sqlite3.Error,OSError):continue
            cert=StartCertificate(record,tuple(votes))
            if not verify_certificate(cert,self.registry.policy):raise StartError('start witness quorum failed')
            now=self.current()
            if now.head!=record.digest:raise StartError('start readback failed')
            return cert


@dataclass(frozen=True)
class TimedObservation:
    start_digest: str
    instrument_id: str
    epoch: int
    counter: int
    report: SignedObservation
    signature_hex: str

    def message(self):
        return {'domain':MEASURE_DOMAIN,'start_digest':self.start_digest,
                'instrument_id':self.instrument_id,'epoch':self.epoch,
                'counter':self.counter,'report_digest':report_digest(self.report)}

    def canonical(self):
        return {'schema':MEASUREMENT_SCHEMA,'start_digest':self.start_digest,
                'instrument_id':self.instrument_id,'epoch':self.epoch,
                'counter':self.counter,'report':asdict(self.report),'signature_hex':self.signature_hex}


def unpack_observation(raw):
    if type(raw) is not dict or set(raw)!={'schema','start_digest','instrument_id','epoch','counter','report','signature_hex'} or raw['schema']!=MEASUREMENT_SCHEMA or type(raw['report']) is not dict or set(raw['report'])!={'experiment_id','protocol_commitment','slot_id','bit','signature_hex'}:
        raise StartError('malformed instrument observation')
    o=TimedObservation(raw['start_digest'],raw['instrument_id'],raw['epoch'],raw['counter'],SignedObservation(**raw['report']),raw['signature_hex'])
    if o.canonical()!=raw:raise StartError('noncanonical instrument observation')
    return o


def verify_observations(cert,measurements,protocol,policy):
    if not verify_certificate(cert,policy):raise StartError('start receipt invalid')
    b=cert.record.binding;instrument=policy.enrolled_instrument(b.instrument_id)
    if protocol.commitment!=b.protocol:raise StartError('sample source roster not bound to start')
    observed=set();out=[]
    for index,m in enumerate(measurements,1):
        if (not isinstance(m,TimedObservation) or m.start_digest!=cert.record.digest or
            m.instrument_id!=b.instrument_id or m.epoch!=instrument.epoch or
            type(m.counter) is not int or m.counter!=b.counter_start+index or
            index>b.max_samples or not _check_sig(instrument.public_key_hex,m.signature_hex,_encoding(m.message()))):
            raise StartError('invalid signed sample timing or counter')
        slot=next((s for s in protocol.slots if s.slot_id==m.report.slot_id),None)
        if slot is None or m.report.slot_id in observed:
            raise StartError('unexpected or repeated sample slot')
        from provenance import SignedEvidenceLedger,Receipt
        ledger=SignedEvidenceLedger(protocol,expected_commitment=protocol.commitment)
        if ledger.offer(m.report)!=Receipt.ACCEPTED:
            raise StartError('bad independently signed sample')
        observed.add(m.report.slot_id);out.append(m.report)
    return tuple(out)


class SimulatedInstrument:
    """Guarded signing interface, not hardware attestation or a trusted clock."""
    def __init__(self,identity,key,policy):
        if _key_hex(key)!=identity.public_key_hex or policy.enrolled_instrument(identity.instrument_id)!=identity:
            raise StartError('invalid physical instrument enrollment')
        self.identity=identity;self.key=key;self.policy=policy;self.counter=0
        self.active=None;self.samples=0

    def arm(self,b):
        if b.instrument_id!=self.identity.instrument_id or b.epoch!=self.identity.epoch or b.counter_start!=self.counter or self.active is not None:
            raise StartError('instrument not at counter arm boundary')
        return self.key.sign(_encoding(arm_body(b))).hex()

    def activate(self,certificate):
        b=certificate.record.binding
        if not verify_certificate(certificate,self.policy) or b.counter_start!=self.counter or b.instrument_id!=self.identity.instrument_id or self.active is not None:
            raise StartError('attempt to activate unattested device start')
        self.active=certificate;self.samples=0

    def sample(self,protocol,slot_id,bit,source_private_key):
        if self.active is None:raise StartError('measurement arrived before witnessed start')
        b=self.active.record.binding
        if self.samples>=b.max_samples:raise StartError('signed measurement window exhausted')
        report=SignedObservation.issue(protocol,slot_id,bit,source_private_key)
        next_counter=self.counter+1
        t=TimedObservation(self.active.record.digest,self.identity.instrument_id,self.identity.epoch,
                           next_counter,report,'')
        result=TimedObservation(t.start_digest,t.instrument_id,t.epoch,t.counter,t.report,
                                self.key.sign(_encoding(t.message())).hex())
        self.counter=next_counter;self.samples+=1
        return result

    def close(self):
        if self.active is None:raise StartError('instrument is not active')
        self.counter=max(self.counter,self.active.record.binding.counter_start+self.active.record.binding.max_samples)
        self.active=None


class MeasuredRegistryActionGate:
    """Serialized local-only composition: attested replay before v0.9 consumption.

    A distributed executor requires an atomic external permission boundary;
    signatures by themselves do not serialize a remote physical side effect.
    """
    def __init__(self,registry,root,child,starts):
        from root_registry import RegistryActionGate
        self.registry=registry;self.root=root;self.child=child;self.starts=starts
        self.parent_gate=RegistryActionGate(registry,root,child,
                       expected_principal=root.policy.principal_id,
                       expected_resource=root.policy.resource_id)

    def check_and_consume(self,campaign_bundle,measurement_bundle,pins,*,
                          expected_v2_epoch,expected_v2_previous_digest):
        from verify_measurement import replay
        with self.registry._serialization:
            current=self.registry.require_active(self.root.policy,
                      expected_principal=self.root.policy.principal_id,
                      expected_resource=self.root.policy.resource_id)
            if (current.head!=pins.get('registry_head') or
                self.root.current().head!=pins.get('scope_head') or
                self.starts.current().head!=pins.get('start_head')):
                raise StartError('stale parent or instrument signing tip')
            if (pins.get('expected_v2_epoch')!=expected_v2_epoch or
                pins.get('expected_v2_previous_digest')!=expected_v2_previous_digest or
                _digest(measurement_bundle['v2_certificate'])!=_digest(campaign_bundle['v2_certificate'])):
                raise StartError('signed measurement and consumed decision differ')
            result=replay(measurement_bundle,pins)
            action=measurement_bundle['v2_certificate']['action_intent']
            if action.get('parameters',{}).get('ace_registry')!=self.registry.policy.commitment:
                raise StartError('action does not pin the global root registry')
            return self.parent_gate.check_and_consume(campaign_bundle,
                         expected_v2_epoch=expected_v2_epoch,
                         expected_v2_previous_digest=expected_v2_previous_digest)
