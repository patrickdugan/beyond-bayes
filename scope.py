"""ACE v0.9: a separately pinned, quorum-backed alpha budget across campaigns.

Root-scope grants consume a nonrefundable allocation *before* any child campaign
is created or sampled. Every child has a deterministic scope-derived identity,
and the exact CampaignPolicy is bound by a signed parent grant.

Local SQLite replicas are an experimental Byzantine-quorum model. This module
does not establish the statistical conditional-null premise or a network BFT
protocol. The executor must use ScopeActionGate rather than a raw child gate.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from anchor import AnchorIdentity
from campaign import CampaignPolicy, CampaignQuorum, CampaignError, SCALE
from campaign_certificate import CampaignActionGate
from provenance import _digest, _encoding
from witnessed import GENESIS_DIGEST, _check_sig, _key_hex, _check_hex256

SCOPE_SCHEMA = 'ACE-risk-scope-policy-v1'
GRANT_SCHEMA = 'ACE-risk-scope-grant-v1'
VOTE_DOMAIN = 'ACE:risk-scope-grant:v1'
ACTION_SCOPE_SCHEMA = 'ACE-scoped-action-v1'

class ScopeError(ValueError):
    pass


def _int(value: object, lo: int, hi: int) -> bool:
    return type(value) is int and lo <= value <= hi


def _name(value: object, lo: int = 1, hi: int = 128) -> bool:
    return type(value) is str and lo <= len(value) <= hi and all(32 <= ord(c) <= 126 for c in value)


def _hex(value: object) -> bool:
    return _check_hex256(value)


@dataclass(frozen=True)
class ScopePolicy:
    scope_id: str
    principal_id: str
    resource_id: str
    total_units: int
    replicas: tuple[AnchorIdentity, ...]
    max_faulty: int
    quorum: int

    def __post_init__(self):
        if not (_name(self.scope_id, 16) and _name(self.principal_id) and _name(self.resource_id)):
            raise ScopeError('invalid scope identity or resource')
        try:
            CampaignPolicy(self.scope_id, self.total_units, self.replicas,
                           self.max_faulty, self.quorum)
        except (CampaignError, ValueError, TypeError) as exc:
            raise ScopeError('invalid scope budget or signing quorum') from exc

    def canonical(self) -> dict:
        return {'schema': SCOPE_SCHEMA, 'scope_id': self.scope_id,
                'principal_id': self.principal_id, 'resource_id': self.resource_id,
                'scale': SCALE, 'total_units': self.total_units,
                'replicas': [x.canonical() for x in self.replicas],
                'max_faulty': self.max_faulty, 'quorum': self.quorum}

    @property
    def commitment(self) -> str:
        return _digest(self.canonical())

    def keys(self) -> dict[str, str]:
        return {x.replica_id: x.public_key_hex for x in self.replicas}


def unpack_policy(raw: object) -> ScopePolicy:
    fields = {'schema', 'scope_id', 'principal_id', 'resource_id', 'scale',
              'total_units', 'replicas', 'max_faulty', 'quorum'}
    if type(raw) is not dict or set(raw) != fields or raw['schema'] != SCOPE_SCHEMA or \
            type(raw['scale']) is not int or raw['scale'] != SCALE or type(raw['replicas']) is not list:
        raise ScopeError('malformed scope policy')
    entries = []
    for r in raw['replicas']:
        if type(r) is not dict or set(r) != {'replica_id', 'public_key_hex'}:
            raise ScopeError('malformed replica identity')
        entries.append(AnchorIdentity(r['replica_id'], r['public_key_hex']))
    p = ScopePolicy(raw['scope_id'], raw['principal_id'], raw['resource_id'],
                    raw['total_units'], tuple(entries), raw['max_faulty'], raw['quorum'])
    if p.canonical() != raw:
        raise ScopeError('noncanonical scope policy')
    return p


def child_id(scope: ScopePolicy, child_nonce: str) -> str:
    if not _name(child_nonce, 16):
        raise ScopeError('invalid child nonce')
    return _digest({'domain': 'ACE:scope-child-id:v1',
                    'scope': scope.commitment, 'nonce': child_nonce})


@dataclass(frozen=True)
class ScopeGrant:
    scope: str
    sequence: int
    previous_digest: str
    child_nonce: str
    child_id: str
    child_policy: str
    child_units: int
    allocated_units: int

    def __post_init__(self):
        if (not _hex(self.scope) or not _hex(self.previous_digest) or
            not _int(self.sequence, 1, 1_000_000_000) or
            not _name(self.child_nonce, 16) or not _hex(self.child_id) or
            not _hex(self.child_policy) or not _int(self.child_units, 1, SCALE) or
            not _int(self.allocated_units, 1, SCALE)):
            raise ScopeError('invalid grant fields')

    def canonical(self) -> dict:
        return {'schema': GRANT_SCHEMA, 'scope': self.scope,
                'sequence': self.sequence, 'previous_digest': self.previous_digest,
                'child_nonce': self.child_nonce, 'child_id': self.child_id,
                'child_policy': self.child_policy, 'child_units': self.child_units,
                'allocated_units': self.allocated_units}

    @property
    def digest(self) -> str:
        return _digest(self.canonical())


def unpack_grant(raw: Any) -> ScopeGrant:
    fields = {'schema', 'scope', 'sequence', 'previous_digest', 'child_nonce',
              'child_id', 'child_policy', 'child_units', 'allocated_units'}
    if type(raw) is not dict or set(raw) != fields or raw['schema'] != GRANT_SCHEMA:
        raise ScopeError('malformed scope grant')
    obj = ScopeGrant(raw['scope'], raw['sequence'], raw['previous_digest'],
                     raw['child_nonce'], raw['child_id'], raw['child_policy'],
                     raw['child_units'], raw['allocated_units'])
    if obj.canonical() != raw:
        raise ScopeError('noncanonical scope grant')
    return obj


@dataclass(frozen=True)
class ScopeVote:
    replica_id: str
    grant_digest: str
    signature_hex: str

    def body(self) -> dict:
        return {'domain': VOTE_DOMAIN, 'replica_id': self.replica_id,
                'grant_digest': self.grant_digest}

    def canonical(self) -> dict:
        return {'replica_id': self.replica_id, 'grant_digest': self.grant_digest,
                'signature_hex': self.signature_hex}


def unpack_vote(raw: object) -> ScopeVote:
    if type(raw) is not dict or set(raw) != {'replica_id', 'grant_digest', 'signature_hex'}:
        raise ScopeError('malformed scope vote')
    return ScopeVote(raw['replica_id'], raw['grant_digest'], raw['signature_hex'])


@dataclass(frozen=True)
class ScopeCertificate:
    grant: ScopeGrant
    votes: tuple[ScopeVote, ...]

    def canonical(self) -> dict:
        return {'grant': self.grant.canonical(), 'votes': [v.canonical() for v in self.votes]}


def unpack_certificate(raw: object) -> ScopeCertificate:
    if type(raw) is not dict or set(raw) != {'grant', 'votes'} or type(raw['votes']) is not list:
        raise ScopeError('malformed scope certificate')
    return ScopeCertificate(unpack_grant(raw['grant']), tuple(unpack_vote(v) for v in raw['votes']))


def verify_certificate(cert: ScopeCertificate, policy: ScopePolicy) -> bool:
    if not isinstance(cert, ScopeCertificate) or cert.grant.scope != policy.commitment:
        return False
    seen = set(); keys = policy.keys()
    for vote in cert.votes:
        if (type(vote.replica_id) is not str or vote.replica_id not in keys or
            vote.replica_id in seen or vote.grant_digest != cert.grant.digest or
            not _check_sig(keys[vote.replica_id], vote.signature_hex, _encoding(vote.body()))):
            return False
        seen.add(vote.replica_id)
    return len(seen) >= policy.quorum


@dataclass(frozen=True)
class ScopeState:
    allocated: int = 0
    child_ids: frozenset[str] = frozenset()


def transition(state: ScopeState, grant: ScopeGrant, policy: ScopePolicy) -> ScopeState:
    if grant.scope != policy.commitment:
        raise ScopeError('wrong scope')
    if grant.child_id != child_id(policy, grant.child_nonce):
        raise ScopeError('child identifier does not bind the parent scope')
    if grant.child_id in state.child_ids:
        raise ScopeError('duplicate child campaign identity')
    if (grant.allocated_units != state.allocated + grant.child_units or
        state.allocated + grant.child_units > policy.total_units):
        raise ScopeError('root budget exceeded or refunded')
    return ScopeState(grant.allocated_units, state.child_ids | {grant.child_id})


def check_child_policy(scope: ScopePolicy, grant: ScopeGrant, child: CampaignPolicy) -> None:
    if (child_id(scope, grant.child_nonce) != child.campaign_id or
        grant.child_id != child.campaign_id or
        grant.child_policy != child.commitment or
        grant.child_units != child.total_units or
        grant.scope != scope.commitment):
        raise ScopeError('child campaign policy differs from the allocated grant')


def action_scope_context(scope: ScopePolicy, grant: ScopeGrant) -> dict:
    return {'schema': ACTION_SCOPE_SCHEMA, 'scope_commitment': scope.commitment,
            'principal_id': scope.principal_id, 'resource_id': scope.resource_id,
            'grant_digest': grant.digest, 'child_id': grant.child_id,
            'child_policy': grant.child_policy, 'child_units': grant.child_units}


class ScopeReplica:
    """Append-only signed vote journal; rollback protection requires a live quorum."""
    def __init__(self, policy: ScopePolicy, replica_id: str,
                 private_key: Ed25519PrivateKey, db_path: Path | str):
        if not isinstance(private_key, Ed25519PrivateKey) or \
                policy.keys().get(replica_id) != _key_hex(private_key):
            raise ScopeError('replica key does not belong to scope')
        self.policy = policy; self.id = replica_id; self.key = private_key
        self.db_path = str(db_path)
        with closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS grants ('
                       'scope TEXT NOT NULL, sequence INTEGER NOT NULL, '
                       'record BLOB NOT NULL, vote BLOB NOT NULL, '
                       'PRIMARY KEY(scope, sequence))')
            db.execute('COMMIT')

    def _connect(self):
        db = sqlite3.connect(self.db_path, timeout=15, isolation_level=None)
        db.execute('PRAGMA busy_timeout=15000')
        db.execute('PRAGMA synchronous=FULL')
        return db

    def _history_in_tx(self, db) -> list[tuple[ScopeGrant, ScopeVote]]:
        rows = db.execute('SELECT sequence,record,vote FROM grants WHERE scope=? ORDER BY sequence',
                          (self.policy.commitment,)).fetchall()
        out = [];state = ScopeState();prev = GENESIS_DIGEST
        for i, (seq, body, signature) in enumerate(rows, 1):
            try:
                raw = json.loads(body)
                grant = unpack_grant(raw)
            except (TypeError, ValueError, KeyError) as exc:
                raise ScopeError('invalid durable grant encoding') from exc
            if (seq != i or grant.sequence != i or grant.previous_digest != prev or
                _encoding(grant.canonical()) != body):
                raise ScopeError('invalid durable grant chain')
            state = transition(state, grant, self.policy)
            vote = ScopeVote(self.id, grant.digest, signature.hex())
            if not _check_sig(self.policy.keys()[self.id], vote.signature_hex, _encoding(vote.body())):
                raise ScopeError('bad durable grant signature')
            out.append((grant, vote)); prev = grant.digest
        return out

    def history(self):
        with closing(self._connect()) as db:
            return self._history_in_tx(db)

    def vote(self, grant: ScopeGrant) -> ScopeVote:
        with closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                hist = self._history_in_tx(db)
                if grant.sequence <= len(hist):
                    previous, vote = hist[grant.sequence - 1]
                    if previous.digest != grant.digest:
                        raise ScopeError('honest replica has signed another successor')
                    db.execute('COMMIT')
                    return vote
                if grant.sequence != len(hist) + 1 or \
                        grant.previous_digest != (hist[-1][0].digest if hist else GENESIS_DIGEST):
                    raise ScopeError('missing or forked predecessor')
                state = ScopeState()
                for old, _ in hist:
                    state = transition(state, old, self.policy)
                transition(state, grant, self.policy)
                vote = ScopeVote(self.id, grant.digest,
                                 self.key.sign(_encoding({'domain': VOTE_DOMAIN,
                                         'replica_id': self.id, 'grant_digest': grant.digest})).hex())
                db.execute('INSERT INTO grants(scope,sequence,record,vote) VALUES(?,?,?,?)',
                           (self.policy.commitment, grant.sequence,
                            _encoding(grant.canonical()), bytes.fromhex(vote.signature_hex)))
                db.execute('COMMIT')
                return vote
            except BaseException:
                db.execute('ROLLBACK')
                raise


@dataclass(frozen=True)
class ScopeView:
    history: tuple[ScopeCertificate, ...]
    state: ScopeState

    @property
    def sequence(self) -> int:
        return len(self.history)

    @property
    def head(self) -> str:
        return self.history[-1].grant.digest if self.history else GENESIS_DIGEST


class ScopeQuorum:
    def __init__(self, policy: ScopePolicy, replicas: list[ScopeReplica]):
        if (len({r.id for r in replicas}) != len(replicas) or
            any(r.policy.commitment != policy.commitment or r.id not in policy.keys()
                for r in replicas)):
            raise ScopeError('duplicate or mismatched scope replicas')
        self.policy = policy; self.replicas = replicas

    def current(self) -> ScopeView:
        histories = []
        for replica in self.replicas:
            try:
                histories.append(replica.history())
            except (ScopeError, sqlite3.Error, OSError):
                continue
        if len(histories) < self.policy.quorum:
            raise ScopeError('insufficient readable root replicas')
        state = ScopeState();prev = GENESIS_DIGEST;certs = [];seq = 0
        while True:
            by_digest = {}
            for hist in histories:
                if len(hist) > seq:
                    item, vote = hist[seq]
                    by_digest.setdefault(item.digest, []).append((item, vote))
            if not by_digest:
                break
            if len(by_digest) != 1:
                raise ScopeError('fork in root grant histories')
            votes = next(iter(by_digest.values()))
            if len(votes) < self.policy.quorum:
                raise ScopeError('unresolved partially committed root grant')
            grant = votes[0][0]
            if grant.sequence != seq + 1 or grant.previous_digest != prev:
                raise ScopeError('bad root grant predecessor')
            cert = ScopeCertificate(grant, tuple(v for _, v in votes))
            if not verify_certificate(cert, self.policy):
                raise ScopeError('bad grant vote quorum')
            state = transition(state, grant, self.policy)
            certs.append(cert);prev = grant.digest;seq += 1
        return ScopeView(tuple(certs), state)

    def allocate(self, child: CampaignPolicy, nonce: str) -> ScopeCertificate:
        if child.campaign_id != child_id(self.policy, nonce):
            raise ScopeError('child policy must use scope-derived identity')
        view = self.current()
        grant = ScopeGrant(self.policy.commitment, view.sequence + 1, view.head,
                           nonce, child.campaign_id, child.commitment,
                           child.total_units, view.state.allocated + child.total_units)
        transition(view.state, grant, self.policy)
        votes = []
        for replica in self.replicas:
            try:
                votes.append(replica.vote(grant))
            except (ScopeError, sqlite3.Error, OSError):
                continue
        cert = ScopeCertificate(grant, tuple(votes))
        if not verify_certificate(cert, self.policy):
            raise ScopeError('root quorum failed; speculative votes require recovery')
        now = self.current()
        if now.head != grant.digest or now.sequence != grant.sequence:
            raise ScopeError('root grant readback failed')
        return cert


def verify_history(history: list[ScopeCertificate] | tuple[ScopeCertificate, ...],
                   policy: ScopePolicy, *, expected_head: str) -> ScopeState:
    """Verify signed history against an *externally trusted* final head."""
    state = ScopeState();prev = GENESIS_DIGEST
    for i, cert in enumerate(history, 1):
        grant = cert.grant
        if (not verify_certificate(cert, policy) or grant.sequence != i or
            grant.previous_digest != prev):
            raise ScopeError('invalid root grant history')
        state = transition(state, grant, policy)
        prev = grant.digest
    if prev != expected_head:
        raise ScopeError('root head differs from trusted monotonic checkpoint')
    return state


class ScopeActionGate:
    """Root-grant guard around the child CampaignActionGate.

    The caller must pin scope ID, principal and resource externally and must use
    this wrapper as the only path to the downstream action executor.
    """
    def __init__(self, root_quorum: ScopeQuorum, child_quorum: CampaignQuorum,
                 *, expected_principal: str, expected_resource: str):
        if (root_quorum.policy.principal_id != expected_principal or
            root_quorum.policy.resource_id != expected_resource):
            raise ScopeError('scope policy differs from the externally pinned principal/resource')
        self.root = root_quorum;self.child = child_quorum

    def check_and_consume(self, bundle: dict, *, expected_v2_epoch: int,
                          expected_v2_previous_digest: str):
        root_view = self.root.current()
        matching = [c.grant for c in root_view.history
                    if c.grant.child_policy == self.child.policy.commitment]
        if len(matching) != 1:
            raise ScopeError('live root quorum has no unique grant for this child policy')
        grant = matching[0]
        check_child_policy(self.root.policy, grant, self.child.policy)
        expected = action_scope_context(self.root.policy, grant)
        try:
            v2_action = bundle['v2_certificate']['action_intent']
            actual = v2_action['parameters']['ace_scope']
            target_resource = v2_action['resource']
        except (KeyError, TypeError) as exc:
            raise ScopeError('missing scope binding in signed v2 action') from exc
        if actual != expected or target_resource != self.root.policy.resource_id:
            raise ScopeError('v2 action resource or scope grant differs from the pinned root')
        return CampaignActionGate(self.child).check_and_consume(
            bundle, expected_v2_epoch=expected_v2_epoch,
            expected_v2_previous_digest=expected_v2_previous_digest)
