"""ACE v0.7: a distinct, pinned, witnessed *clustered* decision certificate.

The v1 witness quorum attests the *complete ordered source-report log* and its
continuity. The v2 externally pinned authorization policy interprets that
same attested log using a precommitted cluster plan and conditional null.
This is a version-separated verifier composition, not a claim that the v1
witnesses ran or endorsed the v2 statistical algorithm.

The independent v2 replay lives in independent_cluster_verifier.py. All
external pins must come from a trusted source; self-reported digests do not
establish policy or action authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
import math

from certificates import InvalidCertificate
from conditional import ConditionalNull, ConditionalRow
from clustered import Cluster, ClusterPlan, ClusteredEvidenceGate
from independent_cluster_verifier import replay_clustered_decision
from provenance import Protocol, _digest
from witnessed import (
    Head, IntakeLog, CheckpointEndorsement, SignedHead,
    export_witnessed_certificate, unpack_protocol,
    verify_witnessed_certificate,
)

SCHEMA_V2 = 'ACE-witnessed-clustered-certificate-v2'
ACTION_SCHEMA = 'ACE-action-intent-v2'
POLICY_SCHEMA = 'ACE-clustered-authorization-policy-v2'


def _keys(d: object, fields: set[str]) -> bool:
    return isinstance(d, dict) and set(d) == fields


def _sha256_hex(s: object) -> bool:
    if type(s) is not str or len(s) != 64:
        return False
    try:
        return len(bytes.fromhex(s)) == 32
    except ValueError:
        return False


@dataclass(frozen=True)
class ActionIntent:
    challenge: str
    operation: str
    resource: str
    parameters: dict

    def __post_init__(self):
        if (type(self.challenge) is not str or len(self.challenge) < 16 or
            any(type(x) is not str or not x for x in (self.operation, self.resource)) or
            type(self.parameters) is not dict):
            raise ValueError('invalid structured action intent')
        # All keys must be string; json canonicalizer rejects NaN and objects.
        if any(type(key) is not str for key in self.parameters):
            raise ValueError('nonstring action parameter key')
        try:
            _digest(self.canonical())
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError('noncanonical action') from exc

    def canonical(self) -> dict:
        return {'schema': ACTION_SCHEMA, 'challenge': self.challenge,
                'operation': self.operation, 'resource': self.resource,
                'parameters': self.parameters}

    @property
    def commitment(self) -> str:
        return _digest(self.canonical())


def unpack_action(d: object) -> ActionIntent:
    if not _keys(d, {'schema','challenge','operation','resource','parameters'}) or d['schema'] != ACTION_SCHEMA:
        raise InvalidCertificate('unsupported action intent or fields')
    return ActionIntent(d['challenge'], d['operation'], d['resource'], d['parameters'])


@dataclass(frozen=True)
class AuthorizationPolicyV2:
    protocol_commitment: str
    witnessed_policy_commitment: str
    cluster_plan_commitment: str
    action_commitment: str

    def __post_init__(self):
        if not all(_sha256_hex(x) for x in (self.protocol_commitment,
              self.witnessed_policy_commitment,self.cluster_plan_commitment,
              self.action_commitment)):
            raise ValueError('incomplete authorization policy')

    def canonical(self) -> dict:
        return {'schema':POLICY_SCHEMA,
                'protocol_commitment':self.protocol_commitment,
                'witnessed_policy_commitment':self.witnessed_policy_commitment,
                'cluster_plan_commitment':self.cluster_plan_commitment,
                'action_commitment':self.action_commitment}

    @property
    def commitment(self) -> str:
        return _digest(self.canonical())


def unpack_policy_v2(d: object) -> AuthorizationPolicyV2:
    if not _keys(d, {'schema','protocol_commitment','witnessed_policy_commitment',
                      'cluster_plan_commitment','action_commitment'}) or d['schema'] != POLICY_SCHEMA:
        raise InvalidCertificate('unsupported v2 policy schema')
    return AuthorizationPolicyV2(d['protocol_commitment'],d['witnessed_policy_commitment'],
                                  d['cluster_plan_commitment'],d['action_commitment'])


def unpack_cluster_plan(d: object, protocol: Protocol) -> ClusterPlan:
    if not _keys(d, {'version','protocol_commitment','clusters', 'conditional_null',
                      'corruption_budget_clusters','alpha'}) or type(d['version']) is not int or d['version'] != 2:
        raise InvalidCertificate('unsupported cluster plan schema')
    if d['protocol_commitment'] != protocol.commitment:
        raise InvalidCertificate('cluster plan refers to different source roster')
    raw=d['clusters']
    if type(raw) is not list:
        raise InvalidCertificate('clusters must be a list')
    clusters=[]
    for x in raw:
        if not _keys(x, {'cluster_id','slot_ids'}) or type(x['slot_ids']) is not list or \
                any(type(s) is not str for s in x['slot_ids']):
            raise InvalidCertificate('malformed cluster')
        clusters.append(Cluster(x['cluster_id'],tuple(x['slot_ids'])))
    null=d['conditional_null']
    if not _keys(null,{'version','initial_state','rows'}) or \
            type(null['version']) is not int or null['version'] != 1 or type(null['rows']) is not list:
        raise InvalidCertificate('malformed conditional-null schema')
    rows=[]
    for x in null['rows']:
        if not _keys(x, {'state','low','high','bet_q','after_zero','after_one'}):
            raise InvalidCertificate('unexpected conditional row fields')
        rows.append(ConditionalRow(**x))
    model=ConditionalNull(null['initial_state'],tuple(rows))
    plan=ClusterPlan(protocol,tuple(clusters),model,
                     d['corruption_budget_clusters'], d['alpha'])
    if plan.canonical() != d or _digest(plan.canonical()) != _digest(d):
        raise InvalidCertificate('noncanonical cluster plan')
    return plan


def _claim(d) -> dict:
    if not math.isfinite(d.robust_max_log_e):
        raise InvalidCertificate('nonfinite robust evidence score')
    return {'authorized':d.authorized,
            'robust_max_log_e':d.robust_max_log_e,
            'admitted_clusters':d.admitted_clusters,
            'missing_clusters':d.missing_clusters,
            'conflicting_clusters':list(d.conflicting_clusters),
            'equivocated_slots':list(d.equivocated_slots),
            'cluster_bits':list(d.cluster_bits),
            'quarantined_reports':d.quarantined_reports}


def export_clustered_certificate(log: IntakeLog, signed_head: SignedHead,
                                  endorsements: list[CheckpointEndorsement],
                                  consistency: list[str], *, plan: ClusterPlan,
                                  action: ActionIntent,
                                  previous_head: Head | None = None) -> dict:
    if plan.protocol.commitment != log.protocol.commitment or \
            action.challenge != log.protocol.challenge:
        raise ValueError('action or statistical plan differs from witnessed roster')
    v1=export_witnessed_certificate(log,signed_head,endorsements,consistency,previous_head)
    gate=ClusteredEvidenceGate(plan,expected_plan_commitment=plan.commitment,
                               expected_protocol_commitment=log.protocol.commitment)
    for report in log.entries:
        gate.offer(report)
    decision=gate.decide()
    policy=AuthorizationPolicyV2(log.protocol.commitment,log.policy.commitment,
                                 plan.commitment,action.commitment)
    return {'schema':SCHEMA_V2,'witnessed_log_v1':v1,
            'cluster_plan':plan.canonical(),
            'action_intent':action.canonical(),
            'authorization_policy_v2':policy.canonical(),
            'authorization_policy_commitment':policy.commitment,
            'claimed_decision_v2':_claim(decision)}


@dataclass(frozen=True)
class VerifiedClusteredDecision:
    authorized: bool
    checkpoint_digest: str
    epoch: int
    log_entries: int
    admitted_clusters: int
    missing_clusters: int
    authorization_policy_commitment: str
    action_commitment: str
    robust_max_log_e: float


def verify_clustered_certificate(bundle: Mapping, *,
                                 expected_protocol: str,
                                 expected_policy: str,
                                 expected_cluster_plan: str,
                                 expected_v2_policy: str,
                                 expected_action: str,
                                 expected_challenge: str,
                                 expected_epoch: int,
                                 expected_previous_digest: str) -> VerifiedClusteredDecision:
    """Fail-closed independent clustered inference over a v1 witnessed log.

    The external parameters are independent trusted pins, *not* read from
    the untrusted certificate. A v1 certificate is always rejected as v2.
    """
    try:
        if not _keys(bundle, {'schema','witnessed_log_v1','cluster_plan',
                               'action_intent','authorization_policy_v2',
                               'authorization_policy_commitment','claimed_decision_v2'}) or \
               bundle['schema'] != SCHEMA_V2:
            raise InvalidCertificate('wrong certificate version or structure')
        if not all(_sha256_hex(x) for x in (expected_protocol,expected_policy,
                      expected_cluster_plan,expected_v2_policy,expected_action)):
            raise InvalidCertificate('all external policy and action pins are required')
        v1=bundle['witnessed_log_v1']
        # Legacy code verifies Ed25519 source signatures, log root, complete
        # evidence sequence, checkpoint and witness quorum, epoch, and chain.
        witnessed=verify_witnessed_certificate(v1,expected_protocol=expected_protocol,
              expected_policy=expected_policy,expected_challenge=expected_challenge,
              expected_epoch=expected_epoch,expected_previous_digest=expected_previous_digest)
        protocol=unpack_protocol(v1['protocol'])
        plan=unpack_cluster_plan(bundle['cluster_plan'],protocol)
        action=unpack_action(bundle['action_intent'])
        policy=unpack_policy_v2(bundle['authorization_policy_v2'])
        if (action.challenge != protocol.challenge or
            action.commitment != expected_action or
            plan.commitment != expected_cluster_plan or
            policy.protocol_commitment != protocol.commitment or
            policy.witnessed_policy_commitment != expected_policy or
            policy.cluster_plan_commitment != plan.commitment or
            policy.action_commitment != action.commitment or
            policy.commitment != expected_v2_policy or
            bundle['authorization_policy_commitment'] != policy.commitment):
            raise InvalidCertificate('v2 policy, cluster roster or action commitment mismatch')
        actual=replay_clustered_decision(v1['complete_log'],plan)
        claim=bundle['claimed_decision_v2']
        expected=_claim(actual)
        if not _keys(claim,set(expected)):
            raise InvalidCertificate('unknown or missing decision fields')
        for key,value in expected.items():
            observed=claim[key]
            if key == 'robust_max_log_e':
                if type(observed) not in (int,float) or not math.isfinite(observed) or \
                        not math.isclose(observed,value,rel_tol=1e-12,abs_tol=1e-12):
                    raise InvalidCertificate('statistical replay score differs from claim')
            elif key in ('authorized',):
                if type(observed) is not bool or observed != value:
                    raise InvalidCertificate('authorization differs from independent replay')
            elif key in ('admitted_clusters','missing_clusters','quarantined_reports'):
                if type(observed) is not int or observed != value:
                    raise InvalidCertificate('cluster count differs from replay')
            elif type(observed) is not list or observed != value:
                raise InvalidCertificate('cluster members or evidence flags differ')
        return VerifiedClusteredDecision(actual.authorized,witnessed.checkpoint_digest,
            witnessed.epoch,witnessed.log_entries,actual.admitted_clusters,
            actual.missing_clusters,policy.commitment,action.commitment,
            actual.robust_max_log_e)
    except (TypeError,ValueError,KeyError,OverflowError,AttributeError) as exc:
        if isinstance(exc,InvalidCertificate):
            raise
        raise InvalidCertificate(str(exc)) from exc
