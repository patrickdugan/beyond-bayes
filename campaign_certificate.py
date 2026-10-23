"""ACE v0.8: externally pinned, independently replayed campaign authorization.

A signed reservation irrevocably spends alpha, a signed finalization binds one
complete v2 certificate, and a signed consumption certificate can be obtained
only once at the current quorum head. The quorum's own history is the monotonic
anchor, including after the relying party loses its local state.

The error guarantee requires *conditional* test soundness given earlier attempts
and predictable selection of alpha before any new data. Cryptography cannot
establish this statistical premise, or prove that reports were unseen at issue.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import math

from certificates import InvalidCertificate
from provenance import _digest
from clustered_certificate import verify_clustered_certificate, VerifiedClusteredDecision
from campaign import (CampaignPolicy, CampaignQuorum, CampaignCertificate,
                      CampaignError, CampaignView, SCALE, unpack_certificate,
                      verify_certificate, GENESIS_DIGEST)

SCHEMA='ACE-campaign-authorization-v1'
CONTEXT_SCHEMA='ACE-campaign-context-v1'


def campaign_context(policy:CampaignPolicy, *,previous_digest:str,sequence:int,
                     alpha_units:int,spent_units:int) -> dict:
    """Commit the exact campaign accounting into v2 ActionIntent.parameters."""
    return {'schema':CONTEXT_SCHEMA,'campaign_commitment':policy.commitment,
            'total_units':policy.total_units,'alpha_units':alpha_units,
            'spent_units':spent_units,'reservation_sequence':sequence,
            'previous_digest':previous_digest}


def export_attempt(reservation:CampaignCertificate,
                   finalization:CampaignCertificate,
                   v2_certificate:dict) -> dict:
    return {'schema':SCHEMA,'reservation':reservation.canonical(),
            'finalization':finalization.canonical(),'v2_certificate':v2_certificate}


@dataclass(frozen=True)
class VerifiedAttempt:
    authorized: bool
    campaign_commitment: str
    reservation_digest: str
    finalization_digest: str
    challenge: str
    risk_units: int
    spent_units: int
    action_commitment: str
    v2_decision: VerifiedClusteredDecision


def verify_attempt(bundle:dict, *,policy:CampaignPolicy,
                   expected_reservation_digest:str,
                   expected_finalization_digest:str,
                   expected_previous_digest:str,
                   expected_previous_spent_units:int,
                   expected_v2_epoch:int,
                   expected_v2_previous_digest:str) -> VerifiedAttempt:
    """Offline verifier: all expected values must come from *outside* bundle.

    Provenance of expected_previous_digest/spent is either a trusted monotonic
    campaign anchor or a pinned genesis checkpoint. A bare certificate alone
    cannot establish it is the live tip or unused by an action executor.
    """
    try:
        if type(bundle) is not dict or set(bundle)!={'schema','reservation','finalization','v2_certificate'} or bundle['schema']!=SCHEMA:
            raise InvalidCertificate('invalid campaign wrapper version')
        r=unpack_certificate(bundle['reservation'])
        f=unpack_certificate(bundle['finalization'])
        if not verify_certificate(r,policy) or not verify_certificate(f,policy):
            raise InvalidCertificate('invalid campaign quorum certificate')
        a=r.record; b=f.record
        if (a.kind!='reserve' or b.kind!='finalize' or
            a.digest!=expected_reservation_digest or b.digest!=expected_finalization_digest or
            a.previous_digest!=expected_previous_digest or
            b.previous_digest!=a.digest or b.sequence!=a.sequence+1 or
            a.payload['spent_units']!=expected_previous_spent_units+a.payload['alpha_units'] or
            a.payload['spent_units']>policy.total_units or
            b.payload['reservation_digest']!=a.digest or
            b.payload['certificate_digest']!=_digest(bundle['v2_certificate'])):
            raise InvalidCertificate('campaign anchor, sequence or certificate digest mismatch')
        v2=bundle['v2_certificate']
        result=verify_clustered_certificate(v2,
            expected_protocol=a.payload['protocol'],
            expected_policy=a.payload['witness_policy'],
            expected_cluster_plan=a.payload['cluster_plan'],
            expected_v2_policy=a.payload['v2_policy'],
            expected_action=a.payload['action'],
            expected_challenge=a.payload['challenge'],
            expected_epoch=expected_v2_epoch,
            expected_previous_digest=expected_v2_previous_digest)
        action=v2['action_intent']
        context=campaign_context(policy,previous_digest=a.previous_digest,
              sequence=a.sequence,alpha_units=a.payload['alpha_units'],
              spent_units=a.payload['spent_units'])
        if (type(action) is not dict or type(action.get('parameters')) is not dict or
            action['parameters'].get('ace_campaign')!=context):
            raise InvalidCertificate('v2 action is missing the exact campaign budget binding')
        plan=v2['cluster_plan']
        alpha=plan['alpha']
        if (type(alpha) not in (float,int) or not math.isfinite(alpha) or
            alpha!=a.payload['alpha_units']/SCALE or
            type(b.payload['authorized']) is not bool or
            b.payload['authorized']!=result.authorized):
            raise InvalidCertificate('the reserved alpha or replayed authorization differs')
        return VerifiedAttempt(result.authorized,policy.commitment,a.digest,b.digest,
                               a.payload['challenge'],a.payload['alpha_units'],
                               a.payload['spent_units'],a.payload['action'],result)
    except (CampaignError,ValueError,TypeError,KeyError,OverflowError,AttributeError) as exc:
        if isinstance(exc,InvalidCertificate):
            raise
        raise InvalidCertificate(str(exc)) from exc


@dataclass(frozen=True)
class GateDecision:
    authorized: bool
    challenge: str
    campaign_commitment: str
    total_spent_units: int
    risk_units: int
    consumption_certificate: CampaignCertificate | None


class CampaignActionGate:
    """Checks the live quorum history and consumes authorized actions once.

    The gate validates the exact finalization at the currently certified tip;
    the quorum persists the consumption *before* returning permission. A crash
    between consume and external actuation loses the action conservatively.
    """
    def __init__(self, quorum:CampaignQuorum):
        self.quorum=quorum

    def check_and_consume(self, bundle:dict, *,expected_v2_epoch:int,
                          expected_v2_previous_digest:str) -> GateDecision:
        view=self.quorum.current()
        if (view.sequence < 2 or view.state.stage not in ('authorized','denied') or
            len(view.history)<2):
            raise CampaignError('no current finalized, unconsumed decision')
        r=view.history[-2];f=view.history[-1]
        if r.record.kind!='reserve' or f.record.kind!='finalize':
            raise CampaignError('incomplete campaign attempt')
        prior=view.history[-3].record if len(view.history)>2 else None
        old_spent=sum(x.record.payload['alpha_units'] for x in view.history[:-2]
                      if x.record.kind=='reserve')
        verified=verify_attempt(bundle,policy=self.quorum.policy,
            expected_reservation_digest=r.record.digest,
            expected_finalization_digest=f.record.digest,
            expected_previous_digest=prior.digest if prior else GENESIS_DIGEST,
            expected_previous_spent_units=old_spent,
            expected_v2_epoch=expected_v2_epoch,
            expected_v2_previous_digest=expected_v2_previous_digest)
        consumed=self.quorum.consume(f) if verified.authorized else None
        return GateDecision(verified.authorized,verified.challenge,
                            verified.campaign_commitment,verified.spent_units,
                            verified.risk_units,consumed)
