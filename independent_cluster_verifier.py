"""Statistically independent Python replay of ACE v0.6 conditional decisions.

Shares only the declared data types and the previously verified source-signing
protocol. This code does not call ConditionalNull's scorer, dynamic-program
methods, ClusteredEvidenceGate or SignedEvidenceLedger.decide.

The v1 witnessed verifier must have checked all supplied signatures and
established the complete ordered log *before* this scorer is invoked.
"""
from __future__ import annotations
from dataclasses import dataclass
import math
from typing import Mapping

from certificates import InvalidCertificate
from clustered import ClusterPlan


@dataclass(frozen=True)
class ReplayedDecision:
    authorized: bool
    robust_max_log_e: float
    admitted_clusters: int
    missing_clusters: int
    conflicting_clusters: tuple[str,...]
    equivocated_slots: tuple[str,...]
    cluster_bits: tuple[int|None,...]
    quarantined_reports: int


def _independent_score(bits: tuple[int|None,...], plan: ClusterPlan) -> float:
    """Min-plus DP over (Markov state, number of altered present clusters)."""
    rows={r.state:r for r in plan.null.rows}
    active={(plan.null.initial_state,0):0.0}
    best=0.0
    for emitted in bits:
        future={}
        for (state,cost), score in active.items():
            row=rows[state]
            for underlying in (0,1):
                changes=cost+(emitted is not None and emitted != underlying)
                if changes>plan.corruption_budget_clusters:
                    continue
                # Independent derivation from the conditional e-bet formula.
                if row.bet_q>row.high:
                    baseline=row.high
                elif row.bet_q<row.low:
                    baseline=row.low
                else:
                    baseline=row.bet_q
                if underlying:
                    factor=math.log(row.bet_q)-math.log(baseline)
                else:
                    factor=math.log1p(-row.bet_q)-math.log1p(-baseline)
                successor=row.after_one if underlying else row.after_zero
                target=(successor,changes)
                amount=score+factor
                if amount < future.get(target,float('inf')):
                    future[target]=amount
        if not future:
            raise InvalidCertificate('empty reconstruction state set')
        active=future
        best=max(best,min(future.values()))
    return best


def replay_clustered_decision(reports: list[Mapping],plan:ClusterPlan) -> ReplayedDecision:
    """Replay fixed membership and conditional score from a signature-verified log."""
    slotnames={slot.slot_id for slot in plan.protocol.slots}
    claims={slot:set() for slot in slotnames}
    for r in reports:
        if type(r) is not dict or set(r)!={'experiment_id','protocol_commitment',
                                          'slot_id','bit','signature_hex'}:
            raise InvalidCertificate('malformed source claim in witnessed log')
        if r['slot_id'] not in claims or type(r['bit']) is not int or r['bit'] not in (0,1):
            raise InvalidCertificate('unexpected source in witnessed log')
        claims[r['slot_id']].add(r['bit'])
    bits=[];disagreements=[]
    for c in plan.clusters:
        responses=[next(iter(claims[s])) if len(claims[s])==1 else None
                   for s in c.slot_ids]
        nonmissing={x for x in responses if x is not None}
        if len(nonmissing)>1:
            disagreements.append(c.cluster_id)
        bits.append(next(iter(nonmissing)) if len(nonmissing)==1 and None not in responses
                    else None)
    equivocators=tuple(sorted(s for s,vals in claims.items() if len(vals)>1))
    bits=tuple(bits)
    score=_independent_score(bits,plan)
    if not math.isfinite(score):
        raise InvalidCertificate('nonfinite evidence score')
    permitted=(not disagreements and not equivocators and
               score>=math.log(1.0/plan.alpha))
    return ReplayedDecision(permitted,score, sum(x is not None for x in bits),
                            sum(x is None for x in bits),tuple(disagreements),
                            equivocators,bits,0)
