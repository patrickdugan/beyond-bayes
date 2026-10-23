"""ACE v0.6: signed sample slots folded into precommitted statistical clusters.

An Ed25519 signature attests to the source key, never the claimed physical
independence of the signed reading. The externally pinned ClusterPlan assigns
ALL enrolled slots to fixed, ordered clusters. Each cluster contributes zero
or one clean-data sampling unit. Incomplete or disagreeing clusters become
explicit erasures; valid contradictions fail closed.

A ClusterPlan is versioned separately from the v0.5 signing Protocol.
The legacy v0.5 witness-certificate verifier cannot verify an ACE v0.6
clustered decision; integration must use a new certificate policy commitment.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Optional

from conditional import ConditionalNull, anytime_robust_max_log_e
from provenance import Protocol, Receipt, SignedEvidenceLedger, SignedObservation


@dataclass(frozen=True)
class Cluster:
    cluster_id: str
    slot_ids: tuple[str, ...]

    def canonical(self) -> dict:
        return {'cluster_id': self.cluster_id, 'slot_ids': list(self.slot_ids)}


@dataclass(frozen=True)
class ClusterPlan:
    protocol: Protocol
    clusters: tuple[Cluster, ...]
    null: ConditionalNull
    corruption_budget_clusters: int
    alpha: float = .05

    def __post_init__(self) -> None:
        if not self.clusters:
            raise ValueError('cluster plan requires at least one cluster')
        names = [c.cluster_id for c in self.clusters]
        if len(names) != len(set(names)) or any(not name for name in names):
            raise ValueError('cluster IDs must be nonempty and unique')
        names_of_slots = [s for c in self.clusters for s in c.slot_ids]
        if any(not c.slot_ids or not all(c.slot_ids) for c in self.clusters):
            raise ValueError('each cluster must contain enrolled slots')
        enrolled = {s.slot_id for s in self.protocol.slots}
        if len(names_of_slots) != len(set(names_of_slots)) or set(names_of_slots) != enrolled:
            raise ValueError('clusters must form a disjoint exact cover of signed roster')
        if type(self.corruption_budget_clusters) is not int or not (0 <= self.corruption_budget_clusters <= len(self.clusters)):
            raise ValueError('invalid compromised-cluster budget')
        if type(self.alpha) not in (int, float) or not math.isfinite(self.alpha) or not 0 < self.alpha < 1:
            raise ValueError('invalid alpha')

    def canonical(self) -> dict:
        return {'version': 2, 'protocol_commitment': self.protocol.commitment,
                'clusters': [c.canonical() for c in self.clusters],
                'conditional_null': self.null.canonical(),
                'corruption_budget_clusters': self.corruption_budget_clusters,
                'alpha': self.alpha}

    @property
    def commitment(self) -> str:
        raw = json.dumps(self.canonical(), sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
        return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ClusterDecision:
    authorized: bool
    plan_commitment: str
    protocol_commitment: str
    robust_max_log_e: float
    alpha: float
    admitted_clusters: int
    missing_clusters: int
    conflicting_clusters: tuple[str, ...]
    equivocated_slots: tuple[str, ...]
    quarantined_reports: int
    cluster_bits: tuple[Optional[int], ...]


class ClusteredEvidenceGate:
    def __init__(self, plan: ClusterPlan, *, expected_plan_commitment: str,
                 expected_protocol_commitment: str):
        if not expected_plan_commitment or expected_plan_commitment != plan.commitment:
            raise ValueError('externally pinned cluster-plan commitment required')
        self.plan = plan
        self.ledger = SignedEvidenceLedger(plan.protocol,
                                           expected_commitment=expected_protocol_commitment)
        self._position = {slot.slot_id: i for i, slot in enumerate(plan.protocol.slots)}

    def offer(self, report: SignedObservation) -> Receipt:
        return self.ledger.offer(report)

    def _cluster_evidence(self) -> tuple[tuple[Optional[int], ...], tuple[str, ...]]:
        observed = self.ledger.observed
        cluster_bits: list[Optional[int]] = []
        conflicts: list[str] = []
        for cluster in self.plan.clusters:
            bits = [observed[self._position[s]] for s in cluster.slot_ids]
            nonmissing = {b for b in bits if b is not None}
            if len(nonmissing) > 1:
                cluster_bits.append(None)
                conflicts.append(cluster.cluster_id)
            elif None in bits:
                cluster_bits.append(None)
            else:
                cluster_bits.append(bits[0])
        return tuple(cluster_bits), tuple(conflicts)

    def decide(self) -> ClusterDecision:
        bits, conflicts = self._cluster_evidence()
        log_e = anytime_robust_max_log_e(bits,
                                         self.plan.corruption_budget_clusters,
                                         self.plan.null)
        # Actual equivocations in the raw signed evidence and discordant
        # members across a cluster are hard evidence-integrity failures.
        authorized = (not conflicts and not self.ledger.equivocations
                      and log_e >= math.log(1 / self.plan.alpha))
        return ClusterDecision(authorized, self.plan.commitment,
                               self.plan.protocol.commitment, log_e,
                               self.plan.alpha, sum(x is not None for x in bits),
                               sum(x is None for x in bits), conflicts,
                               self.ledger.equivocations,
                               len(self.ledger.quarantines), bits)
