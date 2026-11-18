"""BB-CQ-04 exact ECA-04 expected-risk and source-verified revision CPU preflight.

Finite synthetic issuer worlds. Original ECA-04 likelihood/priors are unchanged.
The provisional reports at selected slots are independent fair noise; the
authoritative final reports have the original conditional-iid sensor law.
Correction positions are selected without reading outcomes. An exact final
posterior is consequently well calibrated under the declared data process.

Only typed local archive verification is simulated. No real authentication,
confidentiality, acquisition integrity, probability guarantee or action
authorization is implemented.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from fractions import Fraction as Q
from hashlib import sha256
from itertools import product
from math import comb
import random
from typing import Sequence

from amendment_memory import (
    EvidenceArchive, apply_externally_verified_delta, verify_archive_delta,
)
from revocable_bayes import PRIORS, MATCH_PROBS, posterior_counts, posterior_full_replay

SCHEMA = "ace-bb-cq04-headroom-v1"
N = 12
ARMS = (1, 3, 6)
CALIBRATION_ROOTS = 64
PILOT_ROOTS = 256
CASE_PRIORS = (Q(1,8), Q(1,3), Q(1,2), Q(3,4), Q(7,8))
COST_FP = Q(2)
COST_FN = Q(1)
PRACTICAL_FLOOR = Q(2,100)
DOMAIN = "bb-cq04/v1/"
ORIGINAL_MODEL_SHA256 = "49bf2db1316942a23b91943843eb0398043c806cadd40421371af571aa15b3d8"


def _integer(value: int, low: int, high: int) -> None:
    if type(value) is not int or not low <= value <= high:
        raise ValueError("invalid integer parameter")


def binom_mass(n: int, x: int, p: Q) -> Q:
    if not 0 <= x <= n:
        return Q(0)
    return Q(comb(n, x)) * p ** x * (1 - p) ** (n - x)


@lru_cache(maxsize=None)
def coarse_posterior(old_m: int, new_q: int, j: int, n: int = N) -> tuple[Q, Q, Q]:
    """Bayes-optimal posterior given only (provisional count, new match count).

    Integrates unknown old match bits from replaced slots and all unobserved
    per-slot outcomes. This is stronger than a naive count correction.
    """
    _integer(n, 1, 12)
    _integer(j, 1, n)
    _integer(old_m, 0, n)
    _integer(new_q, 0, j)
    weights = []
    for prior, t in zip(PRIORS, MATCH_PROBS):
        total = Q(0)
        for u in range(n - j + 1):
            v = old_m - u
            total += binom_mass(n - j, u, t) * binom_mass(j, v, Q(1,2))
        total *= binom_mass(j, new_q, t)
        weights.append(prior * total)
    mass = sum(weights, Q(0))
    if mass == 0:
        raise ValueError("impossible aggregate evidence message")
    return tuple(w / mass for w in weights)


def _draw_regime(rng: random.Random) -> int:
    p = rng.random()
    return 0 if p < .45 else (1 if p < .80 else 2)


@dataclass(frozen=True)
class Root:
    id: str
    regime: int
    accepted: tuple[tuple[int, int], ...]
    replacement_order: tuple[int, ...]
    provisional: tuple[int, ...]  # full 12 report values, fair in selected 6 slots

    def frames(self, j: int) -> tuple[tuple[tuple[int,int],...], tuple[tuple[int,int],...], tuple[int,...]]:
        if j not in ARMS:
            raise ValueError("unregistered replacement size")
        chosen = self.replacement_order[:j]
        start = list(self.accepted)
        for i in chosen:
            start[i] = (start[i][0], self.provisional[i])
        return tuple(start), self.accepted, chosen


def make_root(role: str, index: int) -> Root:
    if role not in ("calibration", "pilot"):
        raise ValueError("unknown development cohort")
    limit = CALIBRATION_ROOTS if role == "calibration" else PILOT_ROOTS
    _integer(index, 0, limit-1)
    digest = sha256(f"{DOMAIN}{role}/{index}".encode()).digest()
    rng = random.Random(int.from_bytes(digest, "big"))
    regime = _draw_regime(rng)
    records = []
    for i in range(N):
        label = i % 2
        agrees = int(rng.random() < float(MATCH_PROBS[regime]))
        report = label if agrees else (1 - label)
        records.append((label, report))
    rng.shuffle(records)
    selected = tuple(rng.sample(range(N), max(ARMS)))
    provisional = [r for _,r in records]
    for slot in selected:
        provisional[slot] = rng.randrange(2)
    return Root(digest.hex(), regime, tuple(records), selected, tuple(provisional))


def verified_replacement(root: Root, j: int) -> dict:
    """Simulated caller first validates every full archive successor.

    The lightweight count-only procedure consumes its DELTAs only after that
    full verification. The final exact Bayes posterior is independently replayed.
    """
    before, after, chosen = root.frames(j)
    old_matches = tuple(int(label == report) for label,report in before)
    archive = EvidenceArchive(old_matches, (0,) * N)
    count = archive.count
    pin = archive.digest
    for pos in chosen:
        new_match = int(after[pos][0] == after[pos][1])
        next_archive, delta = archive.change(pos, new_match)
        if not verify_archive_delta(archive, next_archive, delta):
            raise AssertionError("external archive validation failure")
        count, next_pin = apply_externally_verified_delta(count, delta, pin, N)
        if next_pin != next_archive.digest or count != next_archive.count:
            raise AssertionError("verified count/archival mismatch")
        archive, pin = next_archive, next_pin
    actual = sum(int(a == b) for a,b in after)
    if archive.count != count or count != actual:
        raise AssertionError("final corrected match count mismatch")
    fine = posterior_full_replay(after)
    if fine != posterior_counts(actual, N):
        raise AssertionError("independent historical Bayes replay mismatch")
    old_count = sum(old_matches)
    new_q = sum(int(after[i][0] == after[i][1]) for i in chosen)
    coarse = coarse_posterior(old_count, new_q, j)
    return {
        "old_match_count": old_count,
        "new_amended_match_count": new_q,
        "fine_posterior": fine,
        "delta_posterior": posterior_counts(count, N),
        "coarse_posterior": coarse,
        "changed_report_bits": sum(before[i][1] != after[i][1] for i in chosen),
        "archive_digest": archive.digest,
    }


def _mixture(probs: Sequence[float | Q]) -> tuple[float | Q, float | Q]:
    if len(probs) != 3 or any(p < 0 for p in probs):
        raise ValueError("expected a nonnegative three-regime distribution")
    total = sum(probs)
    if not total:
        raise ValueError("zero posterior mass")
    return (
        sum((p * t for p,t in zip(probs,MATCH_PROBS))) / total,
        sum((p * (1-t) for p,t in zip(probs,MATCH_PROBS))) / total,
    )


def policy_action(probs: Sequence[float | Q], case_prior: Q, report: int) -> bool:
    """Bayes grant/deny based on an audit yes/no and supplied regime belief."""
    _integer(report, 0, 1)
    t, f = _mixture(probs)
    grant_loss = COST_FP * (1-case_prior) * (f if report else 1-f)
    deny_loss = COST_FN * case_prior * (t if report else 1-t)
    return deny_loss > grant_loss


def expected_authorization_cost(probs: Sequence[float | Q], regime: int) -> Q:
    """Root-level expectation of 2FP+FN over future independent cases/reports.

    Scored under host-held true regime; individual future case draws and
    audit outcomes do not create extra independent evaluation roots.
    """
    _integer(regime, 0, 2)
    t = MATCH_PROBS[regime]
    f = 1-t
    total = Q(0)
    for p in CASE_PRIORS:
        for report in (0,1):
            allow = policy_action(probs,p,report)
            loss = (COST_FP*(1-p)*(f if report else 1-f) if allow else
                    COST_FN*p*(t if report else 1-t))
            total += loss
    return total / len(CASE_PRIORS)


def brier(probs: Sequence[float | Q], regime: int) -> float:
    return sum((float(v) - int(k==regime))**2 for k,v in enumerate(probs))


def _onehot(regime: int) -> tuple[Q,Q,Q]:
    return tuple(Q(int(regime == i)) for i in range(3))


@lru_cache(maxsize=None)
def exact_population(j: int) -> dict:
    """Independent source-only exact expected risk, full ECA-04 mixture law.

    Integration is over latent regime, valid unchanged reports, fair provisional
    report bits and valid fresh replacement reports; every quantity is Q.
    """
    if j not in ARMS:
        raise ValueError("unregistered correction number")
    sums = {arm: Q(0) for arm in ("fine","coarse","pooled","true_regime")}
    brier_sums = {arm: Q(0) for arm in sums}
    squared_gap = Q(0)
    disagree = Q(0)
    mass = Q(0)
    for k, prior in enumerate(PRIORS):
        t = MATCH_PROBS[k]
        for u in range(N-j+1):
            valid_mass = binom_mass(N-j,u,t)
            for v in range(j+1):
                provisional_mass = binom_mass(j,v,Q(1,2))
                m_old = u+v
                for q in range(j+1):
                    p = prior * valid_mass * provisional_mass * binom_mass(j,q,t)
                    if not p:
                        continue
                    mass += p
                    fine = posterior_counts(u+q,N)
                    coarse = coarse_posterior(m_old,q,j)
                    policies = {
                        "fine":fine,"coarse":coarse,"pooled":PRIORS,
                        "true_regime":_onehot(k),
                    }
                    for arm, probs in policies.items():
                        sums[arm] += p * expected_authorization_cost(probs,k)
                        brier_sums[arm] += p * sum(
                            ((v-int(i==k))**2 for i,v in enumerate(probs)), Q(0))
                    squared_gap += p * sum(((a-b)**2 for a,b in zip(fine,coarse)),Q(0))
                    # Fraction of the ten future decisions that differ.
                    n_diff = sum(policy_action(fine,cp,r) != policy_action(coarse,cp,r)
                                 for cp in CASE_PRIORS for r in (0,1))
                    disagree += p * Q(n_diff,2*len(CASE_PRIORS))
    if mass != 1:
        raise AssertionError("the original likelihood mixture failed normalization")
    if sums["fine"] > sums["coarse"] or sums["coarse"] > sums["pooled"]:
        # The two inequalities hold at population level under the chosen
        # information ordering; a violation is a statistical-contract bug.
        raise AssertionError("population Bayes information monotonicity failed")
    if brier_sums["fine"] > brier_sums["coarse"]:
        raise AssertionError("proper scoring information monotonicity failed")
    return {
        "j":j,"total_probability":mass,
        "risk":sums,"regime_brier":brier_sums,
        "coarse_minus_fine_cost":sums["coarse"]-sums["fine"],
        "pooled_minus_fine_cost":sums["pooled"]-sums["fine"],
        "squared_l2_fine_coarse":squared_gap,
        "decision_disagreement_fraction":disagree,
        "headroom_gate":("PASS" if sums["coarse"]-sums["fine"] >= PRACTICAL_FLOOR
                         else "HEADROOM_BLOCKED"),
    }


def qstr(value: Q) -> str:
    return f"{value.numerator}/{value.denominator}"


def source_only_receipt() -> dict:
    """Source-only exact preflight; independent of model-weight retrieval."""
    expected = {str(j):exact_population(j) for j in ARMS}
    examples = {}
    for j in ARMS:
        roots = [make_root("calibration",i) for i in range(8)]
        proofs = [verified_replacement(root,j) for root in roots]
        examples[str(j)] = {
            "audited_roots":len(proofs),
            "total_changed_provisional_bits":sum(x["changed_report_bits"] for x in proofs),
            "independent_full_vs_delta_parity":all(
                x["fine_posterior"] == x["delta_posterior"] for x in proofs),
        }
    return {
        "schema":SCHEMA,
        "status":"SOURCE_ONLY_EXACT_PREFLIGHT",
        "authorizes_action":False,
        "original_eca04_model_sha256":ORIGINAL_MODEL_SHA256,
        "n_sentinels":N,
        "j_arms":list(ARMS),
        "practical_headroom_floor":str(PRACTICAL_FLOOR),
        "analysis":{j:{
            "population_cost":{k:format(float(v),".12f") for k,v in item["risk"].items()},
            "population_regime_brier":{k:format(float(v),".12f") for k,v in item["regime_brier"].items()},
            "coarse_minus_fine_cost":format(float(item["coarse_minus_fine_cost"]),".12f"),
            "pooled_minus_fine_cost":format(float(item["pooled_minus_fine_cost"]),".12f"),
            "squared_l2_fine_coarse":format(float(item["squared_l2_fine_coarse"]),".12f"),
            "action_disagreement_rate":format(float(item["decision_disagreement_fraction"]),".12f"),
            "headroom_gate":item["headroom_gate"],
        } for j,item in expected.items()},
        "source_only_archive_fixtures":examples,
        "native_weights_loaded":False,
        "scientific_confirmation_roots":0,
    }
