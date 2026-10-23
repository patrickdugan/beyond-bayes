"""Sybil, selective-withholding and enrolled-key corruption experiments.

This is a unit test / counterexample bench for provenance-blind inference,
NOT a general Bayesian comparison. All protocols share p, q, alpha, and the
number of genuinely corruptible enrolled slots. The naive policy mistakes
attacker-invented root labels for genuinely enrolled experimental units and
silently drops censored units, violating the clean null's sampling assumptions.

Sources are FIXED synthetic keys; live deployments need externally witnessed
source enrollment, robust key management, integrity of the measurement process,
and independently justified distributional assumptions.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
import random
from typing import Sequence

from provenance import Protocol, SignedEvidenceLedger, SignedObservation, Receipt
from robust import robust_log_e_from_counts
from test_provenance import fixture, seed_key

NULL_P = .8
BET_Q = .2
ALPHA = .05


def naive_e_process_open(bits: Sequence[int], k: int, alpha: float = ALPHA) -> bool:
    """ID-blind e-process: treats all received (including invented) IDs as roots."""
    ones = zeros = 0
    for bit in bits:
        ones += bit
        zeros += 1 - bit
        if robust_log_e_from_counts(ones, zeros, 0, k, NULL_P, BET_Q) >= math.log(1 / alpha):
            return True
    return False


def attack_sample(clean: Sequence[int], truth: str, k: int, erasures: int,
                  forged: int) -> tuple[list[int | None], list[int]]:
    """Adversary with hindsight poisons up to k admitted keys and m slots.

    Extra roots are arbitrarily forged outside the roster. In the risky
    world, it fabricates negatives to encourage unsafe authorization. In the
    safe world, it fabricates positives to wastefully block authorization.
    """
    if truth not in ('safe', 'risky'):
        raise ValueError('invalid truth')
    target = 0 if truth == 'risky' else 1
    fake_value = target
    changed = list(clean)
    unwanted = 1 - target
    for i in [i for i, x in enumerate(changed) if x == unwanted][:erasures]:
        changed[i] = None
    eligible = [i for i, x in enumerate(changed) if x == unwanted]
    for i in eligible[:k]:
        changed[i] = target
    return changed, [fake_value] * forged


def run_source_attack_benchmark(trials_per_truth: int = 1800, seed: int = 4002):
    scenarios = [
        ('clean', 0, 0, 0),
        ('fabricated_roots', 0, 0, 16),
        ('selective_erasure', 0, 8, 0),
        ('forgery_and_erasure', 0, 8, 16),
        ('compromised_sources', 2, 4, 16),
    ]
    rng = random.Random(seed)
    rows = []
    for scenario, k, erasures, forged in scenarios:
        protocol, keys = fixture(n=24, k=k, alpha=ALPHA, null_p=NULL_P, bet_q=BET_Q)
        presigned = { (i, bit): SignedObservation.issue(protocol, protocol.slots[i].slot_id,
                                                       bit, keys[i])
                      for i in range(24) for bit in (0, 1)}
        fake_key = seed_key('forged-unregistered-reporter')
        for truth, p in [('safe', .2), ('risky', .8)]:
            fake_bit = 1 if truth == 'safe' else 0
            fake_reports = [SignedObservation.issue(protocol, f'invented-slot-{i}',
                                                     fake_bit, fake_key)
                            for i in range(forged)]
            metrics = {name: {'opens': 0, 'locks': 0} for name in ('ID-blind-e-process', 'ACE-v0.3-admission')}
            quarantined_totals = 0
            for _ in range(trials_per_truth):
                clean = [int(rng.random() < p) for _ in range(24)]
                observed, invented = attack_sample(clean, truth, k, erasures, forged)
                naive_stream = [b for b in observed if b is not None] + invented
                naive = naive_e_process_open(naive_stream, k)
                ledger = SignedEvidenceLedger(protocol, expected_commitment=protocol.commitment)
                for i, b in enumerate(observed):
                    if b is not None:
                        assert ledger.offer(presigned[i, b]) == Receipt.ACCEPTED
                for fake in fake_reports:
                    assert ledger.offer(fake) == Receipt.QUARANTINED
                admitted = ledger.decide()
                assert admitted.unauthorized_reports == forged
                assert admitted.missing_slots == sum(bit is None for bit in observed)
                quarantined_totals += admitted.unauthorized_reports
                for name, authorized in (('ID-blind-e-process', naive),
                                         ('ACE-v0.3-admission', admitted.authorized)):
                    metrics[name]['opens'] += int(authorized)
                    metrics[name]['locks'] += int(not authorized)
            for name, stat in metrics.items():
                rows.append({
                    'scenario': scenario, 'truth': truth, 'method': name,
                    'n_enrolled': 24, 'budget': k, 'max_erasures': erasures,
                    'forged_identities': forged, 'trials': trials_per_truth,
                    'unsafe_open_rate': round(stat['opens'] / trials_per_truth, 5) if truth == 'risky' else None,
                    'false_lock_rate': round(stat['locks'] / trials_per_truth, 5) if truth == 'safe' else None,
                    'allowed_actions': stat['opens'],
                    'quarantined_reports': quarantined_totals if name == 'ACE-v0.3-admission' else None,
                })
    return rows


def adversary_can_trigger(clean: Sequence[int], k: int,
                          p: float = NULL_P, q: float = BET_Q,
                          alpha: float = ALPHA) -> bool:
    """Reachable-state DP for a hindsight attacker and an anytime score.

    States are (spent flips, observed ones, observed zeros). Missing positions
    are implicit. Dynamic programming exhaustively covers the three possible
    actions on each clean bit: preserve, erase, flip. Duplicate paths merge.
    """
    threshold = math.log(1 / alpha)
    states = {(0, 0, 0)}
    for t, clean_bit in enumerate(clean, 1):
        following = set()
        for spent, ones, zeros in states:
            following.add((spent, ones, zeros))  # erasure
            following.add((spent, ones + clean_bit, zeros + 1 - clean_bit))
            if spent < k:
                following.add((spent + 1, ones + 1-clean_bit, zeros + clean_bit))
        for _, ones, zeros in following:
            missing = t - ones - zeros
            if robust_log_e_from_counts(ones, zeros, missing, k, p, q) >= threshold - 1e-12:
                return True
        states = following
    return False


def exact_adaptive_error_with_erasures(
    n: int, k: int, p: float = NULL_P, q: float = BET_Q,
    alpha: float = ALPHA,
) -> float:
    """Exact null risk against all erasure/flip attacks via reachable states.

    The attacker sees the entire clean trace and chooses any replacement
    trace with <=k flips and unlimited erasures. This checker enumerates
    all 2^n clean sequences and compresses adversarial outcomes by state.
    It is intended for small n, bounded to 12 here.
    """
    from itertools import product
    if not 0 <= n <= 12 or not 0 <= k <= n:
        raise ValueError('exhaustive oracle limited to n<=12')
    total = 0.
    for clean in product((0, 1), repeat=n):
        if adversary_can_trigger(clean, k, p, q, alpha):
            heads = sum(clean)
            total += p**heads * (1-p)**(n-heads)
    return total


def correlation_counterexample(n: int = 24, p_risky: float = NULL_P):
    """Perfect common-cause correlation makes false authorization =1-p.

    Conditional on one latent Z~Bernoulli(p), every purported observation is
    identically Z. Keys and source IDs may be distinct while randomness is
    shared. Under p=.8, q=.2, alpha=.05, three zeros cross the threshold.
    """
    assert n >= 3
    assert naive_e_process_open([0]*n, k=0)
    assert not naive_e_process_open([1]*n, k=0)
    return {'n_nominal_sources': n, 'one_latent_group': True,
            'risk_false_authorization_exact': 1-p_risky,
            'alpha': ALPHA,
            'reason': 'independence assumption violated: 24 signed IDs, one latent observation'}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--trials-per-truth', type=int, default=1800)
    ap.add_argument('--seed', type=int, default=4002)
    ap.add_argument('--output', default='results')
    args = ap.parse_args()
    rows = run_source_attack_benchmark(args.trials_per_truth, args.seed)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    with (output / 'source_attack_metrics.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    exact = {f'n{n}_k{k}': exact_adaptive_error_with_erasures(n,k)
             for n, k in ((6,0), (6,1), (8,1))}
    with (output / 'provenance_adversarial_results.json').open('w') as f:
        json.dump({'model': {'null_p': NULL_P, 'bet_q': BET_Q, 'alpha':ALPHA},
                   'seed':args.seed, 'trials_per_truth':args.trials_per_truth,
                   'scenarios':rows, 'exhaustive_null_error':exact,
                   'correlation_counterexample':correlation_counterexample()},f,indent=2)
    print(f'{"scenario":>22} {"truth":>6} {"policy":>24} {"unsafe":>8} {"false lock":>10}')
    for row in rows:
        print(f'{row["scenario"]:>22} {row["truth"]:>6} {row["method"]:>24} '
              f'{str(row["unsafe_open_rate"]):>8} {str(row["false_lock_rate"]):>10}')
    print('Exact worst-case false exclusion with adaptive erasures + flips: ', exact)
    print('Correlated-source exact counterexample: ', correlation_counterexample())


if __name__ == '__main__':
    main()
