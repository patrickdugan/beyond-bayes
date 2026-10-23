"""Exact finite-horizon source attack rates by probability-preserving DP.

Every possible iid clean sample is included, and source/censorship behavior
matches source_attack_benchmark.attack_sample: first m unwanted bits withheld,
next k unwanted bits flipped, then f invented identities appended to naive
stream. The two policies observe the same authentic received records, while
only the ID-blind implementation counts invented sources and silently drops
missing scheduled readings. No sampling error, no cryptographic simulation.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import csv
import json
import math
from pathlib import Path

from robust import robust_log_e_from_counts

NULL_P = .8
BET_Q = .2
ALPHA = .05

CASES = [
    ('clean', 0, 0, 0),
    ('fabricated_roots', 0, 0, 16),
    ('selective_erasure', 0, 8, 0),
    ('forgery_and_erasure', 0, 8, 16),
    ('compromised_sources', 2, 4, 16),
]


def exact_policy_rates(truth: str, *, n: int = 24, k: int = 0,
                       erasures: int = 0, forged: int = 0,
                       alpha: float = ALPHA) -> tuple[float, float]:
    """Returns (P(naive ever authorizes), P(ACE ever authorizes)).

    State (e, f, ones, zeros, naive_crossed, ace_crossed) is sufficient:
    erasures are n_processed - ones - zeros; the adversary takes actions
    online on first unwanted bits, which is equivalent to its hindsight
    scan for this policy. Cumulative Bernoulli probabilities are merged for
    identical states with no approximation.
    """
    if truth not in ('safe', 'risky') or any(x < 0 for x in (n,k,erasures,forged)):
        raise ValueError('invalid scenario')
    if not 0 < alpha < 1:
        raise ValueError('invalid alpha')
    p = .2 if truth == 'safe' else .8
    target = 1 if truth == 'safe' else 0
    unwanted = 1 - target
    threshold = math.log(1 / alpha)
    states = {(0, 0, 0, 0, False, False): 1.0}
    for t in range(1, n + 1):
        following = defaultdict(float)
        for (e, f, ones, zeros, naive_crossed, ace_crossed), mass in states.items():
            for clean_bit, chance in ((0, 1-p), (1,p)):
                new_e, new_f = e, f
                if clean_bit == unwanted and e < erasures:
                    observed = None
                    new_e += 1
                elif clean_bit == unwanted and f < k:
                    observed = target
                    new_f += 1
                else:
                    observed = clean_bit
                new_ones = ones + int(observed == 1)
                new_zeros = zeros + int(observed == 0)
                new_misses = t - new_ones - new_zeros
                # Naive e-process advances only when an observation is delivered.
                naive_cross = naive_crossed
                if observed is not None:
                    naive_cross = naive_cross or robust_log_e_from_counts(
                        new_ones, new_zeros, 0, k, NULL_P, BET_Q) >= threshold
                # ACE scores all precommitted slots; missing contributes erasure.
                ace_cross = ace_crossed or robust_log_e_from_counts(
                    new_ones, new_zeros, new_misses, k, NULL_P, BET_Q) >= threshold
                following[(new_e, new_f, new_ones, new_zeros, naive_cross, ace_cross)] += mass * chance
        states = following
    naive_rate = ace_rate = 0.0
    for (_, _, ones, zeros, naive, ace), mass in states.items():
        forgeries = forged
        if not naive:
            # Final prefix has largest forged exposure for the favorable sign;
            # nonetheless checking each prefix is inexpensive and exact.
            for j in range(1, forged+1):
                a = ones + (j if target == 1 else 0)
                b = zeros + (j if target == 0 else 0)
                if robust_log_e_from_counts(a,b,0,k,NULL_P,BET_Q) >= threshold:
                    naive = True
                    break
        naive_rate += mass * naive
        ace_rate += mass * ace
    return naive_rate, ace_rate


def all_exact_rows(n: int = 24, alpha: float = ALPHA) -> list[dict]:
    rows=[]
    for scenario, k, erasures, forged in CASES:
        for truth in ('safe','risky'):
            naive, ace = exact_policy_rates(truth, n=n, k=k, erasures=erasures,
                                             forged=forged, alpha=alpha)
            for method, rate in (('ID-blind-e-process',naive),('ACE-v0.3-admission',ace)):
                rows.append({'scenario':scenario,'truth':truth,'method':method,
                             'n_enrolled':n, 'corruption_budget':k,
                             'selective_erasures':erasures, 'forged_identities':forged,
                             'unsafe_open_rate':round(rate,9) if truth=='risky' else None,
                             'false_lock_rate':round(1-rate,9) if truth=='safe' else None,
                             'calculation':'exact dynamic program'})
    return rows


def main() -> None:
    ap=argparse.ArgumentParser()
    ap.add_argument('--n',type=int,default=24)
    ap.add_argument('--output',default='results')
    args=ap.parse_args()
    rows=all_exact_rows(args.n)
    dest=Path(args.output)
    dest.mkdir(exist_ok=True,parents=True)
    with (dest/'source_attack_exact.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,rows[0].keys());w.writeheader();w.writerows(rows)
    with (dest/'source_attack_exact.json').open('w') as f:
        json.dump({'source':'exact iid finite-horizon DP','rows':rows},f,indent=2)
    for r in rows:
        print(f'{r["scenario"]:>22} {r["truth"]:>6} {r["method"]:>22} '
              f'unsafe={r["unsafe_open_rate"]} false_lock={r["false_lock_rate"]}')


if __name__=='__main__':
    main()
