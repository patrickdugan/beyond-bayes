"""Matched-information experiments: ACE, Bayes with provenance, credal Bayes.

All learners get identical deduplicated binary observations and the same
upper bound k on compromised roots. Bayes marginalizes a declared random
flip model (independent flips conditioned on <=k flips). Credal Bayes
maintains the posterior range over every <=k repair of the observations.
ACE keeps model candidates via adversarially robust anytime e-processes and
chooses by minimax regret. A targeted adversary violates Bayes' stipulated
random-corruption prior while respecting the public attack budget.

Mean costs and unsafe-action rates alone don't show epistemic superiority.
Different decision rules encode different preferences about uncertainty.
"""
from __future__ import annotations

from collections import defaultdict
from functools import lru_cache
from itertools import product
import csv
import json
import math
import random
from pathlib import Path
from typing import Sequence

from ace import ProvenanceLedger, Report
from robust import live_binary_models, exact_worst_case_false_exclusion

P_SAFE, P_RISK = .2, .8
LOSS_SAFE_LOCK = .25
LOSS_RISK_OPEN = 1.0


def _sigmoid(x: float) -> float:
    if x >= 0:
        ex = math.exp(-x)
        return 1 / (1 + ex)
    ex = math.exp(x)
    return ex / (1 + ex)


def posterior_given_clean_ones(ones: int, n: int) -> float:
    """Correct iid likelihood for *one specified* clean binary trace."""
    log_odds = (ones * math.log(P_RISK / P_SAFE)
                + (n - ones) * math.log((1 - P_RISK) / (1 - P_SAFE)))
    return _sigmoid(log_odds)


@lru_cache(maxsize=None)
def random_attack_bayes_posterior(ones: int, n: int, k: int, eps: float) -> float:
    """Exact Bayes for iid flip probability eps conditioned on <=k flips.

    The conditioning constant on the attack event is the same for both
    candidate states; it cancels when forming posterior odds. Summing over
    all flip subsets accounts for their dependence after conditioning.
    """
    if not (0 <= ones <= n and 0 <= k <= n and 0 <= eps < 1):
        raise ValueError("invalid inputs")
    logs = []
    for p in (P_SAFE, P_RISK):
        vals = []
        for j in range(k + 1):
            flip_weight = eps ** j * (1 - eps) ** (n - j)
            if flip_weight == 0:
                continue
            for u in range(max(0, j - (n - ones)), min(j, ones) + 1):
                v = j - u
                clean_ones = ones - u + v
                term = (math.comb(ones, u) * math.comb(n - ones, v)
                        * flip_weight * p ** clean_ones * (1 - p) ** (n - clean_ones))
                if term:
                    vals.append(math.log(term))
        if not vals:
            raise ValueError("all likelihood terms vanished")
        mx = max(vals)
        logs.append(mx + math.log(sum(math.exp(t - mx) for t in vals)))
    return _sigmoid(logs[1] - logs[0])


def targeted_attack_likelihood(observed: Sequence[int], truth: str, k: int) -> float:
    """Exact P(observed | truth, known first-k-target-bits flip policy).

    This comparator receives privileged knowledge of the attacker's exact
    strategy. It is an information-advantaged Bayes oracle, useful to show
    that Bayes can account for targeted corruption once modeled correctly.
    """
    if truth not in ('safe', 'risky') or not 0 <= k <= len(observed):
        raise ValueError('bad policy parameters')
    n = len(observed)
    p = P_RISK if truth == 'risky' else P_SAFE
    target_bit = 1 if truth == 'risky' else 0
    try:
        first_unchanged_target = observed.index(target_bit)
    except ValueError:
        # All target-valued bits were flipped: original contained <=k of them.
        return sum(math.comb(n, j) * (p**j * (1-p)**(n-j) if target_bit else
                    p**(n-j) * (1-p)**j) for j in range(k+1))
    if first_unchanged_target < k:
        return 0.0
    clean_ones = sum(observed) + (k if target_bit else -k)
    if not 0 <= clean_ones <= n:
        return 0.0
    return (math.comb(first_unchanged_target, k)
            * p**clean_ones * (1-p)**(n-clean_ones))


def targeted_policy_aware_bayes(observed: Sequence[int], k: int) -> float:
    """Posterior risk probability when the exact attacker policy is known."""
    safe = targeted_attack_likelihood(observed, 'safe', k)
    risky = targeted_attack_likelihood(observed, 'risky', k)
    if not safe + risky > 0:
        raise ValueError('impossible sample under both specified policies')
    return risky / (safe + risky)


@lru_cache(maxsize=None)
def credal_posterior_interval(ones: int, n: int, k: int) -> tuple[float, float]:
    """Posterior envelope over every possible clean sequence <=k flips away."""
    lo_ones = max(0, ones - k)
    hi_ones = min(n, ones + k)
    return posterior_given_clean_ones(lo_ones, n), posterior_given_clean_ones(hi_ones, n)


def expected_regret(action: str, risk_probability: float) -> float:
    expected_open = LOSS_RISK_OPEN * risk_probability
    expected_lock = LOSS_SAFE_LOCK * (1 - risk_probability)
    return ((expected_open - min(expected_open, expected_lock)) if action == 'open'
            else (expected_lock - min(expected_open, expected_lock)))


def bayes_action(risk_probability: float) -> str:
    return 'open' if LOSS_RISK_OPEN * risk_probability < LOSS_SAFE_LOCK * (1 - risk_probability) else 'lock'


def credal_action(bounds: tuple[float, float]) -> str:
    lo, hi = bounds
    worst_open = max(expected_regret('open', lo), expected_regret('open', hi))
    worst_lock = max(expected_regret('lock', lo), expected_regret('lock', hi))
    return 'open' if worst_open < worst_lock else 'lock'


def ace_action(live: tuple[str, ...]) -> str:
    if live == ('safe',):
        return 'open'
    return 'lock'


def loss(action: str, truth: str) -> float:
    return (LOSS_RISK_OPEN if truth == 'risky' else 0.0) if action == 'open' else (
        LOSS_SAFE_LOCK if truth == 'safe' else 0.0)


def sample_corruption(n: int, k: int, eps: float, rng: random.Random) -> set[int]:
    # Exact conditional Binomial corruption model, via rejection sampling.
    while True:
        indices = {i for i in range(n) if rng.random() < eps}
        if len(indices) <= k:
            return indices


def apply_attack(clean: Sequence[int], truth: str, method: str, k: int,
                 eps: float, rng: random.Random) -> list[int]:
    corrupted = list(clean)
    if method == 'clean':
        flipped = set()
    elif method == 'random':
        flipped = sample_corruption(len(clean), k, eps, rng)
    elif method == 'targeted':
        # Attacker knows theta, can see all readings, and changes at most k roots.
        # Under risky truth, fool defenders into opening; under safe truth,
        # trigger wasteful lockdown. Both are within the attack budget.
        goal_from = 1 if truth == 'risky' else 0
        candidates = [i for i, bit in enumerate(clean) if bit == goal_from]
        flipped = set(candidates[:k])
    else:
        raise ValueError(method)
    for index in flipped:
        corrupted[index] = 1 - corrupted[index]
    return corrupted


def dedup_with_verified_origins(bits: Sequence[int], copies: int) -> list[int]:
    ledger = ProvenanceLedger()
    for i, bit in enumerate(bits):
        # Exact LR for each root under the two simple models.
        lr = (P_RISK / P_SAFE) if bit == 1 else ((1 - P_RISK) / (1 - P_SAFE))
        for j in range(copies):
            ledger.add(Report(f'wire-{i}-{j}', f'verified-root-{i}', lr))
    roots = ledger.root_factors()
    assert len(roots) == len(bits)
    return [int(factor > 1.0) for factor in roots.values()]


def run_scenario(
    scenario: str, n: int, k: int, eps: float, trials_per_truth: int,
    copies: int = 4, seed: int = 42
) -> list[dict]:
    rng = random.Random(seed)
    rows = defaultdict(lambda: defaultdict(float))
    for truth, p in [('safe', P_SAFE), ('risky', P_RISK)]:
        for _ in range(trials_per_truth):
            clean = [int(rng.random() < p) for _ in range(n)]
            observed = dedup_with_verified_origins(
                apply_attack(clean, truth, scenario, k, eps, rng), copies)
            live, _ = live_binary_models(observed, k)
            observed_ones = sum(observed)
            post = random_attack_bayes_posterior(observed_ones, n, k, eps)
            credal_bounds = credal_posterior_interval(observed_ones, n, k)
            actions = {
                'Bayes-known-provenance': bayes_action(post),
                'Credal-Bayes': credal_action(credal_bounds),
                'ACE-v0.2': ace_action(live),
            }
            if scenario == 'targeted':
                oracle_post = targeted_policy_aware_bayes(observed, k)
                actions['Oracle-Bayes-known-policy'] = bayes_action(oracle_post)
            for method, action in actions.items():
                stats = rows[(truth, method)]
                stats['count'] += 1
                stats['cost'] += loss(action, truth)
                stats['unsafe_open'] += int(truth == 'risky' and action == 'open')
                stats['false_lock'] += int(truth == 'safe' and action == 'lock')
                if method == 'Bayes-known-provenance':
                    stats['brier'] += (post - (truth == 'risky')) ** 2
                elif method == 'Oracle-Bayes-known-policy':
                    stats['brier'] += (oracle_post - (truth == 'risky')) ** 2
                if method == 'ACE-v0.2':
                    stats['false_exclude'] += int(truth not in live)
                    stats['model_failure'] += int(len(live) == 0)
                    stats['ambiguous'] += int(len(live) == 2)
    out = []
    for (truth, method), stats in sorted(rows.items()):
        out.append({
            'scenario': scenario, 'n_roots': n, 'k_budget': k, 'truth': truth,
            'method': method, 'trials': int(stats['count']),
            'mean_loss': round(stats['cost'] / stats['count'], 6),
            'unsafe_open_rate': round(stats['unsafe_open'] / stats['count'], 6),
            'false_lock_rate': round(stats['false_lock'] / stats['count'], 6),
            'brier': round(stats['brier'] / stats['count'], 6) if method in ('Bayes-known-provenance', 'Oracle-Bayes-known-policy') else None,
            'ace_false_exclusion_rate': round(stats['false_exclude'] / stats['count'], 6) if method == 'ACE-v0.2' else None,
            'ace_ambiguity_rate': round(stats['ambiguous'] / stats['count'], 6) if method == 'ACE-v0.2' else None,
            'ace_model_failure_rate': round(stats['model_failure'] / stats['count'], 6) if method == 'ACE-v0.2' else None,
        })
    return out


def run_all(trials_per_truth: int = 1800, seed: int = 4126) -> list[dict]:
    scenarios = [
        ('clean', 24, 0, .0),
        ('random', 24, 2, .04),
        ('targeted', 24, 2, .04),
        ('targeted', 24, 4, .08),
        ('targeted', 12, 2, .08),
    ]
    all_rows = []
    for ix, (scenario, n, k, eps) in enumerate(scenarios):
        all_rows += run_scenario(scenario, n, k, eps, trials_per_truth, seed=seed + ix * 1009)
    return all_rows


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--trials-per-truth', type=int, default=1800)
    ap.add_argument('--seed', type=int, default=4126)
    ap.add_argument('--output', default='results')
    args = ap.parse_args()
    rows = run_all(args.trials_per_truth, args.seed)
    dest = Path(args.output)
    dest.mkdir(parents=True, exist_ok=True)
    with open(dest / 'adversarial_metrics.csv', 'w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, rows[0].keys()); writer.writeheader(); writer.writerows(rows)
    with open(dest / 'adversarial_metrics.json', 'w', encoding='utf-8') as fh:
        json.dump({'seed': args.seed, 'trials_per_truth': args.trials_per_truth,
                   'fixed_priors': {'safe': .5, 'risky': .5}, 'rows': rows}, fh, indent=2)
    print(f'{"scenario":>10} n  k  {"truth":>6}  {"method":>22}  {"loss":>6}  {"unsafe":>6}  {"false_lock":>10}  {"excl":>6}')
    for r in rows:
        print(f'{r["scenario"]:>10} {r["n_roots"]:2} {r["k_budget"]:2} '
              f'{r["truth"]:>6}  {r["method"]:>22}  {r["mean_loss"]:6.3f}  '
              f'{r["unsafe_open_rate"]:6.3f}  {r["false_lock_rate"]:10.3f}  '
              f'{r["ace_false_exclusion_rate"] if r["ace_false_exclusion_rate"] is not None else "-":>6}')
    print(f'\nSaved to: {dest.resolve()}')


if __name__ == '__main__':
    main()
