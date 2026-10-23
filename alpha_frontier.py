"""Precommitted alpha risk budgets for ACE binary action certificates.

If the risky model is the true iid Bernoulli null and at most k roots are
corrupted, opening only after its robust exclusion gives:
P(ever opening by ANY stopping time | risky) <= alpha.

Changing alpha after viewing evidence voids that precommitment argument.
"""
import csv
import json
import math
import random
from pathlib import Path

from adversarial_benchmark import (P_SAFE, P_RISK, apply_attack, loss,
                                   dedup_with_verified_origins)
from robust import live_binary_models


def wilson(count: int, n: int, z: float = 1.9599639845) -> tuple[float, float]:
    if not n:
        raise ValueError('empty sample')
    phat = count / n
    scale = 1 + z*z/n
    center = (phat + z*z/(2*n)) / scale
    spread = z * math.sqrt(phat*(1-phat)/n + z*z/(4*n*n)) / scale
    return max(0.0, center-spread), min(1.0, center+spread)


def run_frontier(
    n: int = 24, k: int = 4, trials_per_truth: int = 3500,
    eps: float = .08, seed: int = 5611,
    alphas: tuple[float, ...] = (.005, .01, .025, .05, .1, .2, .35)
) -> list[dict]:
    rng = random.Random(seed)
    totals = {a: {'unsafe': 0, 'false_lock': 0, 'wrong_excluded': 0, 'cost': 0.0}
              for a in alphas}
    for truth, p in [('safe', P_SAFE), ('risky', P_RISK)]:
        for _ in range(trials_per_truth):
            clean = [int(rng.random() < p) for _ in range(n)]
            observed = dedup_with_verified_origins(
                apply_attack(clean, truth, 'targeted', k, eps, rng), 3)
            _, tests = live_binary_models(observed, k)
            for alpha in alphas:
                max_log_threshold = math.log(1 / alpha)
                live = tuple(name for name, e in tests.items()
                             if e.max_log_e < max_log_threshold)
                action = 'open' if live == ('safe',) else 'lock'
                data = totals[alpha]
                data['unsafe'] += int(truth == 'risky' and action == 'open')
                data['false_lock'] += int(truth == 'safe' and action == 'lock')
                data['wrong_excluded'] += int(truth not in live)
                data['cost'] += loss(action, truth)
    rows = []
    for alpha in alphas:
        data = totals[alpha]
        unsafe_lo, unsafe_hi = wilson(data['unsafe'], trials_per_truth)
        lock_lo, lock_hi = wilson(data['false_lock'], trials_per_truth)
        rows.append(dict(
            n_roots=n, k_budget=k, precommitted_alpha=alpha,
            risky_trials=trials_per_truth, safe_trials=trials_per_truth,
            unsafe_open_rate=round(data['unsafe'] / trials_per_truth, 6),
            unsafe_ci95_low=round(unsafe_lo, 6), unsafe_ci95_high=round(unsafe_hi, 6),
            false_lock_rate=round(data['false_lock'] / trials_per_truth, 6),
            false_lock_ci95_low=round(lock_lo, 6), false_lock_ci95_high=round(lock_hi, 6),
            balanced_mean_loss=round(data['cost'] / (2 * trials_per_truth), 6),
            uniform_unsafe_bound=alpha,
        ))
    return rows


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', default='results')
    ap.add_argument('--trials-per-truth', type=int, default=3500)
    args = ap.parse_args()
    rows = run_frontier(trials_per_truth=args.trials_per_truth)
    outdir = Path(args.output); outdir.mkdir(parents=True, exist_ok=True)
    with (outdir / 'alpha_frontier.csv').open('w', newline='') as fh:
        writer = csv.DictWriter(fh, rows[0].keys()); writer.writeheader(); writer.writerows(rows)
    (outdir / 'alpha_frontier.json').write_text(json.dumps(rows, indent=2))
    for row in rows:
        print(f"alpha={row['precommitted_alpha']:.3f}, unsafe={row['unsafe_open_rate']:.3f}, "
              f"false_lock={row['false_lock_rate']:.3f}, "
              f"balanced_loss={row['balanced_mean_loss']:.3f}")
    print('Saved', outdir.resolve())


if __name__ == '__main__':
    main()
