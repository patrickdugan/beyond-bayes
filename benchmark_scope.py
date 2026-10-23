"""Repeated child campaigns, parent alpha spending, and preallocation peeking.

The synthetic null uses genuine Uniform(0,1) p-values, so it isolates the
multiple-comparisons/predictability issue. It is not an AI-system guarantee.
"""
from __future__ import annotations
import argparse
import json
import random
from pathlib import Path


def simulate(trials: int = 100_000, children: int = 20, seed: int = 9209,
             root_alpha: float = 0.05) -> dict:
    if trials < 1 or children < 1 or children > 1000 or not 0 < root_alpha <= 1:
        raise ValueError('invalid benchmark configuration')
    rng = random.Random(seed)
    unscoped = 0; scoped = 0; leaked_before_reserve = 0
    for _ in range(trials):
        # Resets: each child obtains a NEW 5% family budget.
        unscoped += any(rng.random() < root_alpha for _ in range(children))
        # The root grants an exact fixed allocation to each of the children.
        scoped += any(rng.random() < root_alpha / children for _ in range(children))
        # An attacker sees potential current-attempt p-values BEFORE reserving.
        # Each potential p-value is marginally Uniform(0,1), yet conditional
        # validity fails after attacker-selected allocation.
        leaked_before_reserve += min(rng.random() for _ in range(children)) < root_alpha
    return {
        'trials': trials, 'children': children, 'root_alpha': root_alpha,
        'unscoped_theory': 1 - (1 - root_alpha)**children,
        'unscoped_observed': unscoped / trials,
        'root_spending_theory': 1 - (1 - root_alpha / children)**children,
        'root_spending_observed': scoped / trials,
        'peek_theory': 1 - (1 - root_alpha)**children,
        'peek_observed': leaked_before_reserve / trials,
        'interpretation': 'A pinned scope blocks budget resets. The conditional-null guarantee additionally requires allocation before data exposure.'
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--trials', type=int, default=100_000)
    p.add_argument('--seed', type=int, default=9209)
    p.add_argument('--output', type=Path)
    opts = p.parse_args()
    result = simulate(trials=opts.trials, seed=opts.seed)
    if opts.output:
        opts.output.parent.mkdir(parents=True, exist_ok=True)
        opts.output.write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    print(json.dumps(result, sort_keys=True, indent=2))

if __name__ == '__main__': main()
