"""Deterministic and Monte Carlo campaign risk comparisons (no cryptographic claims).

A false opening in each synthetic, independently calibrated null has exactly
probability alpha_i. Campaign alpha spend is fixed before each attempt; stopping
after the first opening is an adaptive strategy. The shared-latent
counterexample deliberately breaks the conditional-null premise.
"""
from __future__ import annotations
import argparse
import json
import math
import random
from pathlib import Path


def exact_any_error(allocations: list[float]) -> float:
    if any(not (0 <= x <= 1) for x in allocations):
        raise ValueError('invalid per-trial rate')
    return 1-math.prod(1-x for x in allocations)


def simulate(n:int=100_000,attempts:int=20,seed:int=8208,alpha_campaign:float=.05):
    rng=random.Random(seed)
    independent_naive=0
    spent_controlled=0
    adaptive=0
    for _ in range(n):
        # Attacker repeats a nominal 5% test as many as twenty times.
        independent_naive+=any(rng.random()<.05 for _ in range(attempts))
        # Fixed alpha spending allocated across exactly twenty attempts.
        spent_controlled+=any(rng.random()<alpha_campaign/attempts for _ in range(attempts))
        # Predictable geometric allocations: attempt count and previous denials
        # determine when the process stops. Total spend is bounded on every path.
        used=0.0
        for i in range(attempts):
            allocation=min(alpha_campaign-used, alpha_campaign/(2**(i+1)))
            if allocation<=0:break
            used+=allocation
            if rng.random()<allocation:
                adaptive+=1
                break
    result={
      'trials':n,'attempts':attempts,'campaign_alpha':alpha_campaign,
      'naive_theoretical':exact_any_error([.05]*attempts),
      'naive_simulated':independent_naive/n,
      'fixed_spending_theoretical':exact_any_error([alpha_campaign/attempts]*attempts),
      'fixed_spending_simulated':spent_controlled/n,
      'adaptive_geometric_spending_simulated':adaptive/n,
      'geometric_total_spend':alpha_campaign*(1-2**(-attempts)),
      'common_cause_bad_null_example':.2,
      'common_cause_note': '20% false-opening counterexample violates the conditional per-attempt alpha premise, so the ledger alone provides no guarantee.'
    }
    return result


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--trials',type=int,default=100_000)
    p.add_argument('--seed',type=int,default=8208)
    p.add_argument('--output',type=Path)
    a=p.parse_args()
    if not 1<=a.trials<=2_000_000:raise ValueError('trials outside permitted range')
    result=simulate(n=a.trials,seed=a.seed)
    if a.output:
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=='__main__':main()
