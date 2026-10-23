"""Synthetic timing counterexamples: a signed start is weaker than a causal one.

Uniform p-value proxy under a true null, 20 pre-visible candidates, alpha 0.05.
No private inference model is being evaluated in this small counterexample;
this isolates the attacker's ability to select data before a signed start.
"""
from __future__ import annotations
import argparse
import json
import random


def run(trials=100_000,seed=1010,attempts=20,alpha=0.05):
    if type(trials) is not int or trials<1 or type(attempts) is not int or attempts<1 or not 0<alpha<1:
        raise ValueError('invalid benchmark parameters')
    rng=random.Random(seed);prepeek=honest=0
    for _ in range(trials):
        candidates=[rng.random() for _ in range(attempts)]
        prepeek+=int(min(candidates)<=alpha)
        # Honest device starts the single reserved experiment before observing a value.
        honest+=int(rng.random()<=alpha)
    return {'experiment':'ACE-start-ordering-synthetic-uniform-null',
            'trials':trials,'seed':seed,'candidate_attempts':attempts,'alpha':alpha,
            'prepeek_software_reporter':prepeek/trials,
            'honest_poststart_single_reading':honest/trials,
            'exact_prepeek':1-(1-alpha)**attempts,
            'exact_poststart':alpha,
            'boundary':'Device signatures cannot prove host-visible data were unobserved before the receipt.'}


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--trials',type=int,default=100_000)
    ap.add_argument('--seed',type=int,default=1010);ap.add_argument('--output',required=True)
    args=ap.parse_args()
    result=run(args.trials,args.seed)
    with open(args.output,'w') as f:json.dump(result,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps(result,sort_keys=True,indent=2))

if __name__=='__main__':main()
