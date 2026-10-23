"""ACE v0.6 dependency falsifiers and matched Bayesian baselines.

All matched statistical procedures see identical cluster-level bits and the
same corruption/erasure budget. Bayes assumes the two exact iid Bernoulli
models and a precommitted 1:20 lock-versus-unsafe loss ratio, corresponding to
prior P(risky)=.5 and posterior authorization threshold 1/21. ACE's
likelihood-ratio e-process with alpha=.05 has the same crossing threshold.

The sensor-naive baselines are explicitly *misspecified counterexamples*:
repeated readings of one latent bit are incorrectly counted as independent.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
import random
from statistics import mean

from conditional import (ConditionalNull, anytime_robust_max_log_e,
                         robust_log_e_prefixes, credal_log_e_prefixes)

ALPHA = .05
P_RISKY = .8
P_SAFE = .2


def matched_bayes_authorize(bits: list[int | None], *, k: int,
                            p_risky: float=P_RISKY,
                            p_safe: float=P_SAFE,
                            risk_loss: float=20.,
                            lock_loss: float=1.) -> bool:
    """Worst-case posterior-risk policy over every plausible clean prefix.

    With prior 1:1 and loss(unsafe):loss(false-lock)=20:1, authorize if
    P(risky | X)<=1/21 for ANY prefix, where the posterior is calculated
    conservatively against all traces compatible with the observed stream.
    This baseline has exactly the same attack budget as ACE.
    """
    if type(k) is not int or k < 0:
        raise ValueError('invalid corruption budget')
    if min(p_risky,p_safe,lock_loss,risk_loss)<=0 or max(p_risky,p_safe)>=1:
        raise ValueError('invalid distributions/costs')
    ones=zeros=missing=0
    ll1=math.log(p_safe/p_risky)
    ll0=math.log((1-p_safe)/(1-p_risky))
    threshold=math.log(risk_loss/lock_loss)
    for obs in bits:
        if obs is None:
            missing+=1
        elif type(obs) is int and obs==1:
            ones+=1
        elif type(obs) is int and obs==0:
            zeros+=1
        else:
            raise ValueError('invalid observation')
        if ll1 < ll0:
            # q<p: the least favorable clean trace has as many ones as
            # possible, achieved by erasing and flipping observed zeros.
            clean_ones=ones+missing+min(k,zeros)
        else:
            clean_ones=max(0,ones-min(k,ones))
        clean_zeros=ones+zeros+missing-clean_ones
        least_log_bf=clean_ones*ll1+clean_zeros*ll0
        if least_log_bf >= threshold-1e-12:
            return True
    return False


def naive_bayes_as_clean_authorize(bits: list[int | None], *, risk_loss=20.,lock_loss=1.) -> bool:
    """Incorrectly assumes all surviving reports are clean unselected samples."""
    logbf=0.0
    threshold=math.log(risk_loss/lock_loss)
    for bit in bits:
        if bit is None:
            continue
        logbf+=math.log(P_SAFE/P_RISKY) if bit else math.log((1-P_SAFE)/(1-P_RISKY))
        if logbf >= threshold-1e-12:
            return True
    return False


def ace_authorize(bits: list[int | None], k: int, model: ConditionalNull,
                  alpha: float=ALPHA) -> bool:
    return anytime_robust_max_log_e(bits,k,model) >= math.log(1/alpha)-1e-12


def credal_bayes_authorize(bits: list[int | None], *, k: int,
                           model: ConditionalNull, risk_loss: float=20.,
                           lock_loss: float=1.) -> bool:
    """Prior-1:1 rectangular credal-Bayes worst-case posterior risk policy."""
    if risk_loss <= 0 or lock_loss <= 0:
        raise ValueError('losses must be positive')
    scores=credal_log_e_prefixes(bits,k,model)
    return max((0.0,*scores)) >= math.log(risk_loss/lock_loss)-1e-12


def simulate_markov(rng: random.Random, model: ConditionalNull, n: int, endpoint: str) -> list[int]:
    state=model.initial_state
    bits=[]
    for _ in range(n):
        row=model.row(state)
        p={'low':row.low,'mid':(row.low+row.high)/2,'high':row.high}[endpoint]
        bit=int(rng.random()<p)
        bits.append(bit)
        state=row.next_state(bit)
    return bits


def targeted_attack(clean: list[int], *, k: int, erasures: int, truth: str) -> list[int|None]:
    """Clairvoyant fixed-budget attacker targeting unsafe opens or false locks."""
    if truth not in ('risky','safe'):
        raise ValueError('invalid world')
    unwanted=1 if truth=='risky' else 0
    wanted=1-unwanted
    observed:list[int|None]=clean.copy()
    # Erasures preferentially censor bits contradicting the chosen target.
    indices=[i for i,b in enumerate(clean) if b==unwanted]
    for i in indices[:erasures]:
        observed[i]=None
    for i in indices[erasures:erasures+k]:
        observed[i]=wanted
    return observed


def check_matched_identity() -> bool:
    from itertools import product
    model=ConditionalNull.iid(P_RISKY,P_SAFE)
    for n in range(1,8):
        for bits in product((0,1,None),repeat=n):
            for k in range(3):
                a=ace_authorize(list(bits),k,model)
                b=matched_bayes_authorize(list(bits),k=k)
                if a != b:
                    raise AssertionError(f'matched policies disagree: {bits=} {k=}')
    return True


def run(trials:int=4000,seed:int=82064):
    if type(trials) is not int or trials<1:
        raise ValueError('positive trial count required')
    rng=random.Random(seed)
    iid=ConditionalNull.iid(P_RISKY,P_SAFE)
    interval=ConditionalNull.markov(initial=(.65,.85),
                                    after_zero=(.60,.75),
                                    after_one=(.80,.95),bet_q=.2)
    rows=[]
    scenarios=[('independent_roots',24,0,0,'iid'),
               ('bounded_poisoning_and_erasure',24,2,4,'iid'),
               ('dependent_markov_low',24,0,0,'markov_low'),
               ('dependent_markov_mid',24,0,0,'markov_mid'),
               ('six_clusters_four_copies',6,0,0,'iid')]
    for scenario,n,k,e,kind in scenarios:
        for truth in ('risky','safe'):
            p=P_RISKY if truth=='risky' else P_SAFE
            summary={name:0 for name in ('ACE-v06','Bayes-matched-robust',
                                          'Bayes-rectangular-credal',
                                          'Bayes-as-clean','Sensor-naive-Bayes')}
            for _ in range(trials):
                if kind.startswith('markov') and truth=='risky':
                    clean=simulate_markov(rng,interval,n,kind.split('_')[-1])
                else:
                    clean=[int(rng.random()<p) for _ in range(n)]
                observed=targeted_attack(clean,k=k,erasures=e,truth=truth)
                model=interval if kind.startswith('markov') else iid
                summary['ACE-v06']+=ace_authorize(observed,k,model)
                summary['Bayes-rectangular-credal']+=credal_bayes_authorize(observed,k=k,model=model)
                if kind=='iid':
                    summary['Bayes-matched-robust']+=matched_bayes_authorize(observed,k=k)
                    summary['Bayes-as-clean']+=naive_bayes_as_clean_authorize(observed)
                if scenario=='six_clusters_four_copies':
                    expanded=[bit for bit in observed for _ in range(4)]
                    summary['Sensor-naive-Bayes']+=naive_bayes_as_clean_authorize(expanded)
            for name,opens in summary.items():
                if name in ('Bayes-matched-robust','Bayes-as-clean') and kind!='iid':
                    continue
                if name=='Sensor-naive-Bayes' and scenario!='six_clusters_four_copies':
                    continue
                rows.append({'scenario':scenario,'truth':truth,'method':name,
                             'num_clusters':n,'raw_sensor_count': n*4 if scenario=='six_clusters_four_copies' else n,
                             'corrupt_cluster_budget':k,'max_erasures':e,'trials':trials,
                             'opens':opens,'unsafe_rate':opens/trials if truth=='risky' else None,
                             'false_lock_rate':1-opens/trials if truth=='safe' else None})
    # A single common latent bit, p_risky=.8, repeated by 24 keys; exact.
    for name,opens_if_zero in [('ACE-one-cluster',0),('Bayes-one-cluster',0),
                               ('Sensor-naive-Bayes',1),('ACE-wrongly-split-24',1)]:
        rows.append({'scenario':'one_latent_24_signatures_EXACT','truth':'risky','method':name,
                     'num_clusters':1 if 'one-cluster' in name else 24,
                     'raw_sensor_count':24,'corrupt_cluster_budget':0,
                     'max_erasures':0,'trials':'exact','opens':None,
                     'unsafe_rate':(1-P_RISKY)*opens_if_zero,'false_lock_rate':None})
    return {'methodology':{'trials_per_truth':trials,'seed':seed,
                           'alpha':ALPHA,'risky_model':'iid Bernoulli(0.8), or conditional Markov envelope',
                           'safe_model':'iid Bernoulli(0.2)',
                           'bayes_prior_risky':.5,'cost_unsafe':20,'cost_false_lock':1,
                           'matched_bayes':'identical cluster units, attacker budget, iid null and loss threshold',
                           'credal_bayes':'worst posterior risky across rectangular null envelope, clean reconstructions, prior 1:1, identical 20:1 losses',
                           'markov_risky_distribution':'conditional lower or midpoint bound, safe iid 0.2',
                           'sensor_naive':'intentionally misspecified; each repeated cluster bit counted as independent'},
            'rows':rows}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--trials-per-truth',type=int,default=4000)
    parser.add_argument('--seed',type=int,default=82064)
    parser.add_argument('--output',default='results/v06_clustered_benchmark')
    a=parser.parse_args()
    result=run(a.trials_per_truth,a.seed)
    p=Path(a.output)
    p.parent.mkdir(parents=True,exist_ok=True)
    p.with_suffix('.json').write_text(json.dumps(result,indent=2,allow_nan=False)+'\n')
    with p.with_suffix('.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=result['rows'][0])
        writer.writeheader();writer.writerows(result['rows'])
    print(json.dumps(result['rows'],indent=2,allow_nan=False))


if __name__=='__main__':
    main()
