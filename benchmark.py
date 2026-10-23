"""Run the ACE proof-of-concept evaluations with Python's standard library."""
import random
from ace import BernoulliEProcess, ProvenanceLedger, Report, SupportGraph, minimax_regret, surviving_models


def stopping_experiment(true_p: float, trials: int = 4000, horizon: int = 200, seed: int = 71):
    rng = random.Random(seed)
    rejected = 0
    stopping_sum = 0
    for _ in range(trials):
        proc = BernoulliEProcess(null_p=.5, alternative_p=.7, alpha=.05)
        for step in range(1, horizon + 1):
            proc.observe(int(rng.random() < true_p))
            if proc.rejected:
                rejected += 1
                stopping_sum += step
                break
    return rejected / trials, stopping_sum / rejected if rejected else None


def main():
    print('ACE v0.1 | synthetic benchmarks | fixed seed')
    print('\nTEST A: ten copied reports, one raw observation, LR=2')
    ledger = ProvenanceLedger()
    for i in range(10):
        ledger.add(Report(f'outlet-{i}', 'original-witness', 2.0))
    naive = 2.0 ** 10
    tracked = ledger.evidence_factor()
    print(f'Assuming ten independent observations: LR={naive:.0f}, posterior with 1:1 prior={naive/(1+naive):.4f}')
    print(f'Deduplicating their common root: LR={tracked:.0f}, posterior with 1:1 prior={tracked/(1+tracked):.4f}')
    print(f'Claimed roots: {ledger.independent_origin_count()}')
    print('Properly dependency-modeled Bayesian inference also yields LR=2 in this example.')

    print('\nTEST B: valid anytime test, H0=Bernoulli(.5), alternative bet=.7, alpha=.05')
    for p in (.5, .7):
        freq, mean_stop = stopping_experiment(true_p=p)
        print(f'True p={p:.1f}: rejection by t=200 = {freq:.4f}; mean rejection step={mean_stop and round(mean_stop,1)}')
    print('Guarantee: under the stated iid H0, false exclusion at any stopping time is <= 0.05.')

    print('\nTEST C: two live causal models and two possible actions')
    losses = {
        'calm': {'deploy': .10, 'watch': .25},
        'turbulent': {'deploy': .60, 'watch': .25},
    }
    action, regrets = minimax_regret(losses)
    print(f'Interventional expected losses: {losses}')
    print(f'Max regrets: {regrets}; minimax-regret action: {action}')
    bayes_deploy = .85*.10 + .15*.60
    print(f'Bayes example (prior P(calm)=.85): deploy expected loss={bayes_deploy:.3f} vs watch=.250')
    print('This is a difference in decision criteria; minimax regret gives the smaller worst-case regret.')

    print('\nTEST D: version-space survival on a single synthetic stream')
    rng = random.Random(812)
    outcomes = [int(rng.random() < .7) for _ in range(200)]
    live = surviving_models(outcomes, {'fair': .5, 'biased': .7}, alternative_p=.7)
    print(f'Heads={sum(outcomes)}/200; surviving candidate models={list(live)}')

    print('\nTEST E: evidence-channel graph under corruption')
    graph = SupportGraph(['witness-A', 'witness-B', 'witness-C'])
    graph.add_path('witness-A', 'newswire', 'claim')
    graph.add_path('witness-B', 'newswire', 'claim')
    print(f'Two apparent witnesses through one channel: cut size={graph.minimum_channel_cut("claim")}')
    graph.add_path('witness-C', 'independent-channel', 'claim')
    print(f'Add a separately delivered third witness: cut size={graph.minimum_channel_cut("claim")}')
    print('Cut size is a graph property, not a statistical confidence level.')


if __name__ == '__main__':
    main()
