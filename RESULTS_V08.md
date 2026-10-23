# ACE v0.8 reproducible results

## Benchmark

Run `python benchmark_campaign.py --trials 200000 --seed 8208 --output results/v08_campaign_benchmark.json`. The synthetic null produces a false opening with exactly the specified probability in each trial; these draws test the family-wise accounting equation, not the physical sampling guarantees of an AI system.

| Policy for 20 attempts | Theoretical rate | Monte Carlo, 200k campaigns |
|---|---:|---:|
| Naïve fresh 5% allowance each attempt | 64.1514% | 64.0360% |
| Fixed 5% **total**, split across 20 experiments | 4.8830% | 4.9725% |
| Stopping after first success with a geometric spend schedule | at most 5% | 4.8860% |

Under an invalid shared-latent conditional model a single repeated sensor error can produce a 20% erroneous authorization rate despite compliant alpha spending. The global budget controls the *repetition multiplier* only under the same conditional evidence assumptions required by the original e-process.

## Regression/attack coverage

The automated v0.8 tests cover exact integer accounting, reserve-before-sample fixture construction, signed quorum votes, duplicate experiment challenges, nonrefundable denials, never-finalized reservations, one-time action consumption, local database rollback, two database rollbacks, partial quorum commits, replayed finalization certificates, wrong v2-model alpha, forged campaign bindings, malformed policy pins, corrupted votes, independent replay and deterministic synthetic bundles. An exhaustive small-cap transition explorer enumerates reachable state paths and checks that cumulative spend equals the sum of accepted reservations.

All results are on synthetic credentials and local SQLite replicas. `README.md` contains full CI commands; run `python -m unittest discover -q` to reproduce all inherited v0.5–v0.7 and v0.8 tests.
