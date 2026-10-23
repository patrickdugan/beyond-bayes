# ACE v0.2 experimental results

Synthetic experiment: Bernoulli(.2) safe / Bernoulli(.8) risky, 1,800
samples per truth and scenario, one public contamination budget k for all
learners, fixed seeds. Four report copies of each root were deduplicated.

Numbers below are per-truth conditional rates, while balanced mean cost uses
equal weights for the two states. A risky open incurs cost 1; an unnecessary
safe lockdown incurs cost 0.25. All baselines were tested on the same
observations. The attack-aware Bayesian oracle receives the additional
exact attack policy.

| Scenario | n,k | Method | Unsafe open under risky | False lock under safe | Balanced cost |
|---|---|---|---:|---:|---:|
| Clean | 24,0 | ACE | 0.00% | 1.39% | .0017 |
| Clean | 24,0 | Bayes | 0.00% | 0.00% | .0000 |
| Random | 24,2 | ACE | 0.00% | 4.22% | .0053 |
| Random | 24,2 | Bayes | 0.11% | 0.06% | .0006 |
| Random | 24,2 | Credal Bayes | 0.00% | 2.39% | .0030 |
| Targeted | 24,2 | ACE | 0.61% | 14.83% | .0216 |
| Targeted | 24,2 | Bayes (random flip model) | 0.33% | 1.06% | .0030 |
| Targeted | 24,2 | Credal Bayes | 0.00% | 8.28% | .0103 |
| Targeted | 24,2 | Policy-aware Bayes oracle | 0.00% | 0.00% | .0000 |
| Targeted | 24,4 | ACE | 0.28% | 87.61% | .1109 |
| Targeted | 24,4 | Bayes (random flip model) | 3.56% | 9.83% | .0301 |
| Targeted | 24,4 | Credal Bayes | 0.00% | 74.72% | .0934 |
| Targeted | 24,4 | Policy-aware Bayes oracle | 0.00% | 0.00% | .0000 |
| Targeted | 12,2 | ACE | 0.56% | 91.78% | .1175 |
| Targeted | 12,2 | Bayes (random flip model) | 8.00% | 19.56% | .0644 |
| Targeted | 12,2 | Credal Bayes | 0.39% | 71.33% | .0911 |
| Targeted | 12,2 | Policy-aware Bayes oracle | 0.00% | 0.00% | .0000 |

### Exact finite-horizon null enumeration

For null p=.2, fixed bet q=.8, alpha=.05, up to **any** k corrupted roots,
attacker allowed to see the entire clean trace, and horizon 12:

| Root flips permitted | Worst-case false exclusion probability |
|---|---:|
| 0 | 1.5073% |
| 1 | 1.0249% |
| 2 | 0.6369% |

The probabilities result from exhaustive enumeration of all clean sequences
and every permitted attack. The shrinking rejection frequency with growing k
reflects the increasing conservatism of the robust evidence envelope, not a
more favorable attack model. The general <=5% guarantee follows from the
pathwise inequality and Ville's theorem.

### Precommitted alpha frontier

Targeted n=24,k=4, 3,500 trials per truth. The rates vary with the selected
error budget; alpha must be fixed before observations arrive.

| Alpha | Unsafe open rate | Unnecessary lockdown rate | Balanced mean cost |
|---:|---:|---:|---:|
| .005 | .1% | 87.5% | .110 |
| .01 | .1% | 87.5% | .110 |
| .025 | .3% | 85.2% | .108 |
| .05 | .3% | 85.2% | .108 |
| .10 | .8% | 71.3% | .093 |
| .20 | .8% | 71.3% | .093 |
| .35 | 2.7% | 68.3% | .099 |

See `results/` for full precision, state-specific false-exclusion and
ambiguous-survival rates, and Wilson Monte Carlo intervals. These are
small synthetic demonstrations with known Bernoulli models and a simple
attacker. Their purpose is to expose proof obligations and tradeoffs.
