# ACE v0.6 benchmark results

**Reproduction:** `python benchmark_clusters.py --trials-per-truth 4000 --seed 82064 --output results/v06_clustered_benchmark`. Synthetic, preregistered random seed; risky and safe worlds each receive 4,000 simulations per scenario. Monte Carlo rates have finite sampling error. The exact one-latent scenario does not use Monte Carlo. The complete CSV and JSON are included.

All methods that claim matched comparison receive the same **cluster-level observations** and (where applicable) the same adversarial substitution/erasure budget. For the precise IID null, `P_risky(1)=0.8`, `P_safe(1)=0.2`, equal prior and action losses unsafe:unnecessary denial =20:1. ACE uses `alpha=0.05`; the resulting thresholds agree.

| Scenario | Method | Unsafe authorization when risky | Unnecessary denial when safe |
|---|---|---:|---:|
| 24 independent roots, no attack | ACE v0.6 | 1.55% | 0.025% |
| 24 independent roots, no attack | Matched robust Bayes | 1.55% | 0.025% |
| 24 roots, 2 substitutions + 4 selective erasures | ACE v0.6 | 0.025% | 86.75% |
| Same attack, identical protection | Matched robust Bayes | 0.025% | 86.75% |
| Same attack, assumes clean observed bits | Naive Bayes | 79.475% | (see CSV) |
| 6 independent clusters with 4 perfectly copied signatures each | ACE v0.6 | 1.20% | 24.675% |
| Same 6 clusters, 24 signatures counted as independent | Naive Bayes | 24.225% | (see CSV) |
| 24 conditional Markov clusters, risky p at lower envelope | ACE v0.6 | 3.60% | 0.875% |
| Same conditional Markov envelope | Rectangular credal Bayes | 2.25% | 2.175% |
| 24 conditional Markov clusters, risky p at interval midpoint | ACE v0.6 | 0.75% | 0.725% |
| Same conditional Markov envelope | Rectangular credal Bayes | 0.525% | 2.05% |
| **Exactly one shared latent bit, 24 signatures** | Correctly grouped ACE or Bayes | **0% exact** | n/a |
| Same latent, wrongly modeled as 24 iid roots | ACE or Bayes | **20% exact** | n/a |

The attack benchmark protects against up to two *cluster* substitutions total, and treats missing scheduled clusters as erasures. The 79.475% result shows a misspecified iid Bayes model under an adaptive adversary, with no matching corruption protection. The strongest Bayesian comparator in the attack row receives the same candidate set and makes identical decisions to ACE.

These simulation numbers are descriptive; the 5% risk control comes from the mathematically valid e-process under its **declared** null assumptions, not from empirical calibration alone. The Markov null uses a conditional interval and precommitted one-step betting factors. The credal comparator maximizes risky likelihood across the same rectangular family and clean-trace reconstruction set.

This release does not claim that cryptographic authentication establishes causal independence, that its Python DP is formally verified, or that the new cluster gate is fully integrated into the witnessed certificate protocol.
