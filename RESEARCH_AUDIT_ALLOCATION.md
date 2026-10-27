# ACE research: allocating audit effort to EvalMath theorem fidelity

**Status:** paired synthetic decision experiment, 27 October 2026. The six mutation families in EvalMath PR #13 supply hypothesis labels. All audit sensitivities, false-positive rates, severities, and priors are invented. There is no observed distribution of mathematical defects, GPU-time measurement, or empirical claim that any policy beats a well-matched Bayesian procedure.

## Setup

Seven possible hypotheses are clean and TF-01 to TF-06. Six hypothetical audits have effort costs, targeted defects, sensitivity and background alert probability. The nominal prior puts probability 3/5 on clean; the shifted prior puts probability 1/4 on clean and more weight on TF-05/06. Both priors are public and form the two-element credal set. Audit outcomes are conditionally independent Bernoulli draws given the hidden hypothesis. Each trial generates all potential outcomes for paired comparison only. Allocation policies observe purchased audits.

All policies have the same **budget ceiling** (five effort units by default) and identical available audits. Actual expenditure differs because costs are indivisible. A single **robust terminal decision rule** is shared across all arms: publishing a flaw costs its severity, withholding a clean theorem costs 3, and withholding a flawed theorem costs 0.

The six allocation arms are a fixed-order cost-blind sweep (called uniform in code, but not a uniform random sampler), cheapest first, uniform random sampling of an affordable audit, Bayesian value of information per unit cost using the nominal prior, robust value of information per unit cost over the credal set, and an adversarial severity-weighted detection heuristic. An audit can be bought once.

## Exact decision calculation

Let H be the hidden hypothesis, a an audit, Y_a its binary report, and d a publish/withhold decision. For a prior P, terminal risk is

    R(P) = min_d Σ_h P(h) L(d,h).

For credal set C, the common terminal policy minimizes worst-case loss:

    R(C) = min_d max_(P in C) Σ_h P(h) L(d,h).

A binary audit produces preposterior risk

    R(C | a) = min_(d0,d1) max_(P in C)
               Σ_(h,y) P(h) Pr(Y_a=y | h) L(dy,h).

Robust audit value is R(C)-R(C | a). A policy can ignore the audit, hence value is nonnegative. With one prior, this reduces to ordinary Bayesian value of information. These are exact rational calculations under the declared likelihood model, not inferred real-world confidence levels.

After an audit, each prior is conditioned on the report and the next affordable action chosen again. The selection policy is greedy; it does not search all remaining budgeted decision trees. The severity heuristic optimizes another score and carries no minimax theorem.

## Reproduction

At repository root:

~~~bash
python -m unittest test_audit_allocation -v
python audit_allocation.py --trials 250 --seed 10227 --budget 5 --output results/theorem_audit_allocation_250.json
python -m unittest discover -q
~~~

Local 250-trial-per-world fixture results:

| Generating world | Arm | Mean terminal loss | Mean effort | Flawed theorem published |
|---|---|---:|---:|---:|
| nominal | robust_evi | 0.160 | 5.000 | 0.016 |
| nominal | bayes_evi | 0.772 | 4.780 | 0.076 |
| nominal | random | 1.252 | 4.808 | 0.016 |
| nominal | cheapest | 1.764 | 4.000 | 0.000 |
| shifted | robust_evi | 0.436 | 5.000 | 0.048 |
| shifted | bayes_evi | 0.744 | 4.712 | 0.084 |
| shifted | random | 0.816 | 4.808 | 0.024 |
| shifted | cheapest | 0.972 | 4.000 | 0.000 |

The fixed-order and cheapest-first policies coincide in this fixture. The adversarial heuristic and nominal Bayesian EVI also coincide. Cheapest-first achieves zero flawed publications by frequently withholding, which raises losses when the theorem is clean. The false-confidence rate by itself is not a sufficient policy score.

The fixture uses synthetic assumptions and 250 trials, so its numerical ranking is neither a statistical result about real AI agents nor a conclusion about the merit of Bayes versus ACE. An end-to-end policy comparison should include a Bayesian method calibrated to the true generative model and use equal observation, provenance and compute budgets.

## Next research gate

Replace invented likelihoods with empirical sensitivity matrices from independently reviewed EvalMath theorem mutations. Bind every mutation, evaluator output and audit action to immutable source hashes before allocation. Correlated evidence should reuse ACE's existing clustered-observation checks. Preserve the distinction between signatures over submitted observations and guarantees about when an observation was acquired.

Source: https://github.com/MoralityLabAI/EvalMath/pull/13
