# ACE v0.2: Adversarial Constraint Epistemics

**Research prototype, October 23, 2026.** 30 Python tests passing locally.
Candidate Lean proof source included; a Lean toolchain was unavailable in the
creation environment, so kernel compilation is pending in the included CI.
No claim of general superiority over Bayesian inference is established.

## Run

```bash
python -m unittest discover -v
python adversarial_benchmark.py --trials-per-truth 1800 --output results
python alpha_frontier.py --trials-per-truth 3500 --output results
```

Requires Python 3.10+, standard library only. Tested with Python 3.13.

### What changed from v0.1

- `robust.py`: exact bounded-Hamming-flip lower-envelope e-process for fixed
  Bernoulli bets, with anytime-valid false-exclusion bound conditional on the
  clean iid null and verified observation roots.
- `adversarial_benchmark.py`: four inference policies; exact provenance-aware
  Bayesian marginalization, credal Bayesian posterior envelope, ACE minimax
  regret, and an attack-policy-aware Bayesian oracle.
- `alpha_frontier.py`: precommitted alpha sensitivity with Wilson intervals.
- `mincut.py`: scalable vertex-capacitated max-flow computation of minimum
  evidence-channel cuts, cross-checked against exhaustive hitting sets.
- `lean/ACE/Foundations.lean`: candidate Lean formalization of root-cloning
  invariance, model survival under new constraints, path-cut monotonicity,
  duplicate support invariance, and robust evidence crossing containment.
- `.github/workflows/verify.yml`: Python regression and Lean kernel-check jobs
  for a future repository push.
- `RESEARCH.md`: precise definitions, theorem argument, threat model, baseline
  fairness notes, model limitations, and future falsification experiments.

## Core mathematical risk contract

For a fixed simple null p, fixed alternative bet q, and distinct verified
clean roots X with independent Bernoulli(p) outcomes, let an attacker change
at most k root values in observed stream Y. On prefix t define

    R_t^p(Y) = min_{Z : d_H(Z,Y[1:t])<=k} E_t^p(Z).

The true X prefix is always a candidate, so R_t^p(Y) <= E_t^p(X), where E
is a nonnegative test martingale under the null. Ville's inequality yields:

    P_p(ever rejecting the true model, any stopping time) <= alpha.

If a high-risk action occurs only when the dangerous null is rejected,

    P_risky(ever taking the high-risk action | risky world true) <= alpha.

This risk bound holds for attacks selected adaptively or with hindsight, given
that at most k *genuine* roots change and that null independence conditions
hold. It is **not** a posterior or a universal error guarantee under
arbitrary missing/incorrect model classes, forged roots, or unlimited edits.

## Most revealing adversarial test

24 distinct roots, up to four malicious flips, 1,800 simulations for each
true world and equal class proportions. The attacker knows the true state.
All policies get the same observations and k; the oracle gets the additional
exact attack algorithm. At alpha=.05:

| Policy | P(open \| risky) | P(lock \| safe) | Balanced mean cost |
| --- | ---: | ---: | ---: |
| ACE | 0.28% | 87.61% | 0.1109 |
| Bayesian, provenance-aware random-flip likelihood | 3.56% | 9.83% | 0.0301 |
| Credal Bayesian posterior interval | 0.00% | 74.72% | 0.0934 |
| Oracle Bayesian, exact attacker policy | 0.00% | 0.00% | 0.0000 |

Costs are 1.0 for opening when risky and 0.25 for locking when safe. This
shows a strong safety/conservatism tradeoff. The random-flip Bayes comparator
is correctly specified for the random scenario, and misspecified by the
targeted adversary's strategic edits. The exact-policy oracle demonstrates
what Bayesian inference can achieve when given the attacker model.

Full results in `results/adversarial_metrics.csv` and
`results/alpha_frontier.csv`. Read `RESEARCH.md` before interpreting the
numbers. Tests use fixed seeds and synthetic data.

## Status of Lean results

`lean/ACE/Foundations.lean` contains proof terms, with no intentional
`sorry`, `admit`, or introduced axioms. Kernel compilation has *not* happened
in the local environment. Once hosted in a GitHub repository,
`.github/workflows/verify.yml` is configured to run the Lean toolchain.
The file formalizes the logical proof obligations; probabilistic Ville
inequality and the executable algorithm's correctness remain outside its
scope. See `lean/README.md`.

## Sources

- [Ramdas, Grünwald, Vovk, Shafer (2023), anytime-valid inference](https://doi.org/10.1214/23-STS894)
- [Walley (2000), imprecise probability](https://doi.org/10.1016/S0888-613X(00)00031-1)
- [Cozman, quasi-Bayesian / credal updating](https://www.cs.cmu.edu/afs/cs/user/fgcozman/www/Research/QuasiBayesian/Global/node2.html)
