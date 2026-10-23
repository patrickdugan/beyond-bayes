# ACE v0.2: hostile evidence, robust e-processes, and policy-aware baselines

**October 23, 2026. Research preprint / executable experiment.**

## 1. What ACE can claim

ACE is a proposed design that composes provenance constraints, sequential
confidence control, version-space inference, causal decision losses, and
minimum source cuts. Much of the component mathematics already exists.
Credal and imprecise probability methods are especially close in spirit.
Our thesis concerns the added value of mandatory provenance and challenge
certificates within practical decision systems. These experiments are not a
novelty proof or a general demonstration that ACE outperforms Bayesian
inference.

## 2. Threat model

There are `n` distinct, **verified** observation roots. Conditional on one of
two true models, clean root outcomes are independent Bernoulli observations:

    M_safe:  P(X_i=1) = 0.2
    M_risky: P(X_i=1) = 0.8

An adversary may change up to `k` distinct root observations in the full
sequence. The malicious edits may depend on the clean data, the true model,
and all other readings. Downstream report duplication does not consume
additional independent observations. If origins are forged or clean roots
have unmodeled correlations, this threat model and its guarantee can fail.

## 3. Robust evidence envelope

For a candidate simple null `p` and a **precommitted fixed** bet `q`, define

    E_t^p(x) = ∏_{i=1}^t q(x_i) / p(x_i).

For the observed prefix `y[1:t]` and Hamming budget `k`, define

    R_t^p(y) = min { E_t^p(z): z∈{0,1}^t, d_H(z,y) <= k }.

Under the clean null, `E_t^p(X)` is a nonnegative martingale with `E_0=1`.
For every attack of at most `k` flips, **path by path**, the true clean
prefix belongs to the minimization set, so

    R_t^p(Y) <= E_t^p(X)  for every t.

Hence the event `sup_t R_t^p(Y) >= 1/alpha` is a subset of the event
`sup_t E_t^p(X) >= 1/alpha`, and Ville's inequality yields

    P_p(∃t: R_t^p(Y) >= 1/alpha) <= alpha.

**Authorization corollary.** If a protected action is allowed only while
the safe model survives and after the risky null has been rejected, then
for any stopping rule and any attacker limited to k altered roots,

    P_risky(ever authorizing the protected action) <= alpha.

This result is about the chance of the action under the risky *true simple
null*, not a calibrated posterior probability or a certificate that the
true model belongs to the candidate class. Alpha is fixed before viewing
data; choosing it after seeing outcomes breaks the stated risk contract.

This allows anytime rejection and arbitrarily targeted flips within the
precommitted *total* budget. For a fixed q, log evidence depends only on the
number of successes in a prefix. If q>p, flip up to `min(k, observed ones)`
ones downward to minimize the ratio; if q<p, flip up to `min(k, observed
zeros)` zeros upward. The resulting O(1) per-prefix formula in `robust.py`
is checked against exhaustive Hamming-ball minimization.

**Formalization boundary:** Lean `Foundations.lean` proves the deterministic
implication conditional on the envelope inequality; it does not yet prove
this specific minimization implementation is an envelope, define stochastic
processes, or formalize Ville. Exhaustive Python tests give finite-state
regression evidence, not a Lean theorem.

## 4. Four comparators

All the following consume **identical** deduplicated observations and the
public bound `k`:

- `ACE-v0.2`: retain two simple null models until the corresponding robust
  e-process crosses `1/.05`; choose the action with smaller maximum regret
  across surviving causal models; on empty model sets flag failure and lock.
- `Bayes-known-provenance`: prior `(0.5,0.5)` on the two truth models; exact
  likelihood under independently flipped roots at rate `eps`, *conditioned*
  on there being at most `k` flips. It integrates over all flip subsets;
  the conditioning creates dependence between flip indicators. This is
  correctly specified for the random-attack scenario.
- `Credal-Bayes`: same two truth models and equal prior; calculate the
  posterior risk interval by conditioning on every candidate clean trace
  within `k` flips, choose minimax posterior regret across that interval.
  This is a robust Bayesian comparator; its interval is defined by the
  range over repairs, without a separate explicit corruption-policy prior.
- `Oracle-Bayes-known-policy`: only in targeted-attack experiments; it
  receives *extra knowledge* of the attacker's exact algorithm: change the
  first `k` root bits that would induce the wrong decision. The likelihood
  is calculated exactly over all preimages of this deterministic map.
  This oracle has privileged information and establishes a stronger upper
  benchmark for what a correctly informed Bayesian analysis can do.

The synthetic loss function has `open` cost `0` in the safe state and `1`
in the risky state; `lock` costs `0.25` in the safe state and `0` in the
risky state. The imbalance makes false opens a higher-consequence outcome.
Individual experiments use equal numbers of safe and risky worlds. ACE and
credal Bayes use the same action costs as the Bayes baselines.

Scenarios:

1. `clean`: 24 roots, no flips. Exact-model Bayes benchmark.
2. `random`: 24 roots, at most 2 random flips from the declared law.
3. `targeted`: 24 roots, at most 2 worst-direction flips by an informed adversary.
4. `targeted`: 24 roots, up to 4 flips.
5. `targeted`: 12 roots, up to 2 flips.

## 5. Interpretation

The expected tradeoff is severe: robust survivor sets demand more evidence
to exclude a possible risky world. ACE can therefore have a low rate of
unsafe openings and an expensive rate of false lockdowns. A Bayesian model
with the true attack mechanism recovers its inferential advantage; a
well-specified credal Bayesian comparator can closely match or exceed ACE
in many regimes. Whether ACE helps depends on how much source corruption
and model ambiguity are tolerated and on action-loss asymmetry.

The empirical rate of excluding the true model need not equal the chosen
`alpha`: Ville is a uniform upper bound and tends to be conservative. It is
valid across stopping times only while the clean null and budget assumptions
hold. The experiment does not optimize the bet q, false-exclusion budget, or
experimental design, and it uses known cause-to-action losses rather than
estimating a causal effect from observations.

## 6. Source-cut robustness

For a family of source-to-claim paths P and corruptible vertices V, define

    Vulnerable_k(P) := ∃ S⊆V, |S|≤k and ∀ p∈P, p∩S ≠ ∅.
    Robust_k(P) := not Vulnerable_k(P).

Adding a new support path shrinks the set of cuts that compromise *all*
paths, so robustness is monotone in the number of paths for fixed allowed
compromise nodes. Duplicating an existing path changes nothing. Lean
`Foundations.lean` states and gives proof terms for both propositions.

These are **graph-topological** properties. Truthfulness and independent
measurement origins require separate semantic certificates. A graph that
has been misreported can give a misleading resilience score.

## 7. Falsifiers / extensions

- Remove verified-root identities, forge them, and quantify ACE failure.
- Create shared latent influences between nominally independent roots.
- Let the attacker change more than k roots or poison the model-selection
  procedure itself.
- Add sequential intervention choices, causal experimental data, and
  policy costs that depend on the environment.
- Compare robust e-processes with calibrated Bayesian adversary-policy
  ensembles, robust sequential confidence sequences, and distributionally
  robust policy optimization at fixed computational cost.
- Prove a full probabilistic Ville-derived theorem in Lean with Mathlib,
  and kernel-check the present core-only module.

## Sources and neighboring research

- Ramdas, Grünwald, Vovk, Shafer (2023), *Game-Theoretic Statistics and Safe
  Anytime-Valid Inference*: https://doi.org/10.1214/23-STS894
- Walley (2000), *Towards a Unified Theory of Imprecise Probability*:
  https://doi.org/10.1016/S0888-613X(00)00031-1
- Cozman, Quasi-Bayesian / credal updating:
  https://www.cs.cmu.edu/afs/cs/user/fgcozman/www/Research/QuasiBayesian/Global/node2.html
- Dellaporta, O'Hara, Damoulas (2026), distributionally robust optimization
  under Bayesian ambiguity sets: https://doi.org/10.3390/e28040430

## 8. Risk frontier

`python alpha_frontier.py` generates `results/alpha_frontier.csv` and a
reproducible Monte Carlo estimate of the authorization-error versus
unnecessary-lockdown frontier for several **precommitted** alpha levels.
Each point has its own valid <=alpha bound; choosing alpha after inspecting
the data forfeits the precommitted guarantee. The 95% Wilson intervals in
the CSV reflect Monte Carlo uncertainty about event frequencies only.

## 9. Computational cut evaluator

The source graph now has an exact minimum corruptible-vertex-cut evaluator
using node splitting and Dinic max flow. Random small DAG comparisons against
the original exhaustive hitting-set oracle (500 fixtures) pass, and a
60-source independent-channel fixture has the expected cut size of 60.

This is a computational implementation test; the Lean source proves only
the semantic monotonicity and duplicate invariance lemmas, not correctness
of Dinic or source-path enumeration.
