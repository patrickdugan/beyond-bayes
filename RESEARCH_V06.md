# ACE v0.6: dependent evidence, conditional nulls and matched Bayesian controls

Research prototype, 23 October 2026. This describes **what the code implements and assumes**, not a new foundational probability theorem. Related work includes Shafer and Vovk's game-theoretic probability, e-process methods for nonstationary conditional means, and composite-null sequential tests (references below).

## 1. The epistemic problem

Ed25519 verifies which enrolled key signed a bit. It does not certify how that bit was generated, whether several keys share a common physical observation, or the conditional distribution of the next bit. Those require a sampling model established independently of the key registry.

A deliberately extreme falsifier has 24 authenticated keys, each faithfully observing a single latent bit `L ~ Bernoulli(0.8)`. Under the incorrect iid null, twenty-four copies of `L=0` yield a Bayes factor `4**24`, exceeding the `1/0.05=20` threshold. Since `P(L=0)=0.2`, the false-authorization probability is **exactly 0.2**. All signatures validate. No identity was forged. The hypothesis model was wrong.

ACE v0.6 introduces an **externally pinned exact-cover cluster plan**. The 24 readings can be assigned to one cluster and yield at most one sampled bit. If any enrolled slot is absent, the cluster is an erasure; valid disagreement inside a cluster is a hard authorization failure. The cluster plan hash covers the underlying v0.5 source manifest hash, ordered cluster membership, conditional model, whole-run corrupted-cluster budget and significance level.

One cluster is an assertion that the underlying clean measurements coincide. The source signatures alone do not establish that assertion. If one truly shared latent process is erroneously assigned to 24 clusters, the error returns. Inference cannot repair a false causal model by cryptographic means.

## 2. Conditional-null e-factors

Let `S_t` be a known, precommitted finite automaton state obtained by updating from the **clean** historical bits. Require, for the full clean history `F_(t-1)`,

```
  l(S_t) <= P(X_t=1 | F_(t-1)) <= u(S_t),
      0 < l(S_t) <= u(S_t) < 1.
```

The state may summarize arbitrary chosen finite memory. Conditional probabilities may still depend on the complete history, provided they stay inside the state-specific interval. Each state carries a fixed target alternative `q(S_t)` and deterministic transitions following 0 or 1. These values are pinned before observations arrive.

A one-step factor for a clean observed bit `x` is:

```
        /  q/l                if x=1, q<l
  e(x)= | (1-q)/(1-l)        if x=0, q<l
        |  q/u                if x=1, q>u
        | (1-q)/(1-u)        if x=0, q>u
        \  1                  if l <= q <= u
```

For `q<l`, the factor's expectation is affine and *decreasing* in the actual conditional success probability `p`, hence its maximum over `[l,u]` is exactly 1 at `p=l`. When `q>u`, the expectation increases with `p` and reaches 1 at `p=u`. For `q` inside the null interval the factor is 1. Every factor is nonnegative and has conditional expectation <=1. Thus the clean capital `E_t = prod_(i<=t) e_i(X_i)` is a nonnegative supermartingale, with initial capital 1, for every null process satisfying the **full-history** conditional restrictions. Ville's inequality then gives `P(sup_t E_t >= 1/alpha) <= alpha`.

This allows Markov-style dependence **across clusters**. Conditional intervals permit a wider family than a single Markov chain; they do not require conditional independence of clusters. They do require a valid externally checked bound on the actual conditional mean given the whole history.

## 3. Robust contaminated/erased reconstruction

Let `Y_t` be the reported cluster observation in `{0,1,missing}`. Assume at most `k` reported cluster bits can disagree with their genuine clean counterparts **in the whole experiment**, and any number of bits may be erased. For any prefix define

```
  C_t(Y,k) = {x in {0,1}^t :
            #{i<=t : Y_i is observed and Y_i != x_i} <= k}.
  R_t(Y) = inf_{x in C_t(Y,k)} log E_t(x).
  Authorize iff max_(0<=t<=n) R_t(Y) >= log(1/alpha).
```

The DP has a state `(used_corruptions, finite_null_state)` with the smallest score of any feasible clean trace reaching it. Each new reported bit branches into clean zero or one. A change to a *present* bit consumes one unit of `k`; missing bits permit either value for free. Transitions and bets are always evaluated on each candidate **clean history**, so poison cannot secretly change the predictable betting strategy. There are at most `(k+1)*|S|` DP states and two branches per step, yielding O(n(k+1)|S|) running time with a cached automaton table.

For the actual clean path `X`, membership `X_(1:t) in C_t(Y,k)` ensures `R_t(Y) <= log E_t(X)` **simultaneously for all t**. Therefore a robust authorization event is included in the clean e-process crossing event, giving the same `alpha` bound even for a hindsight attacker choosing substitutions and erasures. The theorem is conditional on a truthful cluster partition, valid clean-data conditional envelope, bound `k`, secure enrollment and correctly implemented scoring.

## 4. Strong Bayesian comparison with the same inputs

In an exact-null iid test, define the risky model `P0=Bernoulli(0.8)` and safe alternative `P1=Bernoulli(0.2)`. A Bayes decision-maker with `P(risky)=0.5`, loss(unsafe action)=20 and loss(unnecessary lockdown)=1 authorizes when posterior risky probability is at most `1/21`.

The posterior risky probability is `1/(1+BF_(safe:risky))`, so the decision is equivalent to `BF_(safe:risky) >= 20`, precisely ACE's `alpha=0.05` crossing rule. If *both* procedures also guard against the same set of up to `k` substitutions and arbitrary missing observations, both use the minimum admissible Bayes factor and the policies remain **exactly equivalent**. The benchmark asserts this for all observation streams of length 1 to 7 and budgets 0 to 2. A claim that ACE beats this calibrated Bayesian method would be false.

The benchmark also includes an explicitly misspecified Bayes baseline that ignores corruption and deletes erasures. That baseline shows why the provenance and attack assumptions matter; it is not evidence for an intrinsic limitation of Bayes.

For interval-valued Markov nulls, **rectangular credal Bayes** uses the same cluster plan and conditional intervals but maximizes the risky likelihood of *each feasible clean sequence* over all predictable null choices consistent with the interval. Under the fixed safe alternative, its one-step conservative factors are:

```
   x=1: q/u;       x=0: (1-q)/(1-l).
```

Its posterior worst-case risky probability is based on the lowest admissible accumulated factor. This is a legitimate uncertainty-set benchmark with equal prior and 20:1 action losses. It tends to be more conservative because it lets the nuisance null pick a separate worst case for every realized bit; ACE's one-sided betting construction spends evidence more efficiently for the specified direction. Both protect an anytime e-value-style event because their one-step factors have conditional expectation at most one.

## 5. Verification, falsifiers and limitations

- 151 Python unit tests passing locally after v0.6 changes, including exhaustive short-horizon checking of the lower envelope against every compatible clean trace, every report type, all IID fast-path equivalences, and adversarial signed cluster admission.
- Exact enumeration across all clean traces and all reported traces with any erasures plus one substitution for a short Markov horizon confirms the pathwise argument numerically and puts the tested null crossing probabilities below 5% for lower, midpoint and upper transition choices.
- One physical latent repeated across 24 keys yields exactly 20% false opens if misclassified into 24 independent clusters; declaring one correct cluster yields zero false opens in that particular one-bit design.
- A real process outside the pinned conditional intervals can violate the statistical error guarantee, even with perfect source signatures and honest witness quorums.
- The v0.6 `ClusteredEvidenceGate` is a **standalone signed-input statistical prototype**. The v0.5 witnessed authorization certificate still verifies its previous iid inference protocol and MUST NOT be presented as a certificate of a clustered v0.6 authorization. The next protocol version needs explicit versioned signing and independent certificate replay of the cluster-plan hash, conditional model, and reconstruction score.
- The current policy can deny safe actions aggressively under bounded poisoning or censoring. False-lockdown and average-loss metrics must accompany false-authorization rates.
- Inference assumes a preregistered cluster roster, sampling order and a causal argument for its bounds. Unknown shared causes between supposedly distinct clusters remain a model-misspecification risk; their discovery and stress testing are empirical research problems.

## 6. References

- Shafer and Vovk, *Game-Theoretic Foundations for Probability and Finance* (2019), specifically its abstract testing protocols: https://doi.org/10.1002/9781118548035.ch7
- *Testing the mean and variance by e-processes*, Biometrika 112 (2025): https://doi.org/10.1093/biomet/asae049
- Turner, Ly and Grünwald, *Generic E-variables for exact sequential k-sample tests that allow for optional stopping* (2024): https://doi.org/10.1016/j.jspi.2023.106116
- Vovk, *Multiple testing in game-theoretic probability* (2024): https://arxiv.org/abs/2403.11767
