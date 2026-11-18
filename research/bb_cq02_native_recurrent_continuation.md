# BB-CQ-02: Prospective native recurrent continuation and revocable evidence

**November 18, 2026 | Research note / source-stage registration.** Companion implementation: [Control-Harness draft PR #67](https://github.com/MoralityLabAI/Control-Harness/pull/67), with its protocol committed before the native experiment code. This note follows [BB-CQ-01](continuation_quotient_bridge_v0_1.md). No BB-CQ-02 heldout result is claimed from a source-only branch.

## 1. Transfer question

BB-CQ-01 proves a finite deterministic criterion for exact continuation-preserving state compression. Recent BPD observable-quotient results show that a direction invisible to a current readout can affect a later recurrent readout. BB-CQ-02 takes that implication to a genuinely trained recurrent inference model, using the existing 16-hidden-unit ECA-04 issuer-regime GRU.

The model receives twelve authenticated-in-the-synthetic-host, gold-labeled sentinel report pairs and predicts a distribution over three registered reliability regimes. Its original source-frozen evaluation found 777 weighted task-loss units for the GRU and 776 for an exact Bayes arm, each over 3,072 heldout case decisions. The original evaluation cohort is historical evidence, never reused to select or report a new BB-CQ-02 effect.

For frozen GRU hidden state `h6` after six sentinel observations, let `W in R^(3x16)` be the original classifier and let `D` contain the differences between its first two rows and its final row. If `rank(D)=2`, the Euclidean orthogonal projector `P=D^T(DD^T)^(-1)D` has rank two. The reduced physical state `P h6` exactly preserves all present class-logit **differences**, and thus present softmax probabilities, in exact arithmetic.

The prospective neural test is whether this **present-readout quotient** also preserves the next six native recurrent updates and the eventual synthetic case-inspection decisions. Test `h6`, `P h6`, and two separate randomly oriented `ker(D)` interventions with physical L2 norm exactly `||(I-P)h6||`. Advance all four states through the same six future sentinels with the *frozen* GRU. The original 12-event full-history recurrent run supplies the task-observation reference.

A patch that matches the present posterior can depart immediately during future recurrence. This is the neural analogue of BB-CQ-01's delayed swap witness. The projected state is **not** an assumed manifold-valid recovered state: record its size and compare equal-dose nullspace shams. The original teacher is one trained model, so source replications alone cannot support generalization to a population of independently trained models.

## 2. Exact posterior vs revocable provenance

Under the stipulated three-regime conditional evidence family, a two-dimensional vector of posterior log odds is an additive sufficient statistic for **appending** independent, conditionally specified observations. For regime `k`, a posterior after observed events `e_1,...,e_t` is

```
pi_t(k) = prior(k) * product_i P(e_i | regime=k) / Z_t.
```

After a provenance group `g` is revoked, that group must be removed from the likelihood product. Under this model, retain a group-indexed likelihood factor `L_(g,k)` with an active flag, and compute

```
pi_active(k) = prior(k) * product_(g active) L_(g,k) / Z_active.
```

A current posterior alone generally fails to disclose which source groups contributed its probability mass. Distinct evidence histories can therefore have the same current posterior while requiring different revised posteriors after a named group is revoked. This is continuation-distinguishability under a richer event alphabet. An accessible lossless archive and replay are a legitimate full-history baseline.

The proposed source experiment divides the ECA-04 twelve shuffled sentinels into three explicitly declared *evidence bundles*, with sizes 3, 3 and 6. It revokes one of the two prefix bundles, chosen by a hash of the issuer ID before reading the noisy evidence. The source-aware ledger is checked against an independently recomputed exact rational posterior on the remaining nine events. A stale posterior retains all twelve events. A frozen GRU replay over nine surviving events is included as a model-family control, with its changed sequence length explicitly outside the GRU's original 12-step training support.

Each bundle is a **revocable provenance segment within one issuer**, sharing the same latent regime and host issuer authority. These are not independently attested physical source roots. The ledger's exact arithmetic exercises the stipulated conditional-likelihood algebra. Any real-world source revocation requires its own authority and trustworthy history.

## 3. Frozen prospective measurements

The [implementation protocol](https://github.com/MoralityLabAI/Control-Harness/blob/research/bb-cq02-frozen-recurrent-projection/docs/bb_cq02_prospective_protocol.md) fixes:

- **Pilot units:** 64 new independently generated synthetic blocks, each with four or five issuers and 24 cases, source-disjoint from every archived ECA-04 train/validation/heldout root. All work on the original teacher checkpoint is fixed-weight.
- **Primary effect:** block-averaged `TV(shamA,frozen_full)-TV(rank2,frozen_full)` at the final recurrent step; positive favors the rank-two projection. The minimum meaningful gain is 0.02 TV per issuer, with approximate closure target at projected mean TV <= 0.05.
- **Sham resolution:** a second independent equal-dose readout-null sham; the maximum across 64 independent block-mean sham disagreements estimates a conservative 95th-percentile variation envelope under independent exchangeable block draws. This bounds **variation of this registered matched-sham statistic**, not all adversarial neural directions.
- **Behavioral controls:** identical six-audit/24-case policies, after seeing the same sentinel evidence, score cost-2 false approvals and misses using the synthetic host's withheld truth. Total sentinel acquisition and candidate-audit costs are included in the reporting. Exact Bayes full-history and source-factor replay are explicit comparators.

The strong baseline uses **all allowed historical evidence**. A Bayes procedure with group-indexed factors and the same observation contract can match the exact source-revocation response. The scientific target is which memory representation and native update closure is computationally reliable under known cost and information limits.

For confirmatory promotion, require the pilot primary improvement to exceed both 0.02 and the calibrated sham-variation floor, plus approximate closure. A successful source pilot can authorize a *new* sealed registration, rather than an immediate general mechanistic claim. Negative or below-resolution pilot evidence stops the studied compression family. Record per-block effects and all controls even when the proposed projection fails.

## 4. Theorem and experiment boundaries
### Local closure criterion for the rank-two neural quotient

Let `q(h)=D h` with full-row-rank `D`, and consider one fixed, input-conditioned differentiable recurrent step `F_e(h)`. On a convex domain of hidden states, exact one-step closure through `q` is equivalent to

```
D * J_(F_e)(h) * v = 0    for every h and every v in ker(D).
```

**Proof.** If `q(F_e(h))` depends only on `q(h)`, take any null direction `v` and differentiate the constant composite `q(F_e(h+t v))` along its allowed fiber. Conversely, integrate the assumed vanishing directional derivative along the segment from `h` to `h+v`: the fundamental theorem of calculus gives `D(F_e(h+v)-F_e(h))=0`. Thus `q(F_e(h))` is constant on each nonempty convex fiber, yielding a well-defined reduced map on `q(domain)`.

The quotient must satisfy this for **every admissible next input** `e` to support the whole declared future event language. When the reachable domain is nonconvex, only the forward implication is automatic without a suitable path-connectivity condition. For finite-step approximate tests, bounds on the derivative along the actual patch segment plus Lipschitz control of subsequent reduced dynamics are needed to turn local tangent loss into a multi-step error budget.

BB-CQ-02 measures one native six-event continuation after a physical displacement in `ker(D)`; positive task drift therefore supplies an empirical **fiber-collision witness** at that dose and horizon. It does not measure the Jacobian condition for every state, prove a global impossibility theorem, or assert that this particular orthogonal projection is optimal among all 2D sufficient statistics. The criterion is a standard differentiable factorization condition, applied here to the frozen GRU's readout fibers. It complements BPD's finite-horizon stacked observability result.


The finite BB-CQ-01 theorem applies to **total deterministic machines with a declared event alphabet**. The neural GRU is a continuous nonlinear stochastic-input system; the source test measures one fixed horizon and one task. Current-logit preservation for the rank-two projection follows directly from linear algebra; its future effectiveness is a causal empirical question.

BB-CQ-02 is not a new error guarantee for ACE v0.10. Its published receipt carries `authorizes_action: false`, and it never touches the existing `ScopeActionGate`, `CampaignActionGate`, rooted measurement protocol, null-model assumptions, alpha accounting or registry. Signed source messages authenticate the synthetic simulator under explicit host trust. Any e-process requires validity against the actual information filtration, including covert feedback, adaptive selection and source admission.

A useful successor would test whether a smaller **source-aware, continuation-closed** learned representation handles append, revocation and recalibration operations at matched acquisition/compute cost. It would need new trained-model seeds, independent source roots and EvalMath causal sham/power gates. Findings on exact finite likelihoods do not imply a successful neural quotient.

## 5. Reproduction and provenance

Companion PR: https://github.com/MoralityLabAI/Control-Harness/pull/67

Source-only tests:

```sh
PYTHONPATH=src python -m unittest tests.test_bb_cq02 -v
```

The first evaluation is eligible only after a separately committed one-file source-freeze request. The canonical archived ECA-04 teacher is artifact `14355808052`, workflow run `44145067899`, checksum-bound to the original readout receipt; training/validation/heldout source seed bytes are excluded from the new cohort. The source code discloses all fixed seed derivatives used for shams and revocation selection.

**Current evidence class:** exact algebraic continuation counterexamples and source-only engineering preflight. The numerical neural result requires the separate registered first-development readout and independent replay.
