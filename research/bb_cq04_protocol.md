# BB-CQ-04: prospective CPU headroom screen for revision-aware ECA-04

**Source/design registration: 18 November 2026, before the first BB-CQ-04 scoring run.** Research-only; BB-CQ-01/02/03 remain fixed. This is an independently authored development experiment, not a new sealed confirmation study. The original ECA-04 16-unit GRU checkpoint SHA-256 is `49bf2db1316942a23b91943843eb0398043c806cadd40421371af571aa15b3d8`. No weights will be changed.

## Objective and actual evidence law

We want a *task-grounded feasibility screen* for maintaining a compact posterior when one or more named, provisionally misrecorded evidence entries are superseded. The ORIGINAL ECA-04 likelihood and priors are held constant: three complementary report channels, `t=(.95,.65,.15)`, `f=1-t`, and `pi=(.45,.35,.20)`. Twelve known-label/report slots per issuer, six known-positive and six known-negative; original chronological order randomized independently of the latent regime.

For each deterministic public development root: sample the host-true latent issuer regime; sample a FINAL authoritative sequence of twelve independent reports under that regime. Independently select a fixed set of `j` superseded slots with `j in {1,3,6}` from the root's pre-data random selection. The provisional report bits in those `j` slots are independent fair bits, unrelated to the authoritative reports and regime. All other slots are unchanged. The later *trusted hypothetical amendment* supplies the named final reports and versions, displacing the provisional records. The finalized accepted observations are therefore drawn from exactly the original ECA-04 likelihood. The old provisional bits carry no additional information about the regime, including when available to an unrestricted reviewer. By design, this avoids a data-dependent correction-selection attack; the replacement slots were selected independently of any outcomes.

The synthetic host holds a per-root key and may re-sign the corrected records; this is a simulator assumption, not real authenticated acquisition. The current-version model treats provisional records as invalidated at an authenticated revision event. Any probabilistic validity claim in a deployed system would additionally require faithful acquisition, authenticated old-to-new amendments, and full-filtration accounting.

## Information contracts and comparison arms

Every arm receives the SAME revised, model-generated root, but accessible memory differs:

1. **FULL_EXACT:** recompute exact rational ECA-04 posterior from all twelve accepted current-version reports.
2. **DELTA_EXACT:** start with a current provisional match count, receive full externally verified old/new bits for amended slots, update count and posterior exactly. Check identity to FULL_EXACT and check full archive replay. Its storage/verifier work remains part of the end-to-end cost.
3. **AGGREGATE_OPTIMAL:** retain only the provisional match count `m_old` plus the number `q` of matches among the `j` new authenticated reports and the public amendment schedule. Recover the *exact Bayesian posterior conditioned on this coarser information*, integrating over unknown provisional old bits. It must be mathematically calibrated to the declared provisional fair-bit process. It receives no older per-slot bits.
4. **NATIVE_REPLAY:** use original ECA-04 frozen 16-unit GRU on the full revised twelve-record sequence.
5. **NATIVE_STALE:** use the original frozen GRU on the provisional report sequence, without amendment replay.
6. **POOLED:** use the original issuer-regime prior without sentinels.
7. **TRUE_REGIME:** privileged host oracle, reported separately from eligible policies.

The source-only exact comparison must independently derive FULL_EXACT from raw public label/report likelihoods and DELTA_EXACT from an externally checked bitmask delta. No baseline may read host-private regimes for decision selection. Archive digest/counters do not themselves establish authentic source identity or remote freshest state.

## Exact reduced-information posterior

Let `u` be the number of matches among the `12-j` unchanged legitimate reports, `v` the provisional matches among the `j` overwritten slots, and `q` the final matches in those slots. The aggregate sees `m_old=u+v` and `q`, with `v|j ~ Binomial(j, 1/2)` independent of `k,u,q`. Its exact likelihood is

```
Pr(m_old,q | k,j)
 = Bin(j,q) t_k^q (1-t_k)^(j-q)
   * sum_(u:0..12-j) Bin(12-j,u) t_k^u (1-t_k)^(12-j-u)
                       Bin(j,m_old-u) 2^(-j).
```

Multiply by `pi_k` and normalize. This is the optimal posterior available from the aggregate-only sigma-algebra, and equals the conditional mean of the fine posterior given the coarse observation. A separately written exact nested-enumeration oracle must reproduce it for small j; all rational results must be matched independently with the actual full current-version observations and DELTA_EXACT.

## Task-grounded score, independent units and controls

One independent unit is one **issuer root** with a true regime and twelve current-version reports. The three `j` arms, two audit outcomes, five candidate priors, report steps, and eight permutations are paired observations within that root, never new replicates. For each policy's channel mixture `(t_hat,f_hat)`, make grant/deny decisions under cost `2 FP + FN`, separately for a positive and negative future candidate-audit report and each of the original five ECA-04 case priors `{1/8,1/3,1/2,3/4,7/8}`. Score exact **expected weighted authorization loss** conditional on the root's hidden regime by summing the joint probabilities of future truth and each audit outcome. Divide by five case priors, so the unit is weighted-cost per case. This integrates out future case/audit noise rather than treating repeated cases as independent roots. A proper regime Brier score against the root's host-true one-hot regime is secondary. The agent never sees that private truth when choosing its actions.

The most important check is an independent *analytical expected-risk enumeration*, integrating over regime, unchanged true matches `u`, provisional matches `v`, and authoritative amended matches `q` using exact rational weights. This yields the exact mean loss for FULL_EXACT, AGGREGATE_OPTIMAL, POOLED and TRUE_REGIME, without any neural model evaluation. It measures whether source-aware provenance can change optimal **downstream actions**, rather than merely moving posterior coordinates.

**Primary preregistered feasibility contrast:** at `j=6`, the exact population expected authorization-cost advantage of FULL_EXACT over AGGREGATE_OPTIMAL, in `2 FP+FN` cost units per future case. The task-headroom threshold is **0.02** cost units per case, reused from ECA-04's earlier practical effect scale. A positive mathematical loss difference below this threshold is a science **HEADROOM_BLOCKED** decision for a larger learned-revision neural study under this task contract.

**Secondary comparisons:** same contrast for `j=1,3`, exact Brier differences, and development-only NATIVE_REPLAY minus NATIVE_STALE and NATIVE_REPLAY versus FULL_EXACT for each `j`. The provisional-data distribution is different from original ECA-04 training; native weights remain untouched. Compare complete expected loss and regime-score calibration on the same roots. Report any class action changes and calibration defects, without claiming a causal feature has been found.

## Frozen development cohort and sham

Use **64 public deterministic calibration roots** under domain `bb-cq04/v1/calibration/` and **256 disjoint public deterministic pilot roots** under `bb-cq04/v1/pilot/`, each `SHA256(domain + integer_index)` and expanded through a deterministic versioned Python RNG. These counts, generator, and public source are chosen before scoring. A protected new OS-random confirmation cohort remains unsampled. Every root has all three `j` arms, with nested slot order chosen before observations are viewed.

The main physical sensitivity control is a full revised-stream **order nuisance**: eight separately generated permutations of the same corrected reports, leaving its exact Bayesian posterior invariant. Calculate the mean root-level maximum native output/decision shift from permutations and a calibration envelope from the separate 64-root set, retaining the strongest observed nuisance variation as a conservative development floor. Because these roots are public deterministic fixtures, this is an engineering variation diagnostic and **not** a claimed 95/95 statistical tolerance certificate. A real statistical mechanism preflight would need at least 59 independent *new* calibration worlds and a defined effect above their matched-sham floor.

For the native 256-root pilot, report one paired root-level bootstrap interval using 4,096 seeded resamples of issuer roots; descriptive only, because this is one publicly reproducible selected development generator. Every arm, including negative and discarded ones, must remain in the receipt.

## Pass/fail gate

1. **ENGINEERING_PASS** requires frozen checkpoint SHA, distinct public root IDs, no use of historical ECA-04 heldout seeds, exact FULL_EXACT == DELTA_EXACT for every pilot/root/arm, independent formula equivalence for AGGREGATE_OPTIMAL, exact nonnegative population information advantage and finite native outputs. Invalid/stale archive deltas must fail.
2. **HEADROOM_PASS** requires exact `j=6` authorization-cost gain of FULL_EXACT over AGGREGATE_OPTIMAL at least **0.02**. If it fails, issue `HEADROOM_BLOCKED`, report the precise smaller effect and stop before any protected neural study.
3. **NEURAL_MECHANISM_NOT_TESTED** always applies to this readout. Native input changes and nuisance permutations supply a diagnostic, not physical rank-/dose-matched activation intervention, recovered causal fibers, or a calibrated 95/95 sham null. Any later learned-state causal claim requires a separately registered experiment and the EvalMath independent-root/effect-floor preflight.

## Source freeze and reproduction

The research branch must first commit this protocol, the exact rational enumeration, the native runner and source-only tests. Verify their hashes, run source-only CI, then execute the first deterministic development scoring run. No adaptation of the protocol or selection after inspecting its native results is permitted within this experiment ID. If tests expose a bug, amend source with a recorded pre-readout correction before the first pilot, or preserve the original failure and issue a new experiment ID after first readout.

The exact result receipt will be independently replayed by GitHub CI. The native PyTorch checkpoint is an external original artifact and must be supplied by a caller, SHA-checked, with output hashes recorded. GitHub CI should verify source-only invariants without downloading historical heldout rows.
