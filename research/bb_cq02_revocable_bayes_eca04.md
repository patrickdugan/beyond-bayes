# BB-CQ-02: Revocable Bayesian sufficient states and the frozen ECA-04 recurrent model

**18 November 2026 | Stacked research extension after BB-CQ-01.** Source provenance: [Control-Harness ECA-04](https://github.com/MoralityLabAI/Control-Harness/blob/main/reports/eca04_registered_readout.md), [ECA-04 original model source](https://github.com/MoralityLabAI/Control-Harness/blob/main/src/evals/eca04_recurrent_issuer.py), [BPD-ECA-02](https://github.com/MoralityLabAI/Control-Harness/blob/main/reports/bpd_eca02_development_result.md), and [BPD-ECA-06 engineering](https://github.com/MoralityLabAI/Control-Harness/blob/main/reports/bpd_eca06_engineering_dual_transport.md). The ECA-04 weights are frozen, original SHA-256 `49bf2db1316942a23b91943843eb0398043c806cadd40421371af571aa15b3d8`.

**Status:** exact rational deterministic theorem and finite verification; a separately identified frozen **native** GRU development demonstration on publicly reproducible hash-generated fixtures. No source-blind statistical confirmation, newly formalized Lean theorem, real-world provenance, or action authority. All contributions keep ACE v0.10 gates untouched.

## 1. Corrected epistemic target

The original ECA-04 three-channel issuer calibration likelihood uses a known gold bit `y`, a noisy report `r`, and independent draws conditional on issuer regime `k`. The channels satisfy `f_k = 1-t_k` with

```
priors:             [0.45, 0.35, 0.20]
t_k:                [0.95, 0.65, 0.15]
false positive f_k: [0.05, 0.35, 0.85]
```

A report matches its known gold bit with probability `t_k` whatever the value of that gold bit. For `n` current admitted reports with `m` matches,

```
  P(k | observations) =
     pi[k] * t[k]**m * (1-t[k])**(n-m)
       / sum_j pi[j] * t[j]**m * (1-t[j])**(n-m)
```

This is exact *conditional on the sensor law and host's gold labels*. With fixed `n`, the match count is a sufficient statistic for the exact Bayesian posterior. After revocations, both `m` and `n` matter. For future individually revocable sources, a current `(n,m)` or its posterior discards the attribution needed to update correctly.

ECA-04's actual twelve sentinels are all HMAC-signed by **one issuer root**. The separate `evidence_group` declarations in BB-CQ-02 are a deliberately synthetic extension and **do not** imply new independent signers or statistical fault domains. A real ACE integration requires externally attested grouping and the original v0.10 measurement/filtration preconditions. Our `Ledger` authenticates no keys. It implements an exact conditional mathematical model only.

## 2. Exact continuation-state theorem

Fix `g` labeled evidence groups, initially with one observation each. Each group state is `M` (active mismatch), `H` (active match), or `X` (revoked). A future event `revoke:i` removes all of group `i`'s contribution; repeated revocation is idempotent in this **abstract machine**. The output is the exact posterior vector, represented by rational strings.

**Proposition A (revocation memory):** all `3**g` states have distinct future-output continuations. The minimal deterministic continuation-sufficient state count is exactly `3**g`, and an arbitrary fixed-length binary code needs at least `ceil(g*log2(3))` bits. For the `2**g` histories with all groups still active, the current posterior takes only `g+1` possible values, yet the histories are pairwise continuation-distinguishable and need at least `g` bits.

**Proof.** Take distinct group-state vectors `s,t`; choose a group index `i` at which they differ. Revoke all other groups. Their resulting posterior is respectively one of the three values `P(prior)`, `P(prior | match)`, or `P(prior | mismatch)`. These are pairwise different because ECA-04 priors are positive and the likelihood ratio varies across its three channels. The same event suffix thus distinguishes `s,t`. Storing the full trit vector attains the bound. All-active vectors vary by match bit, giving the `g`-bit restriction. This is the classic continuation-equivalence argument under a concrete likelihood law.

**Proposition B (new evidence and admissibility):** add `N` (unobserved) to the group states, allow one `observe:i:0/1` per group and single-use `revoke:i`, and send illegal events to an absorbing `INVALID` state with a separate output. For this exact contract, all `4**g+1` states are continuation-distinct, requiring `ceil(log2(4**g+1))` bits. For two or three groups this is checked exhaustively by BB-CQ-02; the general proof follows by either observing a previously unobserved group, testing the legality of a repeated revocation, or revoking every other group to distinguish active match/mismatch. Invalid event admissibility is part of the contract.

The two machines have *different* duplicate-revocation semantics: static idempotence permits a convenient fixed-roster theorem; the prospective machine matches `Ledger`'s one-shot event contract and totalizes invalid histories. Quotient claims transfer only when event and legality contracts match.

## 3. Exact finite development results

| Independently revocable groups | Revocation states | Distinct current posteriors | Minimal total bits | Extra tag bits retaining current posterior |
| --- | ---: | ---: | ---: | ---: |
| 1 | 3 | 3 | 2 | 0 |
| 2 | 9 | 6 | 4 | 1 |
| 3 | 27 | 10 | 5 | 3 |
| 4 | 81 | 15 | 7 | 4 |
| 5 | 243 | 21 | 8 | 5 |

The extra bits are calculated using the BB-CQ-01 stable online refinement formula. Each posterior fiber contains `C(g,n)*C(n,m)` states (choose `n` active groups and `m` matching groups). The maximum fiber contains 30 states for `g=5`, requiring five extra binary tag bits if the exact posterior label is retained as part of state. This *total* representation need not attain the most compact global binary encoding.

For the prospective `observe/revoke` contract, `g=2` has 17 continuation classes (5 minimal bits) and `g=3` has **65** (7 minimal bits), including the illegal-event sink. The present output has respectively 7 and 11 classes. The exact test suite checks independent full-event likelihood replay against per-group `(n,m,revoked)` counts, checks source revocations/erasures and validates the quotient using an independently implemented pair-product BFS. The committed [exact receipt](../results/bb_cq02_exact_v1.json) records 2,431 independently checked pair comparisons, zero discrepancies, and no neural checkpoint access for this finite portion.

A one-step collision between vectors `011` and `101` has the same current posterior (two matches among three reports). Revoking group 0 produces different posteriors. This is an *exact Bayesian* counterexample to compressing the source history into the current posterior when source-level revocation is allowed.

## 4. Frozen ECA-04 native development observation

The [original ECA-04 archival artifact](https://github.com/MoralityLabAI/Control-Harness/actions/runs/44145067899/artifacts/14355808052) was obtained and independently checked: ZIP SHA-256 `b8c0c3687d1a8e7a039fd256db88572a17db85ea86e5271c1a56fb5a9c629b13`; embedded `gru_state_dict.pt` SHA-256 exactly `49bf2db1316942a23b91943843eb0398043c806cadd40421371af571aa15b3d8`. The checkpoint contains the original PyTorch `GRU(2,16)` and linear three-regime classifier.

The [native source code](../native_eca04_continuation.py) defines **256 public SHA-256-derived development issuer fixtures**. Each has six gold-positive and six gold-negative reports and a known synthetic issuer channel. The first six public events are inspected only to find an opposing pair: one matching, one mismatching. If such a pair exists, the hypothetical host flips **both** report bits and HMAC re-signs their respective records, leaving all gold labels, record positions, other reports and the last six events fixed. This conserves the number of matches in the prefix and full twelve-step history. Every pair has *exactly the same* original Bayesian regime posterior, before and after revision, for the six-step prefix and complete twelve-step observation. The host's signing key is derived from a public fixture seed solely for synthetic testing; it is not a realistic authority root.

The first frozen-checkpoint CPU development run on PyTorch 2.10.0 produced:

| Measure | Original development result |
| --- | ---: |
| Public deterministic root candidates | 256 |
| Pairs with opposing first-six match statuses | **152** |
| Predeclared ineligible roots (no opposing pair) | 104 |
| Exact Bayesian prefix/full posterior equality | 152/152 |
| Pairs with max native final-logit difference greater than 1e-6 | **152/152** |
| Mean max native logit difference | **0.256572** |
| Median max native logit difference | 0.198014 |
| Maximum max native logit difference | 1.277648 |
| Mean three-class predictive total variation | **0.023713** |
| Max predictive total variation | 0.204028 |
| Mean six-step hidden-state L2 separation | 0.616612 |
| Changes in argmax regime class | **3/152** |
| Max full-forward vs six-step-prefix/suffix parity error | 0.0 |

The first public root SHA-256 is `bd4dfecbe41121d2f7047295da956cbecb3d453c5f20025292cfc64e6f1cf00b`. Flip positions 1 and 5: the exact Bayes match count stays fixed, while original final native logits approximately `[3.61502,1.30371,-7.79510]` become `[4.16411,1.11202,-8.14994]`. The final model reads the exact same last six public observations in both arms; full/split recurrent forward parity passed.

**Interpretation:** under this synthetic authenticated-reissue interface, the frozen GRU's output retains distinctions that the ideal complementary-channel Bayesian posterior discards. This establishes a *specific, native-model output counterexample* to treating the exact Bayesian posterior as a continuation-sufficient representation for the GRU's own logits. It does not show that the extra information improves decisions against host truth. Only three eligible pairs changed the top regime classification. The public deterministic fixture is a chosen development diagnostic; its rows do not constitute 152 fresh independent scientific replications or support a causal mechanism claim. The matched corrections themselves intentionally introduce a correlation absent from the original IID data generator.

## 5. Relation to BPD, compactification and ACE

- The exact posterior's memory requirement and the GRU's output-state requirement are **different contracts**. Reconstructing the exact posterior under revocation needs source-group provenance; reconstructing frozen native logits may additionally require the ordered sequence or a certified dynamical quotient.
- BPD-CQ-01 delayed observability warns that invisible present-state changes may appear at future readouts. The present native prefix/suffix test makes that issue measurable in a frozen recurrent model without claiming a uniquely identified intervention basis.
- BPD-ECA-02 and -03 failed preregistered causal-resolution gates. BPD-ECA-06's development-only engineering saw a strong posterior-decoder plane but weak native output-transport fidelity relative to its complement. BB-CQ-02 adds a **future evidence revision** distinction and is methodologically separate from those projector studies.
- ACE v0.10's sequential error bound is conditional on the full actual information filtration and valid enrolled source groups. This module proves no new false-authorization probability bound, source authentication property or action gate safety guarantee.
- A matched exact-Bayes historical replay is the proper comparator and reproduces the grouped counts exactly under the declared model. A GRU output discrepancy alone should not count as extra epistemic correctness.

## 6. Next experiment and registered stopping conditions

A future **BB-CQ-03** may study learned compression under source revision if it first clears a meaningful behavioral effect threshold. The native development sample showed only 3/152 changes in the model's argmax reliability decision, so a study whose endpoint is authorization performance may lack headroom. Require an independent task-headroom screen before spending new protected roots. Freeze the new evaluator, group labels, amendment validity, source/model hashes, outcome, selection process and computational budget **before** any fresh OS-entropy cohort.

The three baselines should include a strong full-history exact Bayesian reviewer, a source-aware sufficient-statistic reviewer with group-level counts, and the frozen native GRU replay. If a learned summary is added, compare future **task-grounded** decision loss after source updates against those controls. Use independently generated issuer roots as the unit, register the effect floor and shams using EvalMath, and preserve a genuinely sealed confirmation cohort. An observational difference between hidden states or logits is a development finding. Stop confirmatory promotion when downstream headroom or the calibrated effect resolution is below the proposed mechanism threshold.

## Reproduce

```sh
python -m unittest test_revocable_bayes test_native_eca04_continuation -v
python benchmark_revocable_bayes.py --check results/bb_cq02_exact_v1.json

# Obtain gru_state_dict.pt from the pinned original ECA-04 artifact.
# Requires PyTorch; computes deterministic development fixtures, never ECA holdout.
python native_eca04_continuation.py \
  --checkpoint /path/to/gru_state_dict.pt \
  --output /tmp/bb_cq02_native_development.json
```

The [BB-CQ-01 continuation quotient](continuation_quotient_bridge_v0_1.md) is a dependency of the finite module; this PR is stacked until BB-CQ-01 merges. Hosted default CI runs the complete pure-Python suite and exact receipt replay. Native PyTorch replay requires the externally supplied original weights, pinned by SHA-256; the corresponding development numbers were measured locally, and must not be described as hosted verified until a separate native replay exists.
