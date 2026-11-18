# BB-CQ-03: Amendment memory, external verification and exact posterior loss

**Research addendum, 18 November 2026.** A bounded, source-only next step from [BB-CQ-01](continuation_quotient_bridge_v0_1.md) and [BB-CQ-02](bb_cq02_revocable_bayes_eca04.md). The mathematical setting is the ORIGINAL ECA-04 single-issuer, twelve-report complementary-channel law, with externally defined record corrections. [Code](../amendment_memory.py) · [tests](../test_amendment_memory.py) · [deterministic receipt](../results/bb_cq03_exact_v1.json) · [Lean arithmetic kernel](../lean/ACE/AmendmentMemory.lean).

**Status:** finite elementary theorem, exact rational conditional decision-risk identities, exhaustive bitmask checks and small deterministic archive simulator. The Lean file proves only its explicitly stated deterministic arithmetic implications; the general 12-bit bound and rational probability identities remain paper proofs with finite executable verification. This research does not authorize actions, certify an actual sensor, or establish a trained-model mechanism. The previously frozen ECA-04 weights are unchanged and unused in BB-CQ-03.

## 1. Why this version matches the original issuer interface

Original ECA-04 signs all twelve public label/report sentinels under ONE synthetic issuer key. BB-CQ-02's separately revocable groups were a helpful generalization, but treating those groups as independently authenticated sources would misdescribe the ECA-04 host. BB-CQ-03 returns to a single issuer and considers **individually addressable report corrections**.

Let each of twelve public known-label/report pairs have a match bit `b_i=1[label_i=report_i]`. Under ECA-04's three latent sensor regimes with prior masses `(0.45,0.35,0.20)` and matching probabilities `(0.95,0.65,0.15)`, the exact conditional likelihood of a history is

```
P(k | history) = pi_k t_k^m (1-t_k)^(12-m) / Z,
m = sum_i b_i.
```

For the original twelve unamended records, `m` is a statistically sufficient posterior state. Replacing the report at one named slot `i` by a new stipulated match bit `c` changes the match count to `m' = m - b_i + c`. This is a **revised-data likelihood**; unless the amendment-generation process is independently modeled, it should not be interpreted as the posterior conditioned on having observed a strategically selected correction.

The distinction matters: an authentic origin signature does not itself prove a correction is the latest, an old value was removed, or a source was statistically independent. An actual ACE adaptation must anchor record identity, versions, complete prior records and revision chronology in a relying-party/witness contract.

## 2. Exact self-contained memory lower bound

**Proposition 1 (single-step distinguishing corrections).** Fix `n` named slots with initially observed binary match statuses `b ∈ {0,1}^n`. Define current output `D(b)=P(k|sum_i b_i)` for the registered complementary family. A future amendment event `REPLACE(i,c)` supplies a slot index and its *new* bit `c`, with no authenticated old bit exposed to the compressed-state updater. Two different histories with the same current posterior have a one-step distinguishing future amendment. Consequently every one of the `2^n` original bit vectors is in its own continuation class; an exact self-contained fixed-length state needs at least `n` bits. A bitmask meets the bound.

**Proof.** ECA-04's posterior odds between regimes 0 and 1 are strictly monotone in `m`, since the odds slope is `[t_0/(1-t_0)]/[t_1/(1-t_1)] ≠ 1`. Histories with different counts already have different current outputs. If `b ≠ b'` and their counts agree, select a slot `i` where they differ. Under one common replacement value `c`, the updated counts differ by one because `m-b_i+c ≠ m-b'_i+c`. Hence their updated posteriors differ. Storing the full bitmask is a valid updater, proving attainability. `∎`

**Corollary (posterior-plus-tag memory).** At fixed `m`, the current posterior fiber has `binom(n,m)` distinct histories, so retaining the current posterior requires an extra uniform tag of at least `ceil(log2 max_m binom(n,m))` bits for an exact named-amendment updater. For `n=12` the largest fiber contains **924** masks (six matches), requiring **10 additional tag bits**. A direct globally encoded bitmask uses 12 bits total, whereas a representation retaining an exact posterior label carries the posterior's own representation cost as well.

This bound concerns future named corrections in a declared model. It does not count additional archive/signature bytes, authentic event delivery, mathematical precision needed to store posterior probabilities, or an ability to infer hidden source truth.

## 3. Sharp approximation risk when the agent stores only m

Consider the original IID-mixture distribution of twelve match statuses. Conditional on count `M=m`, any fixed named old bit is 1 with probability `w=m/12`, by exchangeability. Independently choose a new stipulated match bit `c ∈ {0,1}` with equal probability. A count-only observer receives `(m,i,c)`, without the original `b_i`, and predicts the exact **revised-data Bayesian posterior** as a three-dimensional vector.

Write `p_0=P(k|m+c)` for the case `b_i=0` and `p_1=P(k|m-1+c)` for `b_i=1`, with zero-mass impossible cases omitted at the edges. Under squared Euclidean error relative to the revised-data target, the unique conditional optimal prediction is `r=(1-w)p_0+w p_1`.

**Proposition 2 (sharp source-blind Brier-vector floor).** The minimum conditional expected squared posterior-vector error is

```
R*(m,c) = w(1-w) ||p_0-p_1||_2^2.
```

**Proof.** Expand `(1-w)||p_0-r||² + w||p_1-r||²` around the weighted mean `r`. The cross terms vanish, leaving `w(1-w)||p_0-p_1||² + ||r-r*||²`. Thus the displayed bound is attained by `r=r*`. `∎`

This is **squared-L2 vector imitation loss**, distinct from the mean-TV lower bound for imitating native GRU outputs in BB-CQ-02. Both are metric-relative statements about different targets and evaluation families. A direct quantitative comparison would be misleading.

Under the stated synthetic design, the exact expected floor is

```
R*_12 = (1/2) sum_(m=0)^12 P(M=m)
             [R*(m,0)+R*(m,1)]
      = 0.012832873470... .
```

The value is computed as a Python `Fraction` and rounded for the human receipt. At `m=6`, the exact conditional risks for stipulated replacement `c=0` and `c=1` are approximately 0.009747684361 and 0.000116304240, respectively. Source-aware exact replay has zero imitation loss in this finite calculation. The risk difference is fixed by the information contract; it is not a newly observed neural performance gain.

## 4. An external verified-delta bridge moves the memory

An agent storing only `m` can update it after an external verifier supplies an authenticated old-to-new change `delta=(i,b_i,c)` and establishes that the old value is the record currently stored at slot `i`. The internal update is simply `m' = m-b_i+c`; the separately pinned external archive supplies the missing slot-specific state.

**Proposition 3 (conditional sufficiency given a verified delta).** If every emitted delta is checked against the authoritative current version of the named record and revisions are serialized, the count `m` is sufficient to maintain the exact revised-data posterior for any sequence of accepted deltas. This follows by induction on the number of accepted revisions. The state obligation has moved into an external verifier, whose records and live version must be audited and counted in end-to-end resource costs.

The [toy archive](../amendment_memory.py) stores match bits, per-slot versions, and a digest of the entire state. It returns a typed `EvidenceDelta` containing old/new bits, version step, and before/after digests. `verify_archive_delta` checks the entire predecessor/successor archive. The numerical-only updater requires a caller-held old digest and assumes the external check took place.

**Intentional falsifier:** an actor who forges an old bit can deceive the numerical-only count consumer even while presenting the same digest labels; the independent full-archive verifier rejects the change. No signing infrastructure has been added here. Digests are commitments and do not establish freshness or an authorized source. ACE's v0.10 witnessed enrollment, measurement ordering and action policy remain separate components.

## 5. Finite verification

The committed [development receipt](../results/bb_cq03_exact_v1.json) includes:

| Test / property | Result |
| --- | ---: |
| Full 12-bit initial histories | 4,096 |
| Current exact posterior classes | 13 |
| Largest one-posterior fiber | 924 |
| Exact source-aware amendments, all masks, slots and replacement bits | **98,304** |
| Independent one-event witness pairs in exhaustive 8-bit domain | **6,307** |
| Same-count 12-bit pairs from exact binomial identity | 1,350,030 |
| Self-contained exact memory minimum | **12 bits** |
| Extra bit budget given current posterior | **10 bits** |
| Aggregate-only minimum expected squared posterior-vector error | **0.012832873470** |

The test suite also exhaustively checks the independent conditional risk oracle on every mask at `n=1..6`, cross-checks the source IID mixture and total expectation by a second enumeration, and includes positive and negative archive-correction/replay controls.

`lean/ACE/AmendmentMemory.lean` uses Lean's core arithmetic solver to prove old-value subtraction identities and that opposite old bits produce distinct new counts under the shared replacement. It makes no claim of a Lean proof of the full automata or Bayes theorem. The same implementation is still research-only; all returned endpoints have `authorizes_action=false` and no protected issuer cohorts were sampled.

## 6. Implications for the next neural mechanism study

BB-CQ-02's frozen ECA-04 native GRU had 152/152 deterministic compensating-correction pairs with altered logits but identical exact Bayesian posterior, only 3/152 changing top-regime class. BB-CQ-03 establishes an orthogonal issue: under named corrections, the **ideal** posterior alone lacks the old record needed for an exact update. One can supply that record from an authenticated archive and recompute without changing model weights. This is a memory-placement theorem, not evidence that the original GRU has learned revocation or revision semantics.

A BB-CQ-04 neural study would need a genuinely discriminating endpoint after independently authenticated report amendments, adequate headroom over a full-history exact Bayes reference, and a matched information/compute budget. Register independent issuer roots, a blinded correction process, task-grounded cost, a science effect floor and matched sham calibration before sampling any new cohort. Compare full replay, verified delta update, current-posterior-only approximation and the frozen GRU's native continuation. The external verifier's storage and work belong in the accounted budget; the mathematical exact-Bayes reference remains the correctness ceiling under its specified channel model.

The present exact CPU model can be merged once its source-only Python and new Lean kernel checks pass. A failed causal headroom or resolution screen in the subsequent neural design would block confirmation; the ECA-04/05 original heldouts and the BPD protected populations remain sealed.

## Reproduce

```sh
python -m unittest test_amendment_memory -v
python benchmark_amendment_memory.py --check results/bb_cq03_exact_v1.json
python -m unittest discover -q
# CI also runs: lean lean/ACE/AmendmentMemory.lean
```
