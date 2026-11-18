# BB-CQ-05: calibrated posterior recovery and disclosure timing

Design registration: 18 November 2026. Base: `715a015a85778c9e8091978e6ca542684f93135c`.

## Question and evidence status

How much information must a compressed Bayesian state retain when the identities
of provisional observations become available after compression? How much of the
resulting posterior loss can a verifier repair by supplying old report values?

BB-CQ-04 already reports the exact six-replacement Brier gap
`0.064462690845` between its mixed-count and full-information posteriors. That
observed result motivates this choice of endpoint. BB-CQ-05 is an exact finite
mathematical development study; the earlier result is prior knowledge, and this
registration does not turn the new analysis into an independent confirmation.
BB-CQ-04's `HEADROOM_BLOCKED` authorization verdict remains fixed.

This experiment uses rational enumeration and synthetic archive fixtures.
It samples no new roots and performs no neural inference or training. The scope
includes a mathematical proof, independent small-domain enumeration, a complete
disclosure-risk curve, and a source-hashed receipt replayed by CI.

## Generative law and two disclosure times

Use the original ECA-04 regime prior `(9/20,7/20,1/5)` and match probabilities
`(19/20,13/20,3/20)`. There are `n=12` known-label/report slots. The match bit
is the complete likelihood-bearing observation under this complementary-channel
model. For each `j in {1,3,6}`, select a uniformly random set `S` of `j` slot
indices independently of the regime and all outcomes, before drawing data.

Let `K` denote the latent regime. At slots outside `S`, the old match bits are
independent Bernoulli draws with probability `t_K`; at slots in `S`, the old
bits are independent fair bits. Accepted replacement bits at slots in `S` are
fresh independent Bernoulli draws with probability `t_K`. All these variables
are conditionally independent given `K,S`. The final accepted twelve bits have
the original ECA-04 law.

The source host knows `S` from the start. Its disclosure to a predictor is fixed
separately:

* **EARLY_SCHEDULE:** the predictor sees `S` before compressing the old vector.
  It may discard the provisional bits and retain the valid match count `u`
  among `n-j` informative observations. Each accepted replacement adds one
  observation and its match bit. This calibrated count-state baseline must
  equal full Bayes at every step.
* **DELAYED_SCHEDULE:** the encoder sees the old vector `x`, `n`, and `j`, but
  does not see `S`. It compresses before `S` is disclosed. Its initial calibrated
  posterior is a function of `m=sum(x)` because the uniformly hidden schedule
  makes old vectors exchangeable. At correction time it receives `S` and all
  accepted replacement bits, summarized by their count `q`. The count-only
  arm has discarded the old values at named positions. The full-history arm
  still has them.

These are distinct information contracts. Neither changes CQ04's numeric result;
CQ04 did not specify the timing of its public amendment schedule. A claimed
memory requirement must name the timing contract.

## Progressive disclosure and exact posteriors

For delayed disclosure, reveal the old bits at the first `r` corrected positions
in an outcome-independent ordering of `S`, for each integer `0 <= r <= j`.
The order is fixed before data, and the reveal budget is fixed before outcomes.
Let `s` be the revealed old match count, `u` the valid unchanged count, and `w`
the hidden old match count at the remaining `j-r` corrected positions. Then
`m-s=u+w`. The recovery posterior is

```
p_r(k | m,q,s,j,n) proportional to
  pi_k * Bin(j,q;t_k)
       * sum_u Bin(n-j,u;t_k) Bin(j-r,m-s-u;1/2).
```

Here `Bin(a,b;p)` is a binomial probability mass, zero outside `0 <= b <= a`.
The independent factor `Bin(r,s;1/2)` cancels when normalizing. The predictor
can compute this posterior from two counts `(m-s,q)` plus public stage metadata.
Its count state does not authenticate the revealed old bits.

**FULL_EXACT** uses `p_full(k)=Pr(K=k | u+q,n)`.
**COARSE_OPTIMAL** is `p_0`, with the identical information contract and exact
likelihood as CQ04. **RECOVERY_r** uses the formula above. **EARLY_COUNT** uses
the valid-count update. **VERIFIED_DELTA** receives every old/new bit only after
an external full-archive consistency check; its corrected count must reproduce
FULL_EXACT. **PRIOR** reports the regime prior and supplies a scale reference.

## Scoring and the declared engineering summary

Use the unhalved multiclass Brier score `sum_k (p_k - 1[K=k])**2`.
For every `j,r`, integrate the full joint distribution over
`K,u,s,w,q` with exact rational masses. Record:

* expected Brier loss for each available-information posterior;
* excess Brier loss above FULL_EXACT;
* expected squared distance from that posterior to FULL_EXACT;
* the fraction of the known COARSE_OPTIMAL-to-FULL_EXACT gap recovered.

The primary engineering summary is the smallest number `r` of individually
revealed old bits that recovers at least **90%** of the six-replacement Brier
gap. This is a fixed description of this disclosure family, not a significance
test, universal optimal encoding claim, or authorization threshold. Report the
entire curve, including any flat or adverse result. Curves for `j=1,3` are
secondary. No threshold or arm will change after the first full-size run.

Also report two exact sufficient summaries: a trusted old-count total
`v=sum(x_i for i in S)` and the trusted final corrected match count. Each can
recover FULL_EXACT without disclosing every individual old bit. The bit cost
of a count message is `ceil(log2(j+1))` for `v`, excluding metadata and the
verification system. The selected per-slot reveal family does not define an
information-theoretically optimal communication frontier.

## Required mathematical and engineering checks

1. An independent raw-bit enumeration on small domains must recover the initial
   and revision posterior formulas, including uniform schedule disclosure.
2. Exact population mass is one. For each `j,r`, the Brier regret equals
   `E[||p_r-p_full||^2]`; risk weakly decreases as `r` increases. At `r=0`,
   reproduce CQ04's exact Brier values. At `r=j`, regret is exactly zero.
3. EARLY_COUNT equals the correct posterior before any correction and after
   each accepted replacement. This baseline provides the reference for early
   disclosure at equal predictor information.
4. For delayed schedules, establish that the initial count posterior is
   injective over `m` for the registered finite parameters. Give a constructive
   distinguishing `j`-subset for any two different same-count old histories
   when `1 <= j < n`. Independently enumerate finite continuation classes for
   small `n`. Derive the `n`-bit worst-case exact-state lower bound and the
   supplementary tag bound when retaining the initial posterior label.
5. An external archive verifier checks old/new bits, versions, predecessor
   and successor digests before the small numeric state consumes a delta.
   Test false old values, stale/replayed deltas, wrong pins, and changed
   successors. Count message sufficiency does not make a message trustworthy.
6. A stable source-hashed JSON receipt records the complete exact results,
   disclosure conventions, declared summary, finite checks, and limitations.
   CI regenerates the receipt byte for byte.

The memory bound counts the encoder's state before a delayed schedule is
disclosed and requires exact answers for every legal continuation with positive
probability. It is not an average-case, approximate, learned-state, precision,
or total-system storage bound. With early disclosure the count baseline is
sufficient. With an external archive the archive and verification work remain
part of the system.

## Freeze and completion rules

Commit this protocol before computing the new twelve-slot disclosure curve.
Then commit the implementation and independent tests before recording the
full-size result. Small-domain correctness checks may run while developing
source. Freeze source hashes before the first full-size receipt run. Preserve
any post-readout correction with its reason and previous receipt rather than
redefining the original result.

The result can establish exact Bayesian information and memory identities for
these finite contracts. Recurrent correction learning, physical authentication,
matched activation interventions, and protected statistical confirmation require
their own experiments. No extra ACE action authority follows from this study.
