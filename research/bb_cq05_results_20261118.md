# BB-CQ-05 result: calibrated recovery depends on disclosure timing

18 November 2026. [Protocol](bb_cq05_protocol.md) ·
[Mathematical derivation](bb_cq05_mathematics.md) ·
[Exact receipt](../results/bb_cq05_exact_v1.json) ·
[Implementation](../posterior_recovery.py) ·
[Independent oracle](../test_posterior_recovery.py).

## Registered result

The six-replacement disclosure curve reaches the registered 90% recovery
target at **six individually disclosed old values**. Five disclosures recover
**72.288984%** of the known coarse-to-full Brier gap; full disclosure removes
that gap exactly. The recorded status is `EXACT_DISCLOSURE_CHARACTERIZED`.

The timing of the correction schedule determines the encoder's memory
requirement. A schedule revealed before encoding lets a calibrated count
state match full Bayes throughout the correction stream. If the encoder must
compress first and then answer every possible named correction exactly, the
twelve-slot fixture requires **4,096 distinct states, or 12 bits**. A format
that retains the initial posterior label separately needs **10 supplementary
tag bits** in its largest label fiber.

An external verifier can supply the old match total in the corrected slots.
At six replacements this total has seven possible values, so **three message
bits** suffice for exact recovery, given the retained old total and new
replacement total. The archive supplying that message holds the source
information excluded from the numeric state. The per-slot disclosure result
therefore measures the registered message family; it does not give a minimum
communication budget.

Every posterior in the curve is calibrated for its own observed information.
Lower Brier loss measures the additional information available after disclosure.
The full posterior still has expected Brier loss `0.106036369270665` because
twelve reports leave uncertainty about the regime.

## What was known before this analysis

[BB-CQ-04](bb_cq04_results_20261118.md) had already measured the
six-replacement Brier gap `0.064462690844785` and the authorization-cost
advantage `0.006206757142`. Its registered practical action threshold was
`0.02`, yielding `HEADROOM_BLOCKED`.

That observed Brier gap motivated this experiment's endpoint. BB-CQ-05 is a
finite mathematical development result. It supplies a new disclosure curve
and an explicit timing contract; it introduces no independent confirmation
cohort. The previous authorization gate retains its recorded verdict.

The CQ04 protocol describes its amendment schedule as public without fixing
the time at which an encoder learns it. CQ05 specifies that time in two
separate contracts. This resolves the interpretation of the memory claim
while reproducing CQ04's probability law and numeric endpoint exactly.

## Exact population curve

The prior is `(0.45,0.35,0.20)` and the report-match probabilities are
`(0.95,0.65,0.15)`. A uniformly selected, outcome-independent set of old slots
contains fair provisional bits; accepted replacements follow the original
regime-dependent channel. In the delayed contract, an encoder retains the old
match total before it learns the selected slots. All accepted replacement bits
are available when the old-value disclosure curve is evaluated.

For six replacements, the score is the unhalved three-regime Brier loss.
Recovery means the fraction of the coarse-to-full Brier gap removed.

| Old values disclosed | Expected Brier loss | Excess over full Bayes | Gap recovered |
|---:|---:|---:|---:|
| 0 | 0.170499060115450 | 0.064462690844785 | 0.000000% |
| 1 | 0.164519332357532 | 0.058482963086867 | 9.276261% |
| 2 | 0.157352759179353 | 0.051316389908688 | 20.393658% |
| 3 | 0.148616514291139 | 0.042580145020474 | 33.946063% |
| 4 | 0.137724615911930 | 0.031688246641266 | 50.842501% |
| 5 | 0.123899636003767 | 0.017863266733102 | 72.288984% |
| 6 | 0.106036369270665 | 0 | 100.000000% |

The final disclosure removes `0.017863266733102` expected Brier loss, which is
27.711016% of the original gap. This describes the information pattern in the
specified finite model. Neural representation and causal coding remain outside
the experiment's measurements.

The secondary curves are also complete:

| Replacements | Old values disclosed | Expected Brier loss | Excess over full Bayes | Gap recovered |
|---:|---:|---:|---:|---:|
| 1 | 0 | 0.126593462912078 | 0.020557093641413 | 0.000000% |
| 1 | 1 | 0.106036369270665 | 0 | 100.000000% |
| 3 | 0 | 0.158992258579454 | 0.052955889308790 | 0.000000% |
| 3 | 1 | 0.143532988778964 | 0.037496619508299 | 29.192730% |
| 3 | 2 | 0.125855210446098 | 0.019818841175433 | 62.574812% |
| 3 | 3 | 0.106036369270665 | 0 | 100.000000% |

The prior-only Brier risk is `0.635`. All displayed decimals are rounded for
reading. Population weights, posteriors, score comparisons, and the primary
90% decision use exact rational arithmetic. These values enumerate the stated
finite distribution, so sampling intervals are inapplicable.

## A sufficient posterior can lose future correction information

Before a hidden schedule is disclosed, the old vectors are exchangeable.
Their complete current posterior for the regime depends only on the old match
total `m`. Exact checks give thirteen distinct initial posterior labels for
every replacement size `j=1,...,11` at `n=12`.

Suppose two different old vectors are encoded into one retained state. There
is a common legal correction set for which their unchanged match totals differ.
Giving both histories the same new reports then produces distinct final
posteriors. All such histories and continuations have positive probability
under this model. Thus a self-contained encoder answering every delayed
correction exactly must distinguish all `2**12` histories.

This is compatible with the initial posterior being sufficient for the regime
at the time of encoding. The later schedule reveals information about which
observations were provisional. A state preserving the joint information about
the regime and hidden schedule can support that future update.

The [derivation](bb_cq05_mathematics.md) proves the distinguishing-subset
argument and the cardinality bound. The largest initial-posterior fiber has
`C(12,6)=924` histories, requiring ten fixed-width supplementary tag bits if
that label is stored separately. A jointly chosen encoding attains the total
twelve-bit bound.

| Information available to the system | Exact numeric-state result at six replacements |
|---|---|
| Schedule supplied before encoding | Seven initial valid-count states; a four-bit count field covers all later public stages |
| Schedule supplied after encoding; all legal corrections must be answered without an archive | 4,096 distinct encoder states; twelve bits |
| Initial posterior label retained separately under delayed disclosure | Up to 924 histories per label; ten supplementary fixed-width tag bits |
| External archive supplies a verified old corrected-slot total | Three bits encode that total; the predictor computes `m-v+q` |

The count-field sizes assume that the public stage supplies the informative
sample count and event eligibility. Schedule storage, event deduplication,
versions, cryptographic pins, and archive validation have their own costs.
These finite-state bounds concern exact worst-case behavior. They leave
approximate recovery, floating-point hidden states, and average-case memory
tradeoffs open.

## Proper scoring separates approximation from lost information

Let `p_full` be the full posterior and `p_r` the optimal posterior after
the registered disclosures. Using a containing information field that includes
both old records and accepted replacements gives

```
p_r = E[p_full | observed reduced information].
```

For any predictor `a` using that same reduced information,

```
E[Brier(a,K)] - E[Brier(p_full,K)]
  = E[||a-p_r||^2] + E[||p_r-p_full||^2].
```

The first term measures approximation error relative to the best predictor
with those observations. The second is the irreducible loss from the specified
reduction of information. In this exact experiment `a=p_r`, so the first term
vanishes and excess Brier equals the squared posterior-distance term at every
curve point. The proof also yields monotonic population risk as the fixed
disclosure prefix grows.

The containing field matters because the reduced observations include fair
old bits that the final accepted vector omits. The derivation uses
`H=sigma(S,X,Y)` to justify the conditional-expectation step.

## Verification and provenance

The protocol was committed at
[`2e605f1d522c130e3f931aa4b552f83c31aad393`](https://github.com/patrickdugan/beyond-bayes/commit/2e605f1d522c130e3f931aa4b552f83c31aad393).
Implementation, mathematical derivation, and independent tests were frozen at
[`29ac36b8e592fd45ba6fbc294008427d6d79a121`](https://github.com/patrickdugan/beyond-bayes/commit/29ac36b8e592fd45ba6fbc294008427d6d79a121)
before the first twelve-slot disclosure calculation. The frozen files have
not been amended after that readout.

The local repository suite passed **300 tests**, including eleven new tests.
The independent oracle expands named schedules and raw old/new bit vectors
on two-to-four-slot domains using separately declared probability constants.
It checks 1,548 distinct schedule/vector worlds before expanding regime and
reveal stages. The resulting posterior and Brier identities agree exactly
with the production count calculation.

The finite continuation audit covers fifteen `(n,j)` cases through six slots
and checks 2,684 same-count history-pair witnesses. Exact initial posterior
injectivity is checked for every `j=1,...,11` at twelve slots. The runner also
compares 169 coarse-posterior cells against CQ04 and preserves its full and
coarse Brier endpoints by exact rational equality.

Archive fixtures check ten valid transitions and reject fifty malformed or
replayed transitions. Unit tests additionally exercise false old values,
incorrect pins or counts, changed successors, and non-integer successor
versions. Pre-freeze review caught boolean/integer cache-key aliasing and
permissive version equality; the new public wrappers enforce the intended
types. The archive check establishes consistency of supplied snapshots under
the fixture's trust assumptions. Real acquisition and source authentication
remain external.

The source-hashed receipt is 21,303 bytes with SHA-256
`431f4dfb6b13d1d6574583f0f8669b9982c1a098fb1b0ebb0e90499e2cf73a2b`.
Each rational output has a 15-place displayed decimal and a SHA-256 commitment
to its exact normalized numerator/denominator in the documented hexadecimal
encoding. Source and dependency hashes are included in the receipt.

The CI workflow runs the full Python suite, regenerates this receipt byte for
byte, and checks the existing Lean kernels. The new probability and cardinality
proofs are presented in the mathematical note and checked by finite Python
oracles; they have not been formalized in Lean.

Reproduce from the repository root with a standard Python 3.13 interpreter:

```sh
python -m unittest test_posterior_recovery -v
python bb_cq05_exact.py --check results/bb_cq05_exact_v1.json
```

The CQ05 commands use Python's standard library. The complete repository test
suite also uses its declared requirements. Run `python bb_cq05_exact.py
--output /tmp/bb_cq05_exact.json` to produce a separate receipt.

## Consequence for a recurrent follow-up

A learned-state experiment now has a defined information contract and exact
score references. Its protocol should specify when the schedule becomes
visible, the representation available before that disclosure, and the messages
allowed during correction. An early-schedule task needs the compact valid-count
Bayes baseline. A delayed-schedule task needs full-history Bayes plus the
Bayesian optimum under each explicitly restricted information set.

The proper-score decomposition can separate a learner's approximation error
from the information it has discarded. A recurrent study would still require
its own source freeze and independent evaluation design. BB-CQ-05 loads no
neural weights, samples no scientific roots, and grants no new ACE action
authority.
