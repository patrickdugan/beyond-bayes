# ACE: source-group identifiability and revision-aware verification

**Research extension v0.1, 30 October 2026.** Based on main commit
`c91a758fbf9793368648b002b11778013e7cb69f`. Local verification: **27 focused tests
passed on Python 3.13.5**. The deterministic benchmark receipt replays exactly.
These checks cover the new files. The existing repository-wide suite and Lean
checks require CI; no new Lean theorem is claimed.

## Integration boundary

`identifiability.py` adds a bounded, exact diagnostic beside ACE's existing
statistical authorization machinery. All returned findings carry
`authorizes_action: false`. Existing action gates, signatures, alpha accounting,
and the v0.10 measurement-start protocol remain unchanged.

The extension asks whether the admitted evidence and explicit fault assumptions
identify a particular binary claim. It preserves counterexamples and supports
later source revocation. Its answer is conditional on an externally supplied
model of the observations. It supplies no physical independence attestation.

The [v0.6 research](../RESEARCH_V06.md) already retains compatible clean histories
under corruption. This extension applies that principle to possible worlds of a
finite constraint system, measures the separation needed for uniform recovery,
and makes revision and prospective queries executable. The existing
`mincut.py` concerns channel availability; graph connectivity alone does not
establish the semantic guarantees below.

## Explicit evidence contract

A `Contract` fixes binary variables, a roster of named report slots, each slot's
source/fault group, externally trusted groups, and the maximum number `k` of
faulty untrusted groups. A unary slot reports a variable; a binary slot reports
the XOR of its variables. A faulty group can return arbitrarily wrong and
mutually inconsistent bits across all its reports. Statistical independence
between groups is unnecessary for this deterministic corruption model.

Grouping is supplied externally. Several apparently separate argument paths can
share one faulty source. Unknown shared causes must be represented by an
adequately conservative group model; the code cannot discover them from names.
Cross-cutting dependencies can require coarsening several groups together.

For observed transcript `y`, let `bad(x,y)` be the set of untrusted groups
containing at least one report inconsistent with candidate world `x`. Then

```
W(y) = {x : every active trusted report agrees with x,
            and |bad(x,y)| <= k}.
```

Missing slots and revoked groups contribute no constraints. Repeated statements
from one group count once toward `bad`, even when they disagree with each other.
An empty compatible-world set yields `model_conflict`. When the target has both
values among compatible worlds, the output is `undetermined` with a witness
world for each value. A nonempty unanimous target yields `identified` and its
bit value. These are epistemic diagnostics, with no safety/action semantics.

### Conditional retention theorem

Assume the real binary world satisfies the active trusted observations and all
false active untrusted reports belong to at most `k` declared groups. Then that
world belongs to `W(y)`. Therefore every identified target equals its real value.

**Proof:** the actual world satisfies the two predicates defining `W(y)`.
Unanimity over a set containing that world entails the claimed target value.
The argument allows arbitrary within-group bias and selective missingness. It
holds at each prefix as long as the whole-run group bound and trusted-report
premises remain valid. These premises need external justification.

## Source-group separation theorem

Fix the observed slot roster and the trusted observed values. A world predicts
a vector of reports `c_r(x)` for each active untrusted group `r`. Among pairs of
worlds satisfying the trusted observations and disagreeing on target `q`, define

```
d_q = min_{x_q != x'_q} #{r : c_r(x) != c_r(x')}.
```

When trusted observations already fix the target, the minimum is over no pairs
and is treated as infinite. An inconsistent trusted system is reported
separately and receives no recovery claim.

**Exact threshold:** every admissible transcript with at most `k` faulty source
groups identifies the target if and only if `d_q > 2*k`.

**Sufficiency:** if two opposite-target worlds both fit one transcript, their
predicted report blocks differ only in the union of their respective sets of
faulty groups. That union has at most `2*k` groups, contradicting the distance.

**Necessity:** take opposite-target worlds whose report blocks differ on at most
`2*k` groups. Partition those groups into two sets of size at most `k`. Construct
a report vector using one world's entire blocks on the first set and the
other world's blocks on the second. Both worlds fit that same vector with at
most `k` faulty groups. Trusted observations agree in both worlds.

This is the classical minimum-distance decoding argument applied to source
blocks and a particular target. The underlying coding-theory result is standard;
the implementation and its application to ACE are the engineering contribution.
See [MIT's introduction to error-correcting codes](https://ocw.mit.edu/courses/6-004-computation-structures-spring-2017/pages/c1/c1s1/).

`target_separation` computes the distance with XOR difference vectors `z=x XOR
x'`. It requires `z_q=1` and zero parity difference on every trusted observation,
then minimizes the number of groups having any nonzero report difference. This
uses `O(2^n*m)` work rather than enumerating `O(4^n)` world pairs. A failed
threshold produces a distinctly labeled **synthetic collision**, including two
opposite-target worlds and the invented report vector compatible with both.
Those invented reports must never be admitted as acquired evidence.

A distance below the threshold describes a worst-case failure. A particular
observed transcript can still identify the target. Conversely, a favorable
structural distance cannot make an actually false trust premise valid.

Three edge-disjoint anchor-to-target paths with separately faulty edge sources
have target distance three in the fixture, permitting one faulty source. When
one fault group supplies an edge on every path, the distance falls to one.
Removing every unary anchor from a parity-only system preserves global bit-flip
symmetry and makes the target distance zero.

## Revision and receipts

`Snapshot` stores an immutable, bounded event history. Each enrolled slot can be
observed once. Revocation is permanent within that contract, erases all of the
root's constraints, preserves its previous records, and never refunds `k`.
Reinstatement or altered grouping requires a new externally pinned contract.

Diagnostic receipts bind the contract digest and exact event-history digest.
`verify_receipt` checks caller-held pins and recomputes the complete result.
After a revocation, a receipt from the earlier history fails replay against the
updated history. This implements a small continuation-sensitive case of the
research direction in [PR #14](https://github.com/patrickdugan/beyond-bayes/pull/14).

Receipts are unsigned research objects. Verification reuses the same solver.
Tests also compare its worlds to a separately written discard-root oracle.
Freshness still requires a caller-held current history pin: an attacker given
permission to supply old pins can present an old snapshot successfully. The
extension provides no distributed persistence or acquisition attestation.

## Prospective audit selection

`recommend_audit` considers unobserved, unrevoked slots within a supplied effort
budget. It simulates both possible reports under the original corruption model
and recommends the cheapest slot whose every feasible reply identifies the
target. Untrusted sources are permitted when the same group budget suffices.
The policy has a deterministic tie-break and ignores queries about an unrelated
variable when they leave the target ambiguous.

This is a one-step plan. A `None` result says this policy found no immediately
resolving affordable query. Multi-step experiments can still be useful. The
function performs no measurement, reserves no alpha, and spends no operational
budget. Wiring it to real experiments requires the existing reservation and
measurement-start machinery, together with a reviewed semantic bridge.

## Measured synthetic results

Run from the repository root:

```sh
python -m unittest test_identifiability -v
python benchmark_identifiability.py --check results/identifiability_v1.json
```

The committed receipt contains source hashes and exact finite counts:

| Check | Observed result |
| --- | --- |
| All 32 worlds, no corruption or any one corrupted edge on the three-path graph | 224/224 targets recovered; zero wrong identifications |
| Every admissible truth/report combination for 1-5 unary sources, all caps, arbitrary erasures | 2,914 cases; zero real worlds discarded; zero wrong identifications |
| Matched full-credal comparator | Zero disagreement with target identification |
| 90 false cloned reports from one faulty group plus 10 truthful groups | Correct target identified; source-group distance 11 |
| Three paths sharing one faulty source | `undetermined`; distance 1 and an explicit collision |
| Anchor revoked or unanchored parity | `undetermined` |
| Two of three reports erased, with cap one | `undetermined` |
| Incorrect externally trusted anchor | Wrong identification, deliberately outside the assumptions |
| Hidden common cause split into separate groups while understating the fault cap | Wrong identification, deliberately outside the assumptions |
| Contradictory trusted reports | `model_conflict` |

The 27 unit tests additionally cover stale/tampered receipts, Boolean/integer
confusion, model amendments, source reuse, and resource limits. A separate
root-discard oracle agrees on all 729 enumerated grouped-report/revocation
fixtures. Forty deterministically generated small contracts are checked against
all their report vectors to verify the separation threshold. Collision witnesses
are replayed against the independent oracle.

`credal_target_interval` is the matched uncertainty-set control containing every
point mass on a compatible world. Its lower and upper target probabilities
collapse exactly when all compatible worlds agree. This equivalence is expected
from the shared model. The experiment makes no superiority claim over Bayesian
reasoning and estimates no real-world verifier accuracy.

## Remaining scientific boundary

The core is exhaustive and capped at 12 variables and 128 slots, with an explicit
work limit for repeated queries. A work-limit exception is not an inconsistency
result. These limits make this a falsification harness for small finite problems.

External users must establish the source-group assignments and truth of trusted
observations. Every XOR equation has stipulated semantics. Natural-language
validity, ontology selection, physical measurement integrity, and verifier drift
remain unmeasured. The two intentional false-identification controls show that
incorrect anchors or an incomplete fault model can defeat the diagnostic.

Existing ACE statistical guarantees remain those in
[RESEARCH_V06.md](../RESEARCH_V06.md) and
[RESEARCH_V10.md](../RESEARCH_V10.md). Deterministic compatible-world retention
adds no unconditional probability bound. The relevant statistical background is
[Ramdas et al., Game-theoretic statistics and safe anytime-valid inference](https://arxiv.org/abs/2210.01948).

The next empirical gate is a sealed, independently labeled set of small theorem
or program constraints with known evidence lineage. Freeze the grouping and
mutation rules before evaluation; compare a conventional history-aware reviewer
and this diagnostic using identical evidence and compute budgets. Measure wrong
identifications alongside abstention and effort, including later revocations.
Source classification quality must be measured independently of the solver.
Any connection to an action gate requires a separately reviewed proposal.
