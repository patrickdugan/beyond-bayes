# BB-CQ-01: Finite continuation quotients, minimal online repairs, and causal memory

**18 November 2026. Status:** mathematical derivation plus independently checked exact finite development fixtures. The implementation is a diagnostic alongside ACE v0.10. It neither issues authorization nor changes source-group inference, measurement starts, alpha budgets, or witnesses. This study has no preregistered neural-model effect, unseen confirmation set, physical measurement, or new Lean certificate.

## Research review and ancestry

Beyond Bayes already has complementary, bounded mathematical layers. [Dot Matrix](dot_matrix_continuation_sufficiency_v0_1.md) establishes minimal continuation-state classes and a tight revocable-root lower bound. [Identifiability](broken_verifier_identifiability.md) recovers a binary target under a declared source-group corruption cap when the source-block separation obeys `d_q > 2k`; wrong group assignments and false trusted anchors are known falsifiers. ACE v0.10 contributes signed histories and conditional anytime testing, with an explicit full-information filtration and physical-acquisition trust boundary. The earlier matched IID robust-Bayes comparator reaches the same decisions.

Recent cross-repository results sharpen the motivation:

- [BPD optimal-basis theorem](https://github.com/MoralityLabAI/BPD/blob/main/mechinterp/bpd/theory/OPTIMAL_BASIS_AND_MASKS.md): unregularized expected-L0 optima share the hyperplane-mass rank filtration. A sparse optimum need not identify a unique component basis or intervention algebra. The learned-gating recovery tests require separate evidence.
- [BPD-CQ-01 observable-mask theorem](https://github.com/MoralityLabAI/BPD/blob/main/mechinterp/bpd/theory/causal_observable_masks/THEORY.md): current-readout invisibility can disappear after recurrence. The stacked Gramian, reachable input span and finite horizon determine the exact observable quotient for the specified linear system. Truncated observable mask families need not form block algebras.
- [EvalMath covert-feedback risk](https://github.com/MoralityLabAI/EvalMath/blob/main/paper/covert_feedback_risk.md): a side channel affecting which test is selected can raise error under identical marginal tests. Signed allocation alone cannot certify the actual information filtration.
- [EvalMath mechanistic power preflight](https://github.com/MoralityLabAI/EvalMath/blob/main/skills/evalmath-mechinterp-power/SKILL.md): independent roots, physical intervention effects and a matched sham floor must be resolved before a neural or causal-mechanism claim.

This bridge applies standard deterministic automaton minimization to a **declared finite epistemic contract** and adds a minimal-bit repair calculation for a proposed online representation. It is a finite integration test of continuation closure. It does not establish a novel coding-theory or Myhill-Nerode theorem.

## Contract and exact quotient

A finite Moore-style machine is `(S, A, delta, o)` with finite states `S`, event alphabet `A`, total deterministic transition `delta:S x A -> S` and output `o:S -> Y`. The output is a procedural judgment or task readout chosen in advance. Contract-invalid events must be represented by a distinguishable sink state if future admissibility is relevant. For a state `s` and suffix `u`, `o(delta*(s,u))` is the future output.

Define `P_0(s,t)` to mean `o(s)=o(t)` and

```
P_(h+1)(s,t)  iff  o(s)=o(t)
                 and every event a satisfies P_h(delta(s,a),delta(t,a)).
```

These partitions refine monotonically. With finitely many states, refinement stabilizes at the greatest output-preserving right congruence `P_infinity`; it agrees with equality of all future output traces. The number of blocks is the minimum exact online state count for **this contract**. Horizon `h` recognizes suffixes of length at most `h`, and an event consumes one unit of remaining horizon. A same-horizon online updater cannot generally be inferred from a fixed-h quotient.

The independent oracle searches the product machine on state pairs and returns a shortest event suffix whose outputs differ. If no such suffix exists, the states are continuation-equivalent in this finite machine. This search shares no partition-refinement logic with the quotient builder.

## Minimal additional bits for a *retained* representation

Let `phi:S -> Z` be the proposed retained state label, such as a current GO/STOP verdict or current linear-model readout. There are two different certificates:

1. **Behavioral sufficiency:** `phi(s)=phi(t)` entails equality of all future **task outputs**. Let `Q_D` be the all-horizon output quotient.
2. **Exact online update:** the compressed state must also reproduce its own next `phi` label for every event. Let `Q_(D,phi)` be the all-horizon quotient of the joint observation `(o,phi)`.

For a partition `Q`, write `K_z(Q)` for the number of distinct `Q` classes intersecting the fiber `phi^{-1}(z)`. If the original label must be retained and a uniform fixed-width tag can be added, the exact minimal supplementary storage is

```
b_output = ceil(log2(max_z K_z(Q_D)))
b_online = ceil(log2(max_z K_z(Q_(D,phi))))
```

**Proof:** each pair of different quotient classes inside one original-label fiber needs distinct supplementary tags, giving the lower bound by pigeonhole. For attainment, number the relevant quotient classes within each original-label fiber and reuse tag numbers between different fibers. In the online case `Q_(D,phi)` is a stable right congruence, so the resulting `(phi,tag)` has a well-defined output and transition. The behavioral quotient alone need not preserve successor labels. These are classical finite-state refinement facts applied to research-state projections.

The returned bit counts exclude storage for the original label, archived evidence, physical source provenance, cryptographic proofs, runtime, and the trust/semantic cost of defining the event contract. A finite quotient can be compact while its computation remains expensive.

## Exact development fixtures

The committed [receipt](../results/continuation_quotient_v1.json) is generated from the [replay script](../benchmark_continuation_quotient.py).

| Contract | Present classes | Fully continuation-distinct classes | Extra online bits given current verdict/readout |
| --- | ---: | ---: | ---: |
| Two revocable roots | 2 | 4 | 2 |
| DS-3, three revocable roots | 2 | 8 | 3 |
| Four revocable roots | 2 | 16 | 4 |
| Five revocable roots | 2 | 32 | 5 |
| Two-bit delayed swap, present readout `y` | 2 | 4 | 1 |

In DS-3, all seven nonempty support subsets share GO, yet individual root revocations can distinguish every pair. The source-aware bitmap realizes the three-bit minimum. The machine uses idempotent *abstract* revocations; `identifiability.Snapshot` uses one-shot revocations and must preserve its own legal-history semantics when totalized.

In the delayed swap, state `(x,y)` exposes `y` now and `x` after one `tick`, because `(x,y)` becomes `(y,x)`. The first witnessed collision is `00` versus `10`, with distinguishing suffix `tick`. This is a **discrete finite analogue** of the BPD-CQ-01 linear delayed-observer witness, not an empirical statement about a trained BPD or a proof of the continuous Gramian formula.

An additional three-state fixture has constant outputs and labels `same,same,different`. The two `same` states agree on every future task output but transition to different next labels. Its behavioral repair needs zero bits and its **online** repair needs one. This prevents a current-output-only test from incorrectly certifying an incremental compressed state.

The replay additionally generated **96 deterministic small machines** with 1,618 pairwise quotient-versus-independent-BFS comparisons, **zero disagreements**, and 28 repaired-label-fiber pairs checked for output and transition consistency. These are exhaustive **within each small declared machine**, while the set of 96 machines was selected during development. This supplies engineering evidence, not a statistical estimate of performance on independent research worlds.

## Link back to ACE and experimental requirements

The identifiability solver already demonstrates two source histories with the same currently identified target, distinguished after revoking one root. BB-CQ-01 checks whether a separate compact research-state encoding can retain that distinction in a finite typed event model. Neither source-group separation nor continuation quotient computation supplies independence attestation, truthful trusted anchors, or a valid statistical null. The diagnostic field `authorizes_action` is always false.

A proposed neural/TRM/SAE state compressor needs a predeclared event vocabulary including all allowed amendments, source revocations, missing-evidence disclosures, readouts and interventions. Construct a finite surrogate from pinned admissible histories, test the full transition contract, and expose the shortest counterexample sequence. Next evaluate actual learned states on independent model worlds with matched shams and blinded future interventions. Include the cost of reconstructing the archive, matching the history-aware baseline, and correcting source groups. Passing a toy quotient certificate is only an engineering preflight.

For an approximate recurrent projection `pi` with reduced transition `F_hat`, a separate Lipschitz contract of the form `||pi(F(s))-F_hat(pi(s))|| <= epsilon` on **actually intervened reachable states** yields `e_H <= epsilon * sum_(j=0)^(H-1) L^j` when `F_hat` is `L`-Lipschitz on the compared paths. A local Jacobian or descent potential alone cannot justify this global finite-horizon bound. This bound is a paper implication from the stated hypotheses and is not enforced by the present exact Boolean machine.

**Prospective stop rule:** expand to learned-state causal claims only after an EvalMath preflight with independently sourced model/puzzle roots, a meaningful intervention effect larger than the matched sham floor, a sealed confirmation set and a strong full-history baseline. Maintain the v0.10 ACE core and matched robust-Bayes comparison unchanged. Revisit PR #15's audit-completeness assumptions and PR #16's theorem-audit simulation only after their CI and source contracts pass independently.

## Reproduce

```sh
python -m unittest test_continuation_quotient -v
python benchmark_continuation_quotient.py --check results/continuation_quotient_v1.json
python -m unittest discover -q
```
