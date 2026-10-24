# Dot Matrix: Continuation-Sufficient Research States

**Research note v0.1 | 24 October 2026 | Beyond Bayes / Adversarial Constraint Epistemics (ACE)**

**Status:** Mathematical proposal, with a classical minimization theorem and a domain-specific information lower-bound example. No new implementation, AI-model evaluation, or empirical improvement claim. The primary hypothesis concerns reliable scientific review under bounded working memory and computational cost.

## Abstract

A research agent repeatedly encounters results, amendments, reused evidence, source revocations, proof repairs, and delegated reviews. A compressed state that preserves the current research decision may erase distinctions needed for later decisions. This note formulates *continuation sufficiency* for scientific histories, gives a tight information lower bound for revocable source support, and proves an impossibility result for unrestricted future retrospective questions. An immutable archive and a task-scoped online state address different requirements. The proposed empirical criterion compares a structured Dot Matrix reviewer with a capable, conventional history-aware reviewer supplied with identical evidence and a matched computational budget.

## 1. Scope, ancestry, and novelty

The core right-congruence theorem is a direct application of the Myhill–Nerode theorem; its relevance to research-state compression is proposed here. Predictive states in computational mechanics group histories by their distributions over possible futures, offering a probabilistic analogy. Darwiche and Pearl's iterated belief-revision framework established that the belief set alone may fail to capture information required by subsequent revision. Database provenance semirings provide an algebra of evidence ancestry. Reusable-holdout research documents the risk of adaptively examining the same evaluation data. Yudkowsky and collaborators studied reflective agents and the problems of preserving goals across ontology changes. These contributions provide existing foundations; no priority claim is made for their underlying mathematics.

The candidate advance is an operational, auditable formulation for *research continuation decisions* with a measured memory/cost budget. Any future superiority claim must defeat a conventional history-aware baseline with access to the same evidence, not a model that only remembers the previous decision label.

## 2. Exact objects

Fix the following publicly inspectable objects:

- A typed event alphabet \(\Sigma\), including `FREEZE(rule)`, `OBSERVE(source, payload)`, `AMEND(rule)`, `VERIFY(proof, premises)`, `REVOKE(source)`, `REUSE(source)`, and `QUERY(question)`.
- A prefix-closed language \(\mathcal H\subseteq\Sigma^*\) of legal histories. Semantic constraints, such as which revocations are allowed and what constitutes a pre-observation amendment, belong to this contract.
- An output set \(Y\) of normative **procedural** judgments: `eligible-confirmatory`, `exploratory`, `blocked`, `revoked`, `undetermined`, or a typed action. These labels describe the entitlement to make a scientific claim; they do not assert the claim's underlying truth.
- A specified evaluation function \(D:\mathcal H\to Y\), where \(D(h)\) is the appropriate procedural output following history \(h\). An independently adjudicated ground-truth contract is required to define \(D\) on real studies. For mathematical examples, \(D\) is defined explicitly.

For general strings \(u\), totalize the evaluation with a distinguished value \(\bot\) when \(hu\notin\mathcal H\). This makes admissibility observable and prevents a compression from merging histories that admit different future operations.

A state map \(z:\mathcal H\to Z\) is *exactly continuation-sufficient* when

\[
 z(h)=z(h')\implies\forall u\in\Sigma^*,\ \overline D(hu)=\overline D(h'u).
\]

It is *incrementally realizable* if there are an updater \(U:Z\times\Sigma\to Z\) on legal events and an output map \(g:Z\to Y\), such that

\[
 U(z(h),e)=z(he),\qquad g(z(h))=D(h).
\]

Both properties are required. A correct one-time summary that becomes unsound after the next source revocation is insufficient.

## 3. Minimal continuation-state theorem

Define

\[
 h\equiv_D h'\quad\Longleftrightarrow\quad\forall u\in\Sigma^*,\ \overline D(hu)=\overline D(h'u).
\]

**Theorem 1 (exact minimality).** If there are \(N<\infty\) equivalence classes under \(\equiv_D\), any continuation-sufficient state representation has at least \(N\) distinguishable states. The quotient \(z(h)=[h]_D\) attains \(N\) states and admits a deterministic incremental update \(U([h]_D,e)=[he]_D\). A fixed-length binary encoding needs at least \(\lceil\log_2N\rceil\) bits.

**Proof.** If a representation identifies inequivalent histories, some continuation gives different correct outputs. An updater supplied the same state and future event sequence must return identical results, a contradiction. For the quotient, appending the same event preserves continuation equivalence, because every subsequent suffix is still a suffix of the original histories. Hence the quotient update is well-defined. Distinct classes need distinct codewords. \(\square\)

The theorem concerns state count, not the computational cost of discovering equivalence classes or validating real-world scientific judgments.

## 4. A tight research-specific memory lower bound

Suppose a decision can rely on any of \(m\) distinct, revocable authority/support roots \(r_1,\ldots,r_m\). A history \(h_S\) has an active support set \(S\subseteq[m]\), and its current decision is

\[
 D(h_S)=\mathrm{GO}\quad\Longleftrightarrow\quad S\ne\varnothing.
\]

Events `REVOKE(i)` remove \(i\) from the active set. Revoking a root already absent is legal and has no effect. The decision may be queried after any sequence of revocations.

**Proposition 2 (revocable-root lower bound).** For \(m\ge2\), even restricting attention to the \(2^m-1\) histories with the *same current output* `GO`, an exact continuation-sufficient encoding requires at least \(m\) bits. For the entire system, including the empty-support state, the exact minimal memory is \(m\) bits.

**Proof.** For distinct nonempty \(S,T\), choose an index \(i\in S\triangle T\). Revoke every root other than \(i\). The remaining decision is `GO` for exactly the history containing \(i\), so \(h_S\not\equiv_D h_T\). Consequently the nonempty states alone require \(2^m-1\) distinct codes, whose minimum fixed-length encoding uses \(\lceil\log_2(2^m-1)\rceil=m\) bits for \(m\ge2\). Including the empty set gives \(2^m\) states; the \(m\)-bit support bitmap achieves the bound. \(\square\)

This is an intentionally elementary construction. “Independent” refers to *separately revocable logical root identities*. Source signatures and distinct IDs do not prove statistical independence or establish the truth of their evidence.

For \(m=3\), the exact minimal automaton has eight states: all subsets of \(\{a,b,c\}\). The seven nonempty states currently say `GO`, while future revocations distinguish every pair. For instance, \(S=\{a\}\) and \(T=\{b\}\) both initially yield `GO`; after `REVOKE(b)` and `REVOKE(c)`, the respective answers are `GO` and `STOP`. A last-label-only compression necessarily fails this fixture. An ordinary history-aware program carrying the same three-bit bitmap passes it exactly.

## 5. Amendment order and observational status

Fix a rule \(R_1\), a later rule \(R_2\), and observed evidence \(x\). Compare two histories:

\[
 h_A=[\mathrm{FREEZE}(R_1),\mathrm{AMEND}(R_2),\mathrm{OBSERVE}(x)]
\]
\[
 h_B=[\mathrm{FREEZE}(R_1),\mathrm{OBSERVE}(x),\mathrm{AMEND}(R_2)].
\]

Both end with the same active rule and same data; any post hoc numerical application of \(R_2\) to \(x\) may produce the same score. Under a contract that defines confirmatory eligibility by pre-observation registration, a future `QUERY(confirmatory-status,R2,x)` distinguishes the histories. The status for \(h_A\) is eligible subject to all other protocol gates; the status for \(h_B\) is exploratory. The chronology and prior looks are part of the state.

An *order-sensitivity diagnostic* can be written as

\[
 K_{A,L}(h)=\mathbf1\{D(A(L(h)))\ne D(L(A(h)))\},
\]

where \(A\) means amendment and \(L\) means looking at outcomes, and both compositions have contract-defined semantics. “Epistemic holonomy” is a speculative name for this kind of path dependence. No geometric connection, parallel transport law, or holonomy group is established by this binary indicator.

ConstitutionalAlignment's registered analysis and its later plan to judge visible reflection-arm answers supply a documented *development example*: the subsequent analysis was chosen after observing the evaluation failure and acceptance-tag patterns, so its procedural evidential status differs from a prospectively frozen test. The available completed result also depends on output validity and judge amendments. This example has been reviewed repeatedly and must not be placed in a sealed confirmatory test set.

## 6. Open-ended inquiry impossibility

**Proposition 3 (unbounded retrospective queries).** If a research history may contain an arbitrarily long sequence of independent binary facts \(b_1,\ldots,b_n\), and future queries can ask for any past bit \(b_i\), no fixed \(B\)-bit state is exactly continuation-sufficient for all \(n\).

**Proof.** For each \(n\), the \(2^n\) bit strings yield pairwise distinguishable histories: a differing index can be queried. Therefore the state requires at least \(n\) bits for each \(n\). An absolute constant \(B\) cannot satisfy all \(n\). \(\square\)

This makes an architectural requirement precise: **retain a content-addressed, losslessly recoverable evidence archive; treat online compressed states as task-scoped, versioned projections.** When the admissible future question family expands, recompute the projection from archived evidence before making decisions under the expanded contract. A new ontology can invalidate an old sufficient-state certificate.

A signed digest alone establishes a commitment and is insufficient for answering arbitrary questions unless the underlying content is available for retrieval and verification.

## 7. Bounded horizons and approximate states

For a budget of at most \(H\) future events, define \(h\equiv_H h'\) when all continuation outputs agree for every legal suffix of length at most \(H\). The number of such classes \(N_H\) gives a lower bound \(\lceil\log_2N_H\rceil\) on exact \(H\)-horizon state bits.

The right-congruence property requires care: an event consumes one unit of the horizon. A sound horizon-indexed updater maps a state sufficient at horizon \(H\) to one sufficient at horizon \(H-1\). An ordinary fixed-\(H\) quotient need not support a same-\(H\) update.

For approximate reasoning, fix a decision loss \(L(\hat y,y)\), a set of admissible histories, and a prospective continuation horizon. Define \((\varepsilon,H)\)-sufficiency by the maximum continuation loss of the compressed updater relative to the externally specified correct decisions being no greater than \(\varepsilon\). Under binary zero-one loss and \(\varepsilon<1\), the exact distinguishability lower bound still holds. More permissive losses permit task-specific merges but require independently justified error budgets.

A bounded-state representation is a computational research claim, and its value depends on the measured tradeoff between retained bits, verifier effort, and decision regret.

## 8. Deterministic fixture contract: DS-3

The smallest informative formal fixture uses three revocable roots, event-sourced support sets, and one decision predicate. It can be checked by hand before implementation.

**Input histories:** all eight subsets of \(\{a,b,c\}\). **Events:** `GRANT(a/b/c)`, `REVOKE(a/b/c)` (idempotent), `QUERY(decision)`. **Oracle:** `GO` iff at least one active root remains. **Continuations:** every revocation sequence of length 0–3 ending in a query. **Required checks:**

1. The eight subsets are pairwise continuation-distinguishable; seven nonempty subsets initially share `GO`.
2. A current-label-only representation collapses the seven `GO` states and fails at least one continuation.
3. The three-bit support bitmap returns the correct decision and transitions for all legal histories and continuations.
4. A full-history replay baseline passes every fixture.
5. A changed source identity or an added event type triggers reevaluation of the state specification; existing sufficiency applies only to its defined event family.

**Pass condition:** the mathematical assertions above hold by exhaustive enumeration or a proof over finite sets. This checks the *state-contract theorem*, not the scientific truth of external evidence.

## 9. One prospective discriminating study

**Question:** Under a matched information and compute budget, does a Dot Matrix reviewer using typed provenance and continuation-state obligations commit fewer consequential scientific-status errors than a strong chronological history-aware reviewer?

**Material:** a sealed set of approximately 40 archived research snapshots from several independent projects, with later independently resolved protocol-status questions. The training/development set may include ACE and ConstitutionalAlignment examples; those previously inspected artifacts are excluded from the sealed set. If there are too few genuinely unseen resolved cases, postpone the study rather than relabel familiar cases as confirmatory.

**Conditions:** the *same* model, event records, documents, tool permissions, available time, and total computational/token budget in both conditions. One reviewer receives a competent conventional instruction to account for chronology, alternative explanations, and source reuse. The Dot condition receives the typed research-state protocol, with all preprocessing and verification costs included in its budget. Each condition answers the same held-out questions, including later disclosed revocations and amendments. Runs are paired on each history and randomized in order or seed as appropriate.

**Ground truth:** a procedural eligibility or amendment classification derived from contemporaneous rules and independently adjudicated without seeing either model output. A question involving unresolved empirical truth remains `undetermined` and is not forced into a true/false label.

**Primary measurement:** paired consequential misclassification rate after the future continuation, with particular attention to falsely upgrading exploratory findings to confirmatory status. **Secondary measurements:** missing corrections, unnecessary downgrades, source-dependence errors, review time, computational cost, and false-positive objections. Publish the full cost/error frontier.

**Precommitment and gate:** register the case selection, rules, prompts, labels, scoring costs, and practical effect threshold before model review. An engineering expansion is warranted only if the structured condition yields a material error reduction against the strong matched baseline, survives independent adjudication and paired uncertainty analysis, and fits the same budget. Failure or indistinguishable performance preserves the useful historical ledger but halts architectural expansion.

A positive result would concern review reliability on the sampled tasks; it would not establish general superiority over Bayesian reasoning, prove a physical sampling model, or certify an autonomous system's safety.

## 10. Research agenda and exact stopping rule

1. **Proved now at the mathematical level:** classical quotient minimality, the revocable-root memory lower bound, and the impossibility of constant-memory exact response to arbitrary past-bit queries, given their explicitly defined event models.
2. **Specified, pending formalization:** a type-safe vocabulary for scientific amendments, dependence, proof discharge, and future event queries, plus an auditable state reconstruction rule.
3. **Empirical hypothesis:** the Dot Matrix state representation improves consequential review decisions at fixed information and computation compared with a strong history-aware baseline.

**Stop infrastructure expansion** until the matched study or an independently identified control failure demands a specific new mechanism. Preserve the archive, the formal contracts, and the negative results in the interim.

## References

- A. Darwiche and J. Pearl, *On the Logic of Iterated Belief Revision*, Artificial Intelligence 89 (1997). https://www.sciencedirect.com/science/article/pii/S0004370296000380
- J. P. Crutchfield and C. R. Shalizi, *Thermodynamic Depth of Causal States*, Physical Review E 59 (1999). https://journals.aps.org/pre/abstract/10.1103/PhysRevE.59.275
- T. J. Green, G. Karvounarakis and V. Tannen, *Provenance Semirings*, PODS (2007). https://web.cs.ucdavis.edu/~green/papers/pods07.pdf
- C. Dwork et al., *The Reusable Holdout: Preserving Validity in Adaptive Data Analysis*, Science (2015). https://pubmed.ncbi.nlm.nih.gov/26250683/
- E. Yudkowsky and M. Herreshoff, *Tiling Agents for Self-Modifying AI, and the Löbian Obstacle* (early draft, 2013). https://intelligence.org/files/TilingAgentsDraft.pdf
- E. Yudkowsky and N. Soares, *Functional Decision Theory* (2017). https://arxiv.org/abs/1710.05060
- E. Yudkowsky et al., *Ontology Identification Problem: Technical Tutorial*. https://www.alignmentforum.org/w/ontology-identification-problem-technical-tutorial
- Myhill–Nerode theorem, standard automata-theoretic right-congruence and state-minimization result. https://www.cs.columbia.edu/~tal/3261/sp18/MyhillNerode.pdf