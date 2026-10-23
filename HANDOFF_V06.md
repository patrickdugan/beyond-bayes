# ACE v0.6 handoff: connecting clustered inference to witnessed decisions

Repository branch is based on `research/ace-v0.5-anchored-witness`. v0.6 keeps the previous witness signing protocol unchanged and adds **standalone** model-aware statistical inference under a separately pinned cluster plan.

## Checklist for the next engineering iteration

1. Create a **version 2 evidence authorization protocol** in which the witnessed epoch includes the cluster-plan digest and explicit `ConditionalNull` version alongside the original signed source manifest digest. Ensure every witness recomputes the cluster assignment from the complete signed log, checks cluster contradictions and replays the DP and threshold. Never reinterpret an existing version-1 certificate as version 2.
2. Keep the independently pinned policy digest at the relying party, together with nonce, epoch and monotonic latest anchored head. Prevent a certificate signed under one cluster partition, null envelope, corruption budget or alpha from authorizing a different action.
3. Formalize the **finite-tree supermartingale implication** in Lean: valid one-step conditional e-factors yield an expected capital of at most one for every finite horizon; then separately formalize Ville's maximal bound or link it to a mechanized probability library. The current `lean/ACE/Conditional.lean` proves the deterministic event implication given explicit monotonicity and Ville premises.
4. Run causally meaningful **cluster-validation experiments** on data with concealed common causes and history-dependent transition probabilities. Report rate of false certified independence, unsafe authorization, unnecessary denial and computation, with a matched robust Bayesian counterpart.
5. Preserve the v0.5 antirollback and witness safety boundaries. Local SQLite and synthetic Ed25519 fixtures remain research scaffolds, unsuitable for autonomous asset transfer.

## Commands

```sh
python -m pip install -r requirements.txt
python -m unittest discover -q
python benchmark_clusters.py --trials-per-truth 4000 --seed 82064 --output results/v06_clustered_benchmark
```

`conditional.py` defines the finite-state conditional-null family, contamination/erasure DP and credal comparator. `clustered.py` pins signed source slots to ordered statistical clusters. `benchmark_clusters.py` compares exact IID-model Bayes and ACE, the attack-ignorant Bayes falsifier, credal Bayes with rectangular conditional envelopes, and repeated-sensor counterexamples. Complete exact assumptions: `RESEARCH_V06.md`.
