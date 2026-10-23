# ACE v0.9: a risk budget above individual campaigns

## The reset attack

In v0.8, `CampaignPolicy.campaign_id` defines the budgeting boundary. Replacing that policy with a fresh identifier and a fresh 5% allowance creates twenty independent opportunities for error, with probability `1-(1-.05)^20 = 64.1514%` under independently calibrated tests. A signed campaign log cannot determine by itself whether another logically related campaign has already consumed the organization's risk allowance.

v0.9 introduces an externally pinned **risk scope** that binds one principal and resource namespace to a total alpha allowance. Its independently journaled replicas sign a sequence of irrevocable **child-campaign grants**. A child `CampaignPolicy` is valid only when its campaign ID is derived from the parent commitment and a nonce, and its full policy commitment and allowance agree with a live certified parent grant. The child must use a scope-aware action gate: the authenticated v2 action must identify the same principal, resource, parent commitment, and grant digest.

## Hierarchical error guarantee

Let a fixed parent scope be allocated cap `A`. The ledger grants child campaign `j` the nonnegative budget `b_j` *before the child can obtain new data*. Each child spends `a_{j,i}` predictably before attempt `i`, according to its complete prior evidence transcript. The two ledgers enforce the pathwise inequalities:

`Σ_j b_j ≤ A`, and for every child `j`, `Σ_i a_{j,i} ≤ b_j`.

For each false authorization event `E_{j,i}`, assume the **full parent-scope history** filtration gives the conditional bound

`P(E_{j,i} | F_{j,i-1}) ≤ a_{j,i}`,

where this includes every other child campaign's observations, selection decisions and prior denials, and the bound remains valid after any allowed source corruption. Then

`P(∃ j,i: E_{j,i}) ≤ E[Σ_j Σ_i a_{j,i}] ≤ E[Σ_j b_j] ≤ A`.

This applies also when attackers adaptively pick the next child campaign from previously observed results. The conditional soundness premise remains scientifically substantive. The Python code checks the parent and child ledger inequalities, signatures, and policy commitments. The Lean module proves deterministic implications about allocating a nonzero parent budget and retaining it after child abandonment. The measure-theoretic probability argument is still a paper proof.

## Root grant protocol

- `ScopePolicy`: externally trusted scope ID, principal ID, resource namespace, cap, signing roster and quorum. A scope commitment is the hash of the complete canonical policy.
- `ScopeGrant`: signed hash chain entry with sequence and predecessor; child nonce; derived child ID; full child `CampaignPolicy` commitment; child cap; cumulative allocated units.
- `ScopeReplica`: separately persisted Ed25519 SQLite journal. A replica signs a single successor after transactionally persisting it. Readable history is replayed from genesis with signature and transition checks.
- `ScopeQuorum`: a live read requires a unique certified prefix with quorum votes at every entry. Divergent or speculative minority successors suspend allocation. Every grant spends its full cap immediately, even if the child is never started.
- `ScopeActionGate`: before consuming a child action, checks the latest root quorum, exact child-policy grant, pinned principal/resource, and `ace_scope` inside the signed v2 action. The wrapped v0.8 `CampaignActionGate` then performs the independent clustered evidence replay and one-use child consumption.
- `verify_scope.py`: offline audit of the complete signed grant chain against an **externally pinned root head** and child policy. Historical offline verification cannot replace the live scope read.

With `n=4, f=1, q=3`, two signature quorums share an honest replica provided protected keys and monotonic persistence. These four SQLite instances run in a single process and share a physical host; this is a fault-model experiment, not deployable network BFT.

## Attacks and counterexamples

1. **New child ID to reset alpha:** every new child needs a fresh parent grant. Five 1% grants exhaust a 5% root scope; further grants fail.
2. **Child DB rollback:** resetting a child database cannot refund parent allocations. A second grant for the same derived child identity fails.
3. **Wrong signer roster or child allowance:** changes the committed child policy; the root grant verifier rejects it.
4. **Wrong principal or resource:** the scope action gate rejects a signed action with a mismatched scope context or action resource field.
5. **One parent replica rolled back:** the remaining three certify the latest root grant. Two rolled-back replicas cause signing to suspend.
6. **Partial grant publication:** a minority successor causes a fail-closed read. Replicas can later approve the *same* successor to restore progress.
7. **Preallocation data peeking:** choosing the smallest of 20 individually valid uniform p-values after seeing them, then allocating 5%, has a 64.15% false-authorization rate. The ledger is mathematically correct, but the predictable test-selection premise has failed.

## Boundaries for the next version

A principal can reset the global allowance by convincing the operator to trust a new root `ScopePolicy`. Preventing that needs policy governance outside this program, such as an independently maintained immutable principal/resource registry. The parent `ScopeGrant` also does not attest that the child's physical observations occurred after the grant was certified. Both facts must be enforced by operational trust roots and protected measurement-start attestations.

The child v2 evidence witnesses sign the underlying log, while the parent quorum signs the child budget grant. A policy-aware final witness endorsement that includes the parent scope would reduce reliance on wrapper composition. Device-rooted measured boot, authenticated replication over separate hosts, and exactly-once effects remain outside the prototype. Never use this research code to release real assets.
