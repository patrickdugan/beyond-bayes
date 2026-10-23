# ACE v0.8: campaign-wide error budgeting under adaptive authorization

Issue: [#7](https://github.com/patrickdugan/beyond-bayes/issues/7). The previous v0.7 verifier binds a *single* clustered test to a signed log and action. A malicious or merely persistent actor can request fresh studies, obtaining a new per-study alpha allowance each time. Twenty calibrated, conditionally independent 5% tests have a family-wise error probability of `1 - 0.95^20 = 0.6415140776`.

## A conditional family-wise guarantee

Let `F_{i-1}` be the complete campaign transcript immediately before attempt `i` is reserved, including prior evidence and decisions. Let `alpha_i >= 0` be `F_{i-1}`-measurable, selected **before** any new data from attempt `i` are examined. An adversary may select the test, its action, and its next allocation using prior denials. The active risky/null hypothesis, instrument identity and conditional sampling model must be known to the risk policy at reservation time.

Assume the per-attempt rejection (unsafe authorization under the null) event `E_i` satisfies

`P(E_i | F_{i-1}) <= alpha_i`

under the campaign-wide null/conditional model, including all attacker strategies admitted by the corruption budget. A non-running attempt has `alpha_i=0`. The attempted experiment may be sampled or stopped adaptively within its own observed stream because the underlying e-process is anytime-valid under the conditional null. Assume also that the durable ledger enforces the pathwise budget

`sum_{i>=1} alpha_i <= A <= 1`.

Then, by the union bound, tower rule and monotone convergence,

`P(any erroneous authorization in the campaign) <= sum_i E[P(E_i | F_{i-1})] <= E[sum_i alpha_i] <= A`.

This is a **conditional probabilistic assumption plus a deterministic ledger invariant**. The Lean file `lean/ACE/Campaign.lean` proves accounting and event-order implications; it does not formalize conditional probability measures, martingales, signature unforgeability, hardware independence, or the actual Python implementation.

Correlation across campaigns is permitted if the declared conditional null remains sound after prior attempts. Hidden persistent factors, data peeking before allocation, or a reset of the externally pinned campaign scope can invalidate the premise. The program does not infer causal independence.

## Operational experiment semantics

All alpha allocations are exact integer units with scale `10^12`; values are stored in canonical signed event records. A fixed `CampaignPolicy` supplies the externally pinned campaign identifier, global alpha budget, Ed25519 replica roster and quorum parameters. The signature quorum is `q` of `n` durable replicas with at most `f` faulty and `2q > n+f`. It ensures that two signed successor quorums intersect at an honest replica **if the fault and persistence assumptions hold**.

1. **Reserve**: the campaign replicas durably sign a new, unused challenge, the cluster-plan commitment, the v2 policy, the action commitment, a positive allocation, and the new cumulative spend. Only one outstanding attempt is allowed. A reservation consumes alpha even if data never arrive or the coordinator crashes.
2. **Finalize**: after the signed evidence log has been evaluated, replicas sign the digest of exactly one complete v2 certificate and the asserted result. A second finalization of the same reservation is rejected. A denied attempt retains its alpha expenditure.
3. **Consume**: if the independent v2 replay agrees with the finalization and the challenge remains at the live certified tip, the action gate obtains a third, quorum-signed event before returning authorization. Reusing the same finalization after a local database rollback cannot obtain a second consumption event from honest replicas.

The v2 `ActionIntent.parameters.ace_campaign` object commits the campaign ID, overall alpha cap, predecessor, reservation sequence, exact alpha allocation and cumulative spend. Since the v2 action commitment is itself pinned inside the v2 authorization policy, a cloned v2 certificate from an unrelated campaign is rejected. v1 witnesses still attest the original signed evidence log and its checkpoint, not this additional campaign interpretation directly.

A quorum vote signs a proposed campaign event, not a proof that the experiment's risk model is scientifically valid. A signed finalization asserts one claimed boolean; the independent relying party must check it against v2 replay before consuming the action.

## Crash and rollback model

Each anchor replica uses its own SQLite database and persists its vote inside an `IMMEDIATE` transaction before returning. The coordinator reads a quorum-certified chain and refuses to proceed if any uncommitted minority successor or fork is found. Loss of one of four replica histories leaves three replicas with the certified head; loss of two causes signing to suspend.

A crash after reserve irreversibly spends alpha and may leave the campaign pending. A crash after consume but before the external executor acknowledges the action can lose the action, which is safer than re-executing it. Exactly-once external side effects still require an executor that also anchors its operation IDs. All four replicas run inside one test process, so this code offers neither network fault tolerance nor physical storage isolation.

## Explicit security boundaries

- The trusted caller must pin **one campaign scope** across every attempted action. Starting a new campaign under another ID resets the budget and is outside the guarantee without an umbrella policy.
- Signing key custody and asynchronous network consensus are external. Individual SQLite files on the same disk share failure modes.
- A small, short-horizon Lean state machine and simulations are evidence of the implementation's behavior under those models, not proof of statistical error control in deployment.
- A v0.8 ticket does not prove the evidence was first observed after reservation. Attested experiment start times, trustworthy measurement apparatus and confidential preregistration remain future work.
- An offline verifier authenticates a historical consumption certificate using independently pinned inputs. Freshness requires the **live quorum read** performed by `CampaignActionGate`.
- Releasing real funds or commanding machines requires additional permissions, independently protected risk-scope registration, transactionally idempotent effect execution, and deployment review.
