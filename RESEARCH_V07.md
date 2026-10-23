# ACE v0.7: witnessed clustered authorization with independent replay

## Scope

This patch binds the v0.6 cluster/conditional-null inference engine to the
v0.5 signed source-report log and one-use action gate. It introduces a separate
certificate schema (`ACE-witnessed-clustered-certificate-v2`) and a distinct,
externally pinned authorization policy. Every accepted v2 claim is recomputed by
a second scorer whose state transition and numerical code do not import the
original conditional scoring routines.

A v1 witness signs a **log checkpoint**, including its epoch, ordered Merkle
root, prior checkpoint digest and source-enrollment manifest, under a v1
witness quorum. V2 adds an externally pinned interpretation of that exact log.
The witnesses do **not** certify the correctness of the v2 cluster assignment
or source independence. Those remain statistical model obligations; the
authorization gateway applies the v2 policy to the witnessed log.

## Domain-separated commitments

An authorization object includes the following objects:

1. **Source manifest** `P`: pre-enrolled Ed25519 keys, fixed observation slots,
   immutable experiment challenge. Existing v1 domain.
2. **Witness policy** `W`: quorum of checkpoint signers and evidence receipt
   requirements. Existing v1 domain.
3. **Cluster plan** `C`: a disjoint exact cover of P's signed slots, its ordered
   sampling units, conditional-null transition table, corruption budget (whole
   clusters), and false-authorization alpha. The v0.6 schema includes `version:2`.
4. **Action intent** `A`: schema, the fixed experiment challenge, operation name,
   resource and typed parameters. Its domain is `ACE-action-intent-v2`.
5. **V2 interpretation policy**:

   ```json
   {"schema":"ACE-clustered-authorization-policy-v2",
    "protocol_commitment":"SHA256(P)",
    "witnessed_policy_commitment":"SHA256(W)",
    "cluster_plan_commitment":"SHA256(C)",
    "action_commitment":"SHA256(A)"}
   ```

   Every digest uses deterministic JSON encoding, `sort_keys=True`, compact
   separators, ASCII escaping and nonfinite number rejection. This is a Python
   serialization contract; a fully cross-language canonical JSON specification
   remains a separate task.

The verifier receives *trusted*, external expected values for all five pins,
the action nonce, next epoch and previous head digest. These inputs are never
learned from the candidate bundle itself.

## Verification chain

`verify_clustered_certificate` first checks the strict **v2** schema and pins.
It invokes the existing verified v1 witness-log verifier to check every source
signature, the entire ordered log's Merkle root, checkpoint signature, quorum
signatures, previous-head continuity and the supplied epoch. It reconstructs a
ClusterPlan from the candidate v2 policy, checks its canonical commitment and
compares every trusted pin. It then independently derives:

- For each signed source slot, the set of distinct valid signed readings.
- Equivocated source slots and conflicting member readings within clusters.
- The ordered cluster bit (or explicit erasure) from every precommitted cluster.
- The minimum conditional log e-score over possible clean bit histories with
  up to k substitutions at present cluster positions, allowing both options
  for erasures.
- The maximum prefix lower score and whether it exceeds `log(1/alpha)`.

`authorized` additionally requires no signed-slot equivocation and no
within-cluster contradiction. Every field of the claimed decision is compared
to independent replay. A pre-v2 certificate is rejected by the v2 verifier.

With valid clean-world conditional null probabilities, fixed cluster mapping,
and an adversarial corruption budget k, the true clean history is contained in
the reconstruction set at each prefix. Thus the robust score is bounded above
by the clean e-process and the anytime false-authorization bound follows from
Ville's inequality. The supplied Lean theorem module only proves structural
commitment binding; these probabilistic assumptions are not machine-checked.

## Independent scorer

The alternative replay uses a min-plus DP keyed by `(state, edits_used)`, with
`log(q)-log(p)` and `log(1-q)-log(1-p)` computed independently from v0.6's
`math.log(q/p)` and `math.log((1-q)/(1-p))` implementation. State transitions
use each **candidate clean bit**, rather than adversarial reported bits.
The bounded-corruption score's complexity remains O(n(k+1)|S|) in time and
O((k+1)|S|) in working state, with n cluster positions, k edit budget and S
finite conditional-null states. Exhaustive differential tests cover all 3^n
binary/erasure streams for n up to 5, k in {0,1,2} and two conditional models.

## Authorization gate and negative tests

A SQLite `BEGIN IMMEDIATE` transaction atomically checks the **next** pinned
head and the unused experiment nonce. On a denied decision, the gate persists
the new checkpoint but leaves the nonce unconsumed. On an authorized decision,
it persists the head and consumes the nonce before returning. The `anchors`
and `consumed` tables intentionally match the inherited v1 gate so mixed-version
replays within the *same* database share a nonce namespace and log head.

The tests exercise substituted action arguments, all five pin mismatches,
model/bet/budget/alpha changes, altered cluster membership, signed equivocation,
intra-cluster disagreement, erasures, repeated reports, adversarial decision
claims, checkpoint tampering, missing quorum endorsements, stale epoch/prior,
legacy v1 cross-version injection, non-finite scores, JSON duplicate keys and
reused nonces. A persistent deterministic signed fixture allows offline review.

## Security boundaries

- **The v2 statistical plan is trusted through explicit external pins.** An
  honest v1 witness can sign a log that a v2 policy later interprets
  incorrectly if the cluster plan or conditional-null model is false.
- **Authenticated input is not independently generated evidence.** Sensor
  calibration, causal common roots, physical source honesty and k bound must
  be established independently.
- **The witness quorum's completeness promise covers reports acknowledged by
  a receipt quorum before sealing.** An attacker can suppress reports before
  any honest witness receives them; scheduled missing slots become erasures.
- **The local relying-party database has no whole-file rollback protection.**
  The v0.5 external anchor protocol protects witness signing state, not the
  relying-party database used for v2 action consumption. Deployments need a
  comparable monotonic anchor and atomic integration with actual actions.
- **Downgrade prevention requires routing policy.** The v2 verifier only
  accepts v2; an independent caller who intentionally invokes the legacy v1
  authorization gateway remains exposed to v1 policy semantics.
- **No production network protocol or protected execution boundary** is
  provided. The signed certificates use deterministic synthetic test keys.
- **The v1 signers attest the evidence root, not the v2 policy decision.** An
  independently witnessed v2 policy-endorsement and externally persisted
  policy transition should be a separate, versioned consensus upgrade.

The prototype is unsuitable for authorizing real financial transfers.
