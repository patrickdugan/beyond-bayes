# ACE v0.10: Root enrollment and acquisition-order attestations

## Research problem

The campaign-level bound presupposes that an experiment is selected, and its risk allocation fixed, before its evidence becomes available. `scope.py` v0.9 already burns allocations at the root scope but allows an operator to create a different `ScopePolicy` with a fresh nominal limit for the same principal and protected resource. Meanwhile, a signed campaign reservation records an event in software, not when a physical device first observed data.

This prototype separates **root enrollment**, **signed protocol ordering**, **device acquisition integrity**, and **statistical validity**. The first two are auditable under their signing and storage assumptions. The latter two require independent trust.

## Globally pinned root enrollment

The external trust anchor is a `RegistryPolicy` with an administrator's Ed25519 key, a fixed 4-replica signing roster, a 3-of-4 signature requirement (up to one faulty), and enrolled instrument keys and epochs. Multiple competing registry instances can themselves reset the budget if a relying party allows the actor to choose its registry anchor. The verifier therefore takes the registry identity and certified head as independently supplied pins.

For each `(principal, resource)` key, the registry stores one active `ScopePolicy`, an immutable lifetime cap, prior allocations, and a set of previously used scope identities. An `enroll` event is allowed once per key. A `rollover` must cite the current scope, include its complete signed grant chain at a stated head, and authenticate a new scoped policy with an operator signature and registry quorum signatures. If the old scope had allocated `a` and previously retired scopes allocated `u`, the new scope's `b` obeys:

\[
u+a+b\leq A_{root}.
\]

Earlier allocations stay consumed even if their campaigns are abandoned. All permitted action gates must consult the active registry scope at the time of consumption. The local simulator serializes rollover and consumption with one in-process lock; that is **not** an atomic network protocol.

## Signed start receipt

The parent scope grant and child campaign reservation are certified before a new start receipt is signed. The start record commits to the certified registry and root heads, root grant digest, reserved campaign record, instrument enrollment, complete v2 inference policy, intended action, experiment nonce and allocated device counter range. The device first signs an *arm* message over the intended start binding. The witness quorum then checks the current registry, parent grant and reserved child policy and signs the receipt.

The start journal persists one nonce and one reservation identity per experiment. It also enforces nonoverlapping counter windows for an enrolled instrument epoch. Every admitted source observation is signed by its configured source and re-attested by the registered instrument key with the witnessed start digest and an ascending counter. The v0.10 offline verifier independently checks the registry, parent, campaign and start signatures, replays the v2 clustered decision and checks exact correspondence to all reports in the Merkle witnessed log.

This is a **model of controlled acquisition**. The `SimulatedInstrument` has a signing interface that refuses measurements before activation, but it accepts a bit supplied by its caller. A caller who saw a candidate bit beforehand can supply it after activation. A protected acquisition path, protected keys and counters, and appropriate device attestation would be needed to make physical-time claims. Signed software timestamps alone cannot supply those properties. See RFC 9162's treatment of signed log commitments and inclusion proofs and NIST SP 800-90B's entropy-source health-test requirements for relevant engineering context. Neither standard certifies this prototype or solves advance observation by a malicious caller.

## Probability guarantee

For attempts indexed by \(i\), let \(\mathcal F_{i-1}\) include all observations, failed attempts, side-channel information and adaptive decisions known before choosing the next attempt. Only when the next test satisfies

\[
\Pr(\mathrm{false\ authorize}_i\mid\mathcal F_{i-1})\leq \alpha_i
\]

and \(\alpha_i\) is selected predictably, with pathwise budget constraint \(\sum_i\alpha_i\leq A\), can the campaign family-wise risk be bounded by \(A\). If the instrument can inspect future outcomes before allocation, the conditional validity premise fails. The registry does not repair an invalid sampling model.

## Exact counterexample

For twenty independent uniform null p-values \(U_1,\ldots,U_{20}\), an attacker who observes all candidates before committing to one test can choose \(\min U_i\). With a 0.05 threshold,

\[
\Pr(\min U_i\leq 0.05)=1-(0.95)^{20}\approx 0.641514.
\]

An honest single post-start uniform observation rejects at 0.05. This remains true even if the malicious software signs a measurement report *after* the witnessed start. It demonstrates a limitation in the source-acquisition assumption, not a cryptographic signature forgery.

## Formal boundary

`lean/ACE/RootOrdering.lean` establishes the deterministic rollover cap and monotonic counter-window properties from exact natural-number state transitions. The theorem that a reservation has one start assumes an honest single-successor journal. The proof leaves the cryptographic security model, physical device behavior, stochastic model and distributed linearizability outside Lean. Kernel compilation in CI checks those deterministic statements only.

## Unresolved issues

- A registry of registries requires a top-level immutable externally trusted anchor and governance for budget renewals.
- Live parent rollover and remote action consumption require an atomic or explicitly serialized distributed protocol. This research version uses one process-local lock.
- Attesting that measurements originated after a start event requires protected acquisition hardware or a comparably trusted environment. Enrolled keys and signed counters show provenance and order of signatures, not causal sample time.
- The instrument mock keeps its active session and counter in memory. The witness quorum rejects reused signed counter windows after a client rollback, while local reporter-side rollback and physical reset protection remain unimplemented.
- Merkle receipts and log inclusion/consistency checks rely on the existing witnessed protocol; no network gossip or production key-management is supplied.
