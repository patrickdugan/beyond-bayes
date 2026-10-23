# v0.5 research note: rollback-resistant witness anchoring

A witnessed authorization certificate depends on honest witnesses retaining
receipts and signed epochs. An Ed25519 signature on a local SQLite snapshot
protects integrity while leaving that state vulnerable to full-database
rollback. ACE v0.5 adds an external monotonic anchor quorum.

Let n independent anchor replicas persist signed successor records. Under at
most f Byzantine replicas, a write quorum of q and read quorum of q satisfy
2q > n+f, so any two quorums intersect in more than f members, including an
honest replica. A vote signs (policy, witness ID, sequence, predecessor,
signed-snapshot digest). Honest replicas persist their vote before sending it
and decline a fork at any fixed predecessor.

**Falsifier reproduced:** a standalone signed SQLite journal can be restored
to a prior valid snapshot. Under this rollback, the same witness will endorse
two incompatible checkpoint heads for the same epoch. The v0.5 external
anchor catches the rolled-back local snapshot and restores its last known
signed view, then rejects the incompatible head.

**Conditional theorem:** if two different successors of the same anchored
predecessor each obtain q durable votes, their voter sets intersect in at
least one honest replica, contradicting that replica's single-successor rule.
The theorem does not establish an external signing key's protection, correct
network delivery, or Byzantine resilience of a single machine hosting all
anchor replicas.

**Read rule:** inspect at least q authenticated replica heads; if a newer
partially published head is observed without q matching votes, freeze. If
there is a quorum at the greatest observed height, restore the full signed
snapshot from that certificate. The snapshot authenticates the witness's
epoch obligations, preserving them across a rolled-back local DB. Safety
trades availability for conservative rollback detection.

**Crash ordering:** a signing operation commits its external anchor quorum
inside the local SQLite transaction and releases its signed response after
both external quorum and local commit succeed. If the process crashes after
external votes but before its local commit, quorum-backed recovery reinstalls
the prior signed snapshot. A partial external publication may cause a safe
freeze requiring repair.

**Boundary:** the model is a single-process harness using separate SQLite
files for independent simulated replicas. Deployment must put replicas across
failure domains with protected keys and a protocol for catching up lagging
replicas. The statistical theorem still assumes a correct clean null, a
fixed roster, a valid corruption budget and appropriate dependence structure.

---

# ACE v0.4 research note: witnessed provenance as an inference contract

## Formal commitment

Consider an immutable sampling protocol `P`, a witness policy `W`, and a
fixed action challenge `c`. The protocol includes `n_s` *preregistered
observation slots*, risky null model `P0`, alternative betting strategy
producing a nonnegative e-process `E_t`, confidence budget `alpha`, and
maximum number `k` of compromised sampled slots.

At each scheduled prefix `t`, all absent admitted observations are erasures,
including those suppressed by an adaptive adversary. Define

`A_t(Y) = {x in {0,1}^t : flips_observed(x,Y) <= k}`,

`R_t(Y) = inf_{x in A_t(Y)} E_t(x)`.

If the genuine clean prefix belongs to `A_t(Y)`, then `R_t(Y) <= E_t(X)`
pathwise. Thus `{exists t: R_t(Y) >= 1/alpha}` is a subset of
`{exists t: E_t(X) >= 1/alpha}`. For a nonnegative `P0` test martingale with
starting value one, Ville's inequality bounds the latter by `alpha`.

A witnessed evidence log attempts to make the scope of `Y` an auditable
object: every certified checkpoint commits to a full log; valid source
observations and witness receipts are bound to `P` and epoch-specific
witness obligations; the decision is recomputed from the committed log.

This is a *conditional chain of implications*, not a claim of unconditional
real-world Type-I error control.

## The witness-receipt theorem

Let the witness roster be `N`, `|N|=n`. At most `f` witnesses are Byzantine.
A report `z` has a valid **epoch-e receipt quorum** `R⊆N`, `|R|>=r`, when
r distinct witnesses have signed the report digest and target epoch `e`.
The checkpoint has signatures from `Q⊆N`, `|Q|>=q`.

Elementary counting gives:

`|Q ∩ R| >= q + r - n`.

If `q+r > n+f`, then `|Q∩R| > f`, so at least one member `w` of the
intersection is honest. Since `w` issued its receipt for `e`, it received
`z` before endorsing checkpoint `e`. Its honest signing rule requires every
report it acknowledged to be present in the checkpoint's complete log.
Consequently, a valid checkpoint cannot omit a report that obtained a receipt
quorum for that epoch (or an earlier epoch in its extended log).

Likewise, for two checkpoint signing sets `Q1` and `Q2`,
`|Q1∩Q2| >= 2q - n`. If `2q > n+f`, at least one honest witness would need
to sign two incompatible epoch-e heads for a split view to exist. Honest
witnesses with durable one-head-per-epoch state refuse.

Assumptions: Ed25519 witness signatures are authentic; identity and keys are
properly pre-enrolled; at most f signers are Byzantine *over the entire
relevant epoch*, and honest witnesses persist receipt obligations and
checkpoint history without rollback. A witness has access to the complete
plaintext log and verifies the signed reports and root before signing. A
liveness or network delivery guarantee is not proven.

## A necessary strengthening: epoch-targeted receipts

A timestamp-free receipt could be issued after a head was signed, then
presented as proof that the signer should have included the observation in
that earlier head. v0.4 binds receipts to each witness's *next unsigned epoch*.
Verification of receipt quorum requires every receipt to target the same
expected epoch. The witness state advances atomically with endorsements.

This is a **logical sequence guarantee**, not globally synchronized time. If
three witnesses issue receipts targeting different epochs, a report has not
met the intended common-epoch receipt threshold. Late observations can force
the next epoch to include a conflict, but cannot retroactively revoke an
already-performed protected action.

## An exact adversarial omission counterexample

Choose `n=4`, at most `f=1` corrupt witness, and checkpoint threshold `q=3`.
Let `r=2`, a weakened receipt threshold. Take receipt signers `R={0,1}` and
checkpoint signers `Q={0,2,3}`. Witness 0 is corrupt. Honest witness 1
received the conflicting report but does not sign the checkpoint. Honest
witnesses 2 and 3 never saw the report, so they legitimately sign the
collector's incomplete head. Corrupt witness 0 signs it dishonestly. An
observer sees three valid checkpoint signatures and a source omission.
The intersection `Q∩R={0}` is entirely Byzantine.

With `r=3`, any three-receipt set and any three-checkpoint set of four
witnesses intersect in at least two members, of which at least one is honest.
The omission attack is blocked. `quorum_audit.py` exhaustively verifies this
counting bound, and `test_witnessed.py` drives actual Ed25519 signatures.

## Merkle proofs and replay boundaries

For list of canonical signed report bytes, the log hash recursively matches
RFC 9162's design: leaf H(0x00 || input), interior H(0x01 || left || right),
and empty H(empty). Every checkpoint contains protocol and witness-policy
commitments, epoch, Merkle root, size and previous checkpoint digest.

`merklelog.py` generates and independently verifies inclusion and append-only
consistency paths, including irregular tree sizes. The relying-party verifier
reads the **entire supplied log**, recomputes its root, verifies the signature
quorum and compares the claimed authorization to a fresh run of the enrolled
source-signature ledger and robust e-process.

A signed checkpoint is a statement about a particular view. The requirement
that the view covers all quorum-acknowledged reports depends on honest
witness receipt obligations. Protection against certificate replay requires
an external challenge and monotonic checkpoint history; `relying_party.py`
keeps that state transactionally and records a challenge before authorizing.

## Crash recovery and unresolved rollback

The basic `Witness` class uses in-memory state. The `DurableWitness` wrapper
persists signed receipt obligations, complete prior bytes and epoch-signing
history to SQLite. It commits an updated, self-signed state before returning
a receipt or endorsement. Crash/restart tests verify these obligations
survive process replacement and that modified rows are detected.

A signed database snapshot alone cannot prove freshness. An attacker capable
of replacing an entire SQLite database with an older valid snapshot can
still force double-signing. The minimum credible deployment requires a
rollback-resistant witness checkpoint anchor, protected keys, replication,
and a sound recovery protocol.

## Scope, competing methods and falsifiers

Witnessed ACE remains compatible with Bayesian conditional probabilities,
credal Bayes, adversarial robust Bayes, and sequential likelihood-ratio
methods. Its operational aim is to elevate provenance and admissibility to
first-class, machine-checkable constraints while retaining quantified
sequential error control.

- It is possible for 24 enrolled signing sensors to share one physical
  Bernoulli(.8) latent bit. A nominal 5% anytime test can falsely authorize
  with 20% probability if the apparent 24 samples are treated as iid.
- A fully hidden observation that never obtains a receipt quorum is outside
  this particular completeness theorem. Treating missing scheduled slots
  as erasures remains an important statistical defense, but unaudited later
  source equivocations can complicate incident reconstruction.
- An adversary can deny service by preventing quorum receipts or checkpoint
  cosigning. The theorem is about acceptance safety, not availability.
- A recovered witness with a rolled-back valid disk image may forget an old
  signature. This violates the honest-witness monotonic-state assumption.
- A Bayesian oracle granted the same manifest and witnessed evidence can
  match the source-authentication guarantee. ACE must be judged on attack-
  conditioned risk, total loss, computation and formalization cost.

## Lean proof boundary

`lean/ACE/WitnessQuorum.lean` contains natural-number quorum-overlap lemmas
and deterministic consequences of receipt/signature predicates. The proof
contracts take set-counting bounds and witness honesty/obligation predicates
as explicit assumptions. They do not mechanize the actual cryptographic
primitive, Python code semantics or Ville's inequality. All three Lean
modules await kernel compilation in a Lean 4 runtime / GitHub Actions.

## Next research obligations

Establish a durable distributed witness recovery protocol, formulate an
experiment-specific causal dependence graph with statistically sound clustered
sampling units, and run a matched Bayesian/credal comparator with identical
witness budgets. Specify a separate action-effector handshake that can atomically
coordinate a consumed nonce with an external protected action.
