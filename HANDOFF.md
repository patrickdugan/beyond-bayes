# ACE v0.5 engineering handoff

The canonical repository is https://github.com/patrickdugan/beyond-bayes.
Start by running the 93-test Python suite and the four Lean modules in CI.

A working read-only audit exists for a four-replica local anchor quorum. The
principal remaining architectural gap is networked authenticated replicas,
with a durable repair protocol for a transition stored by fewer than q
replicas, and eventual action-effector coordination.

Security reviews should challenge: quorum read latest-head selection,
crash ordering across two SQLite stores, data-store rollback exceeding f,
replica key substitution, identity/domain separation, replay of ancestor
anchor certificates, and binding a protected action to its authorization
nonce. Audit performance and liveness separately from authentication safety.

These prototype anchor signatures are bound to pinned witness/protocol keys.
No single public key can attest independence of a sensor's physical origin.

---

# ACE v0.4 engineering handoff · 23 October 2026

## Current state

- Fixed source manifest and robust anytime e-process inherited from v0.3.
- RFC 9162-style Merkle evidence log, inclusion and consistency proof tests.
- Receipts signed to a unique report and target (next unsigned) epoch.
- Four-witness / one-fault / three-signature checkpoint + receipt protocol.
- Full sealed-log replay, externally pinned action nonce, policy and epoch.
- Durable, signed SQLite witness snapshots and one-use relying-party gate.
- Exact adversarial 2-receipt counterexample and 3-receipt omission resistance.
- Three Lean modules are written; kernel compilation pending.

## Next PR in a dedicated ACE repository

1. Import the v0.4 package as a standalone history-preserving repository.
   Run all Python tests and all Lean modules in GitHub Actions.
2. Install pinned Lean v4.35.0 in CI. Compile `lean/ACE/Foundations.lean`,
   `Admission.lean`, and `WitnessQuorum.lean`. Fix any elaboration errors
   while preserving statements and without `sorry` or new axioms.
3. Introduce a witness-to-witness external monotonic checkpoint anchor.
   Test a Byzantine operator rolling back a fully valid previously signed
   SQLite snapshot, causing split-view re-signing, and ensure the external
   antirollback witness catches the attack. Specify recovery semantics.
4. Create an authenticated transport carrying `(report, target_epoch)` and
   collect `r` signed witness receipts before deadline. Require a source-side
   `r`-receipt proof before calling a report quorum-acknowledged. Never claim
   completeness for messages that fail to obtain a timely receipt quorum.
5. Add external effect execution with an idempotent two-phase or transactional
   action API. The SQLite gate currently records a nonce before permitting a
   side effect, which prevents replay but allows crash-induced lost actions.
6. Independently port and property-test Merkle inclusion/consistency in Rust
   or Lean, and use shared canonical-json golden vectors for cross-language
   signature and hash agreement.
7. Model correlated sensor groups and source-dependence attacks. Match the
   best Bayesian and credal alternatives on enrollment and witness budgets,
   compare both false approvals and unnecessary shutdowns, and disclose
   the true statistical premise used for every test.

## Verification checkpoints

- `python -m unittest discover -v`
- `python quorum_audit.py`
- `python demo_witnessed.py`
- `python verify_witnessed.py ...` using independently pinned anchors
- `for f in lean/ACE/*.lean; do lean "$f"; done`
- prove crash-persistent single-view per epoch under normal restarts
- demonstrate a whole-store rollback attack and block it with the added
  external anchor under a declared Byzantine fault model

## Known blockers

Real witness-network delivery assumptions, antirollback trust, physical
sample independence, external atomic side effects, and actual Lean kernel
verification. Do not use this prototype for signing real-asset movements.
