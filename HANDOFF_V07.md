# ACE v0.7 → v0.8 engineering and mathematics handoff

Repository: `patrickdugan/beyond-bayes`. This work is stacked on the v0.6
branch while PR #1 (anchored witnesses) and PR #3 (clustered conditional nulls)
remain draft PRs.

## Current scope

- v1 witnessed, complete ordered log of signed reports.
- v2 externally pinned action+conditional model interpretation policy.
- independent v2 replay of all signed cluster evidence from that log.
- SQLite nonce-consumption gate and head continuity.
- deterministic synthetic fixture and exhaustive short-horizon differential QA.

## Next high-priority tasks

1. Add **new v2 witness endorsement messages** explicitly signing the
   model/action-policy commitment alongside the log checkpoint digest. Protect
   that signing state in the existing independently anchored witness state,
   including policy-transition constraints. Stop old v1 policy interpretive
   routes for v2-only experiments.
2. Add externally anchored, transactional **relying-party monotonic state**;
   prove that whole-store rollback cannot reauthorize a nonce or allow a fork.
   Model a crash after nonce consumption but before an action executor commits.
3. Specify a portable canonical encoding (e.g., deterministic CBOR or a
   cross-language canonical JSON profile), with integer/floating-point
   agreement across Rust/Lean/Python. Commit standard hash/signature vectors.
4. Formalize the clean-history conditional e-process one-step expectation and
   adaptiveness assumptions in Lean with appropriate measure theory. Connect
   the Python DP transition to a finite-state refinement proof.
5. Test witness/collector quorum recovery under network partitions,
   withholding, conflicting epochs, source-sensor common-cause errors and
   externally pinned model changes. Carry an explicit alpha budget over repeated
   challenges, not merely a per-challenge one-off bound.
6. Run matched Bayesian and credal baselines with equal cluster, cost,
   provenance and corruption assumptions. Report unnecessary lockdown.

## Cautions

Witnesses certify the log root in v0.7. They do not sign the v2 model/action
policy digest directly, and the cluster model is an external statistical
assumption. Python tests and structural Lean lemmas do not establish physical
sampling independence, cryptographic unforgeability or production safety.
