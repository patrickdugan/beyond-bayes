# ACE Lean 4 proofs (kernel compilation pending)

Pinned toolchain: `leanprover/lean4:v4.35.0` (root `lean-toolchain`).

```bash
for file in lean/ACE/*.lean; do lean "$file"; done
```

- `Foundations.lean`: cloning, constraint survival, source cuts and
  conditional event inclusion.
- `Admission.lean`: abstract signed-slot rejection, lower-envelope
  soundness, monotonicity and conditional anytime event inclusion.
- `WitnessQuorum.lean`: arithmetic honest-quorum intersection and logical
  consequences for witnessed receipts and single-view checkpoint signing.

The probability space, Ville inequality, Rust/Python source-code semantics,
Ed25519 security, and actual honest-witness durability are *assumptions or
independent engineering tasks*. These Lean proofs represent deterministic
consequences of explicitly stated contracts. All modules still await their
first Lean kernel verification in a Lean-equipped runtime or CI.
