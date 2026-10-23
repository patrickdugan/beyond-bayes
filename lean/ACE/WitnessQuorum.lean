/-
ACE v0.4: Witnessed checkpoint implications. Lean 4 core-only.

These statements isolate the *mathematical* part of a witness quorum protocol.
The set-cardinality inequalities and the honest-witness conditions are
explicit inputs; signature security, filesystem durability, and the
statistical/e-process guarantee are separate assumptions.

Kernel compilation still needs to be run in GitHub CI.
-/
import Lean

namespace ACE

/- If a receipt/checkpoint quorum intersection contains `overlap` members,
   of which at most `f` may be corrupt, the quorum cardinality condition
   implies at least one honest member exists.

   q+r ≤ n+overlap comes from |Q union R| ≤ n.
   overlap ≤ f+honestOverlap comes from at most f faulty witnesses.
-/
theorem honest_receipt_checkpoint_overlap
    (n f q r overlap honestOverlap : Nat)
    (finite_union : q + r ≤ n + overlap)
    (fault_bound : overlap ≤ f + honestOverlap)
    (safe_quorums : n + f < q + r) :
    0 < honestOverlap := by
  omega

/- Two checkpoint quorums intersect in an honest signer when 2q > n+f. -/
theorem honest_checkpoint_checkpoint_overlap
    (n f q overlap honestOverlap : Nat)
    (finite_union : q + q ≤ n + overlap)
    (fault_bound : overlap ≤ f + honestOverlap)
    (safe_quorums : n + f < q + q) :
    0 < honestOverlap := by
  omega

section ProtocolConsequences

variable {Witness Report Checkpoint : Type}

/- Receipt issuance and signing are external, cryptographically authenticated
   predicates. An honest witness signing a checkpoint that follows a receipt
   must have seen the receipt's report in the complete log. -/
theorem quorum_acknowledgment_cannot_be_omitted
    (Honest : Witness → Prop)
    (Acknowledged : Witness → Report → Prop)
    (Signed : Witness → Checkpoint → Prop)
    (Included : Report → Checkpoint → Prop)
    (honest_obligation : ∀ w r h, Honest w →
      Acknowledged w r → Signed w h → Included r h)
    (w : Witness) (r : Report) (h : Checkpoint)
    (hHonest : Honest w)
    (hAck : Acknowledged w r)
    (hSigned : Signed w h) :
    Included r h := by
  exact honest_obligation w r h hHonest hAck hSigned

/- An honest signer whose durable state forbids signing two different roots
   for one epoch makes the conflicting-head attack impossible. -/
theorem shared_honest_signer_rules_out_split_view
    (Honest : Witness → Prop)
    (Signed : Witness → Nat → Checkpoint → Prop)
    (single_view : ∀ w epoch a b, Honest w →
      Signed w epoch a → Signed w epoch b → a = b)
    (w : Witness) (epoch : Nat) (a b : Checkpoint)
    (hHonest : Honest w)
    (ha : Signed w epoch a)
    (hb : Signed w epoch b) :
    a = b := by
  exact single_view w epoch a b hHonest ha hb

end ProtocolConsequences

end ACE
