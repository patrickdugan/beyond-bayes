/-!
ACE v0.5: monotonic anchor quorum implications (Lean 4 core).

Persistence, cryptographic authentication, and antirollback of each honest
anchor remain external predicates. The mathematical lemmas prove only the
stated set-intersection and recovery consequences.
-/
import Lean

namespace ACE

/- A read quorum and a write quorum share an honest anchor if their
   intersection has at most `f` faulty elements and 2*q > n+f. -/
theorem honest_anchor_read_write_overlap
    (n f q overlap honestOverlap : Nat)
    (finite_universe : q + q ≤ n + overlap)
    (fault_bound : overlap ≤ f + honestOverlap)
    (quorum_condition : n + f < q + q) :
    0 < honestOverlap := by
  omega

section Anchoring

variable {Replica State : Type}

/- An honest anchor signs at most one successor of a specified predecessor.
   This is a protocol hypothesis supplied as a local premise, not a cryptographic
   proof about the concrete Python implementation. -/
theorem common_honest_anchor_rejects_fork
    (Honest : Replica → Prop)
    (Voted : Replica → State → State → Prop)
    (single_successor : ∀ a prior first second,
      Honest a → Voted a prior first → Voted a prior second → first = second)
    (a : Replica) (prior first second : State)
    (isHonest : Honest a)
    (firstVote : Voted a prior first)
    (secondVote : Voted a prior second) :
    first = second := by
  exact single_successor a prior first second isHonest firstVote secondVote

/- If a recovered witness takes the certified monotonic head as its state,
   its externally certified sequence is preserved regardless of what value
   its local disk had prior to recovery. -/
theorem recovery_uses_certified_sequence
    (certified local recovered : Nat)
    (restore : recovered = certified) : recovered = certified := by
  exact restore

/- A checked extension cannot decrease its anchor sequence. -/
theorem anchored_successor_is_strictly_newer
    (previous next : Nat) (step : next = previous + 1) :
    previous < next := by
  omega

end Anchoring

end ACE
