/-
ACE v0.6: finite-state conditional-null proof boundary.

The concrete Python program enumerates compatible clean traces with a
finite-state dynamic program. These Lean lemmas establish deterministic
relationships between compatibility, erasure, lower envelopes and
anytime-event containment. The probability/event-weight monotonicity and
Ville bound are *explicit premises*: no conditional-martingale measure theory
or Ed25519 verification is formalized in this Lean module.
-/
import Lean

namespace ACE.Conditional

def slotDiscrepancy (reported : Option Bool) (clean : Bool) : Nat :=
  match reported with
  | none => 0
  | some bit => if bit = clean then 0 else 1

def compatible (observed : List (Option Bool)) (clean : List Bool)
    (budget : Nat) : Prop :=
  observed.length = clean.length ∧
    (List.zipWith slotDiscrepancy observed clean).sum ≤ budget

theorem missing_slot_cost_is_zero (clean : Bool) :
    slotDiscrepancy none clean = 0 := by
  rfl

theorem authentic_slot_cost_is_zero (clean : Bool) :
    slotDiscrepancy (some clean) clean = 0 := by
  simp [slotDiscrepancy]

theorem erasing_one_slot_cannot_raise_cost
    (observed clean : Bool) :
    slotDiscrepancy none clean ≤ slotDiscrepancy (some observed) clean := by
  simp [slotDiscrepancy]

theorem budget_expansion_preserves_compatibility
    (observed : List (Option Bool)) (clean : List Bool)
    (k larger : Nat)
    (leBudget : k ≤ larger)
    (wasCompatible : compatible observed clean k) :
    compatible observed clean larger := by
  exact ⟨wasCompatible.1, Nat.le_trans wasCompatible.2 leBudget⟩

/- Every admitted clean trace contributes an upper bound on a certified
   evidence infimum. Scores use Nat purely as an ordered abstraction. -/
def LowerBound (Score : List Bool → Nat)
    (observed : List (Option Bool)) (budget lower : Nat) : Prop :=
  ∀ clean, compatible observed clean budget → lower ≤ Score clean

theorem actual_clean_score_dominates_infimum
    (Score : List Bool → Nat)
    (observed : List (Option Bool)) (clean : List Bool)
    (budget lower threshold : Nat)
    (withinBudget : compatible observed clean budget)
    (certified : LowerBound Score observed budget lower)
    (crossed : threshold ≤ lower) :
    threshold ≤ Score clean := by
  exact Nat.le_trans crossed (certified clean withinBudget)

/- The conditional model's martingale premise and Ville's bound are separate
   obligations. The event inclusion is deterministic for every attack trace. -/
theorem robust_anytime_probability_bound
    {World : Type}
    (cleanScore robustScore : World → Nat → Nat)
    (eventMass : (World → Prop) → Nat)
    (threshold alpha : Nat)
    (dominates : ∀ w t, robustScore w t ≤ cleanScore w t)
    (eventMassMonotone : ∀ (A B : World → Prop),
      (∀ w, A w → B w) → eventMass A ≤ eventMass B)
    (villePremise : eventMass (fun w => ∃ t, threshold ≤ cleanScore w t) ≤ alpha) :
    eventMass (fun w => ∃ t, threshold ≤ robustScore w t) ≤ alpha := by
  apply Nat.le_trans (eventMassMonotone _ _ ?_) villePremise
  intro w h
  rcases h with ⟨t, ht⟩
  exact ⟨t, Nat.le_trans ht (dominates w t)⟩

end ACE.Conditional
