/-
ACE v0.9: deterministic root alpha-grant accounting.

This module establishes implications of a correctly maintained parent ledger.
Statistical conditional probabilities, crypto security, and storage reliability
remain premises of the separate engineering protocol.
-/
import Lean

namespace ACE.Scope

structure RootState where
  allocated : Nat
  budget : Nat

/-- Root allocations consume a nonzero allowance and preserve the global cap. -/
def grant (s : RootState) (child : Nat) : Option RootState :=
  if 0 < child ∧ s.allocated + child ≤ s.budget then
    some { s with allocated := s.allocated + child }
  else none

theorem grant_preserves_cap (s next : RootState) (child : Nat)
    (h : grant s child = some next) :
    next.allocated ≤ s.budget := by
  by_cases bound : 0 < child ∧ s.allocated + child ≤ s.budget
  · simp only [grant, if_pos bound, Option.some.injEq] at h
    cases h
    exact bound.2
  · simp [grant, bound] at h

theorem grant_monotone (s next : RootState) (child : Nat)
    (h : grant s child = some next) :
    s.allocated ≤ next.allocated := by
  by_cases bound : 0 < child ∧ s.allocated + child ≤ s.budget
  · simp only [grant, if_pos bound, Option.some.injEq] at h
    cases h
    simp
  · simp [grant, bound] at h

theorem grant_preserves_total (s next : RootState) (child : Nat)
    (h : grant s child = some next) :
    next.budget = s.budget := by
  by_cases bound : 0 < child ∧ s.allocated + child ≤ s.budget
  · simp only [grant, if_pos bound, Option.some.injEq] at h
    cases h
    rfl
  · simp [grant, bound] at h

/-- Child abandonment is nonrefundable. -/
def abandon (s : RootState) : RootState := s

theorem abandoning_child_does_not_refund (s : RootState) :
    (abandon s).allocated = s.allocated := rfl

/-- Uniqueness follows from the stated honest single-successor premise. -/
theorem parent_grant_single_successor
    {Replica Grant : Type}
    (Honest : Replica → Prop)
    (Signed : Replica → Grant → Grant → Prop)
    (single : ∀ (r : Replica) (previous a b : Grant),
      Honest r → Signed r previous a → Signed r previous b → a = b)
    (r : Replica) (previous a b : Grant)
    (hr : Honest r) (ha : Signed r previous a) (hb : Signed r previous b) :
    a = b := single r previous a b hr ha hb

end ACE.Scope
