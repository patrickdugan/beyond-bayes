/-
ACE v0.10: deterministic budget-preserving scope rollover and
monotone measurement counter windows. The cryptographic authenticity,
physical acquisition order and stochastic conditional-null premises
remain outside this Lean module.
-/
import Lean

namespace ACE.RootOrdering

structure Root where
  cap : Nat
  lifetimeSpent : Nat
  remaining : Nat

/-- A retired scope contributes all of its allocated budget to lifetime spend.
    The new scope is bounded by the unused lifetime cap. -/
def rollover (s : Root) (oldAllocated nextBudget : Nat) : Option Root :=
  if s.lifetimeSpent + oldAllocated + nextBudget ≤ s.cap then
    some { cap := s.cap
           lifetimeSpent := s.lifetimeSpent + oldAllocated
           remaining := nextBudget }
  else none

theorem rollover_monotone (s next : Root) (used fresh : Nat)
    (h : rollover s used fresh = some next) :
    s.lifetimeSpent ≤ next.lifetimeSpent := by
  by_cases permitted : s.lifetimeSpent + used + fresh ≤ s.cap
  · simp only [rollover, if_pos permitted, Option.some.injEq] at h
    cases h
    simp
  · simp [rollover, permitted] at h

theorem rollover_budget_cap (s next : Root) (used fresh : Nat)
    (h : rollover s used fresh = some next) :
    next.lifetimeSpent + next.remaining ≤ s.cap := by
  by_cases permitted : s.lifetimeSpent + used + fresh ≤ s.cap
  · simp only [rollover, if_pos permitted, Option.some.injEq] at h
    cases h
    omega
  · simp [rollover, permitted] at h

theorem rollover_preserves_global_cap (s next : Root) (used fresh : Nat)
    (h : rollover s used fresh = some next) : next.cap = s.cap := by
  by_cases permitted : s.lifetimeSpent + used + fresh ≤ s.cap
  · simp only [rollover, if_pos permitted, Option.some.injEq] at h
    cases h
    rfl
  · simp [rollover, permitted] at h

structure Window where
  firstCounter : Nat
  capacity : Nat

/-- A successor window begins after the entire previous allocated range. -/
def nonoverlapping (previous following : Window) : Prop :=
  previous.firstCounter + previous.capacity ≤ following.firstCounter

theorem no_counter_reuse (previous following : Window)
    (h : nonoverlapping previous following)
    (oldCounter : Nat)
    (hOld : oldCounter < previous.firstCounter + previous.capacity) :
    oldCounter < following.firstCounter := by
  unfold nonoverlapping at h
  omega

/-- Honest single-successor and fixed reservation identities are premises
    supplied by the witnessed start protocol's authenticated journal. -/
theorem one_start_per_reservation
    {Reservation Start : Type}
    (Valid : Reservation → Start → Prop)
    (unique : ∀ (r : Reservation) (a b : Start), Valid r a → Valid r b → a = b)
    (r : Reservation) (a b : Start)
    (ha : Valid r a) (hb : Valid r b) :
    a = b := unique r a b ha hb

end ACE.RootOrdering
