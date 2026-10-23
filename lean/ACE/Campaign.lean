/-
ACE v0.8: exact integer alpha-spending and campaign event ordering.

These are deterministic implications of checked accounting. The conditional
per-attempt error premise, the union bound for events selected from a
filtration, and the cryptographic/persistence assumptions are not formalized
in this module. They remain explicit requirements of the paper.
-/
import Lean

namespace ACE.Campaign

structure Ledger where
  spent : Nat
  cap : Nat

/-- An approved reservation consumes a strictly positive integer allocation. -/
def reserve (ledger : Ledger) (allocation : Nat) : Option Ledger :=
  if 0 < allocation ∧ ledger.spent + allocation ≤ ledger.cap then
    some { ledger with spent := ledger.spent + allocation }
  else none

theorem reserve_is_monotone (ledger next : Ledger) (a : Nat)
    (h : reserve ledger a = some next) :
    ledger.spent ≤ next.spent := by
  by_cases bound : 0 < a ∧ ledger.spent + a ≤ ledger.cap
  · simp only [reserve, if_pos bound, Option.some.injEq] at h
    cases h
    simp
  · simp [reserve, bound] at h

theorem reserve_preserves_cap (ledger next : Ledger) (a : Nat)
    (h : reserve ledger a = some next) :
    next.spent ≤ ledger.cap := by
  by_cases bound : 0 < a ∧ ledger.spent + a ≤ ledger.cap
  · simp only [reserve, if_pos bound, Option.some.injEq] at h
    cases h
    exact bound.2
  · simp [reserve, bound] at h

theorem reserve_keeps_total (ledger next : Ledger) (a : Nat)
    (h : reserve ledger a = some next) :
    ledger.cap = next.cap := by
  by_cases bound : 0 < a ∧ ledger.spent + a ≤ ledger.cap
  · simp only [reserve, if_pos bound, Option.some.injEq] at h
    cases h
    rfl
  · simp [reserve, bound] at h

/-- A denied attempt never returns its allocated budget. -/
def finalize (ledger : Ledger) (_authorized : Bool) : Ledger := ledger

theorem denial_does_not_refund (ledger : Ledger) :
    (finalize ledger false).spent = ledger.spent := rfl

theorem a_finalize_does_not_refund (ledger : Ledger) (decision : Bool) :
    (finalize ledger decision).spent = ledger.spent := rfl

/-- An honest durable replica signing a single successor for each predecessor
    implies any two of its endorsements for that predecessor coincide. -/
theorem honest_single_successor
    {Replica Event : Type}
    (Honest : Replica → Prop)
    (Signed : Replica → Event → Event → Prop)
    (rule : ∀ a previous first second,
      Honest a → Signed a previous first → Signed a previous second → first = second)
    (replica : Replica) (previous first second : Event)
    (honest : Honest replica)
    (v1 : Signed replica previous first)
    (v2 : Signed replica previous second) :
    first = second := rule replica previous first second honest v1 v2

/-- A signed consumed reservation is unique under an explicitly supplied
    single-consumption condition. External storage/crypto proves that premise. -/
theorem only_one_action_after_consume
    {Action : Type}
    (Consumed : Action → Prop)
    (unique : ∀ a b, Consumed a → Consumed b → a = b)
    (first second : Action)
    (v1 : Consumed first) (v2 : Consumed second) :
    first = second := unique first second v1 v2

end ACE.Campaign
