import Lean

/-!
# ACE / BB-CQ-03: verified revision count arithmetic

This is the deterministic arithmetic kernel of the 12-report amendment model.
It formalizes only the implications of an externally verified old/new
matched-report status. It does not establish that an archive's event, source
signature, previous slot value, revision order or physical acquisition is
authentic. It also does not formalize the full 2^12 state-count theorem,
the Bayesian probability model or the exact rational Brier-risk result.
-/

namespace ACE.AmendmentMemory

/-- The number of matching reports after replacing one attested old bit. -/
def replaceCount (nMatches oldMatch newMatch : Nat) : Nat :=
  nMatches - oldMatch + newMatch

/-- A valid old contribution can be subtracted before adding its replacement. -/
theorem replaceCount_balance (nMatches oldMatch newMatch : Nat)
    (hOld : oldMatch ≤ nMatches) :
    replaceCount nMatches oldMatch newMatch + oldMatch =
      nMatches + newMatch := by
  unfold replaceCount
  omega

/-- Under the external old-bit premise, a verified delta preserves the count. -/
theorem verifiedDelta_count (nMatches oldMatch newMatch target : Nat)
    (hOld : oldMatch ≤ nMatches)
    (hTarget : target = nMatches - oldMatch + newMatch) :
    replaceCount nMatches oldMatch newMatch = target := by
  simp [replaceCount, hTarget]

/--
Two histories with an equal positive aggregate match count but opposite old
status at the selected slot separate after a common absolute replacement
value. This is the arithmetic witness behind the one-step collision test.
-/
theorem oppositeOldMatch_separates (nMatches newMatch : Nat)
    (hPositive : 0 < nMatches) :
    replaceCount nMatches 0 newMatch ≠
      replaceCount nMatches 1 newMatch := by
  unfold replaceCount
  omega

/-- Replacing a confirmed zero with a confirmed one increases the count. -/
theorem zeroToOne (nMatches : Nat) :
    replaceCount nMatches 0 1 = nMatches + 1 := by
  simp [replaceCount]

/-- Replacing a confirmed one with zero decreases a positive count. -/
theorem oneToZero (nMatches : Nat) (hPositive : 0 < nMatches) :
    replaceCount nMatches 1 0 + 1 = nMatches := by
  unfold replaceCount
  omega

end ACE.AmendmentMemory
