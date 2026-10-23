/-
# ACE: abstract provenance admission and erasure soundness (Lean 4 core)

A small independently checkable theorem boundary. Cryptographic validity and
physical independence are external predicates; this file proves consequences
of a fixed roster, candidate-set inclusion, and certified lower envelopes.
No probability spaces or signature libraries are imported.
-/
import Lean

namespace ACE

section IdentityAdmission

/- A toy admission projection with boolean signature verification. The Python
   implementation additionally detects conflicting valid observations. -/
def admissionStep (roster : List Nat) (validSignature : Bool)
    (slot : Nat) (reading : Bool) (state : Nat → Option Bool) :
    Nat → Option Bool :=
  if validSignature && decide (slot ∈ roster) then
    fun other => if other == slot then some reading else state other
  else state

theorem unknown_source_cannot_change_state
    (roster : List Nat) (signatureOK : Bool) (slot : Nat)
    (reading : Bool) (state : Nat → Option Bool)
    (notRegistered : slot ∉ roster) :
    admissionStep roster signatureOK slot reading state = state := by
  simp [admissionStep, notRegistered]

theorem bad_signature_cannot_change_state
    (roster : List Nat) (slot : Nat)
    (reading : Bool) (state : Nat → Option Bool) :
    admissionStep roster false slot reading state = state := by
  simp [admissionStep]

theorem unknown_source_cannot_increase_score
    (roster : List Nat) (signatureOK : Bool) (slot : Nat)
    (reading : Bool) (state : Nat → Option Bool)
    (score : (Nat → Option Bool) → Nat)
    (notRegistered : slot ∉ roster) :
    score (admissionStep roster signatureOK slot reading state) = score state := by
  rw [unknown_source_cannot_change_state roster signatureOK slot reading state notRegistered]

end IdentityAdmission

section LowerEnvelope

variable {Trace : Type}

/- A score is a greatest lower bound of e-values over a set of candidate
   clean traces. The exact Bernoulli count formula is separately tested in
   Python, and is not formalized here. -/
def CertifiedInfimum (evidence : Trace → Nat)
    (admissible : Trace → Prop) (lower : Nat) : Prop :=
  (∀ clean, admissible clean → lower ≤ evidence clean) ∧
  (∀ candidate, (∀ clean, admissible clean → candidate ≤ evidence clean) →
    candidate ≤ lower)

theorem true_trace_dominates_lower_envelope
    (evidence : Trace → Nat) (admissible : Trace → Prop)
    (lower : Nat) (clean : Trace) (threshold : Nat)
    (certified : CertifiedInfimum evidence admissible lower)
    (trueTraceAdmissible : admissible clean)
    (authorized : threshold ≤ lower) :
    threshold ≤ evidence clean := by
  exact Nat.le_trans authorized (certified.1 clean trueTraceAdmissible)

/- Erasing a source or raising the permitted corruption budget can only
   enlarge the candidate set, decreasing its greatest lower bound. -/
theorem candidate_expansion_never_raises_evidence
    (evidence : Trace → Nat) (before after : Trace → Prop)
    (lowerBefore lowerAfter : Nat)
    (candidateInclusion : ∀ clean, before clean → after clean)
    (certificateBefore : CertifiedInfimum evidence before lowerBefore)
    (certificateAfter : CertifiedInfimum evidence after lowerAfter) :
    lowerAfter ≤ lowerBefore := by
  apply certificateBefore.2
  intro clean hBefore
  exact certificateAfter.1 clean (candidateInclusion clean hBefore)

theorem identical_candidate_sets_same_evidence
    (evidence : Trace → Nat) (before after : Trace → Prop)
    (scoreBefore scoreAfter : Nat)
    (sameCandidates : ∀ clean, before clean ↔ after clean)
    (certificateBefore : CertifiedInfimum evidence before scoreBefore)
    (certificateAfter : CertifiedInfimum evidence after scoreAfter) :
    scoreBefore = scoreAfter := by
  apply Nat.le_antisymm
  · apply certificateAfter.2
    intro clean hAfter
    exact certificateBefore.1 clean ((sameCandidates clean).mpr hAfter)
  · apply certificateBefore.2
    intro clean hBefore
    exact certificateAfter.1 clean ((sameCandidates clean).mp hBefore)

end LowerEnvelope

section Anytime

/- Works path by path for ANY pattern of report arrivals or omissions,
   provided every current clean trace is still in the candidate set.
   Turning the event inclusion into an alpha probability bound additionally
   requires a valid nonnegative e-process and Ville's inequality. -/
theorem safe_crossing_is_subset_of_clean_crossing
    (cleanScore lowerScore : Nat → Nat)
    (pathwiseBound : ∀ t, lowerScore t ≤ cleanScore t)
    (threshold : Nat)
    (observedCrossing : ∃ t, threshold ≤ lowerScore t) :
    ∃ t, threshold ≤ cleanScore t := by
  rcases observedCrossing with ⟨t, crossing⟩
  exact ⟨t, Nat.le_trans crossing (pathwiseBound t)⟩

end Anytime

end ACE
