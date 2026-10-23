/-
# ACE Foundations (Lean 4, core-only)

A deliberately small proof boundary: clone invariance, monotonic survival under
hard constraints, provenance-path robustness, and the deterministic event
inclusion behind robust e-processes. All theorems are conditional on their
stated assumptions. There are no probability measures or Ville inequality
formalized in this file.

Lean compilation has not been verified in the development container; use
`lean lean/ACE/Foundations.lean` or the accompanying CI workflow.
-/

import Lean

namespace ACE

/- A copied report with an already present root does not add a new root. -/
section Provenance

variable {Root : Type}

theorem root_clone_invariance
    (reports : List Root) (root : Root) (hasRoot : root ∈ reports) :
    ∀ candidate : Root,
      (candidate ∈ root :: reports) ↔ (candidate ∈ reports) := by
  intro candidate
  constructor
  · intro h
    simp only [List.mem_cons] at h
    rcases h with same | already
    · simpa [same] using hasRoot
    · exact already
  · intro h
    simp only [List.mem_cons]
    exact Or.inr h

end Provenance

/- Additional constraints can remove candidates, never restore them. -/
section Survival

variable {Model : Type}

def Survives (constraints : List (Model → Prop)) (model : Model) : Prop :=
  ∀ condition, condition ∈ constraints → condition model

theorem extra_constraint_shrinks_survivors
    (constraints : List (Model → Prop)) (extra : Model → Prop)
    (model : Model) (h : Survives (extra :: constraints) model) :
    Survives constraints model := by
  intro condition hc
  exact h condition (by simp [hc])

theorem append_constraints_shrinks_survivors
    (constraints extra : List (Model → Prop)) (model : Model)
    (h : Survives (constraints ++ extra) model) :
    Survives constraints model := by
  intro condition hc
  exact h condition (by simp [hc])

end Survival

/- Source integrity is a family of support paths and an attacker cut budget.
   Corruptible nodes may include roots and intermediate channels. The claimed
   output itself is never meant to be counted as a corruptible channel. -/
section SourceCuts

variable {Node : Type}

def Hits (attack path : List Node) : Prop :=
  ∃ node, node ∈ attack ∧ node ∈ path

def IsCut (paths : List (List Node)) (attack : List Node) : Prop :=
  ∀ path, path ∈ paths → Hits attack path

def Vulnerable (paths : List (List Node))
    (allowed : List Node) (budget : Nat) : Prop :=
  ∃ attack, attack.length ≤ budget ∧
    (∀ node, node ∈ attack → node ∈ allowed) ∧
    IsCut paths attack

def Robust (paths : List (List Node))
    (allowed : List Node) (budget : Nat) : Prop :=
  ¬ Vulnerable paths allowed budget

theorem cut_extended_restricts
    (base extra : List (List Node)) (attack : List Node)
    (h : IsCut (base ++ extra) attack) :
    IsCut base attack := by
  intro path hPath
  exact h path (by simp [hPath])

theorem new_support_preserves_robustness
    (base extra : List (List Node)) (allowed : List Node) (budget : Nat)
    (h : Robust base allowed budget) :
    Robust (base ++ extra) allowed budget := by
  intro compromised
  apply h
  rcases compromised with ⟨attack, withinBudget, legal, cutsAll⟩
  exact ⟨attack, withinBudget, legal,
    cut_extended_restricts base extra attack cutsAll⟩

theorem duplicate_path_preserves_cut
    (base : List (List Node)) (path attack : List Node)
    (appears : path ∈ base) :
    IsCut (path :: base) attack ↔ IsCut base attack := by
  constructor
  · intro h other hOther
    exact h other (by simp [hOther])
  · intro h other hOther
    simp only [List.mem_cons] at hOther
    rcases hOther with same | appeared
    · rw [same]
      exact h path appears
    · exact h other appeared

theorem duplicate_path_preserves_vulnerability
    (base : List (List Node)) (path : List Node)
    (allowed : List Node) (budget : Nat) (appears : path ∈ base) :
    Vulnerable (path :: base) allowed budget ↔
      Vulnerable base allowed budget := by
  constructor
  · intro h
    rcases h with ⟨attack, lengthOK, legal, cutsAll⟩
    exact ⟨attack, lengthOK, legal,
      (duplicate_path_preserves_cut base path attack appears).mp cutsAll⟩
  · intro h
    rcases h with ⟨attack, lengthOK, legal, cutsAll⟩
    exact ⟨attack, lengthOK, legal,
      (duplicate_path_preserves_cut base path attack appears).mpr cutsAll⟩

end SourceCuts

/- Pathwise domination is the purely logical part of robust e-process
   validity. The probabilistic Ville bound must be supplied separately. -/
section Evidence

variable {Trace : Type}

theorem crossing_of_lower_envelope
    (baseEvidence robustEvidence : Trace → Nat)
    (consistent : Trace → Trace → Prop)
    (lowerBound : ∀ clean observed, consistent clean observed →
      robustEvidence observed ≤ baseEvidence clean)
    {clean observed : Trace} (admissible : consistent clean observed)
    {threshold : Nat} (crossed : threshold ≤ robustEvidence observed) :
    threshold ≤ baseEvidence clean := by
  exact Nat.le_trans crossed (lowerBound clean observed admissible)

theorem anytime_crossing_event_inclusion
    (cleanEvidence robustEvidence : Nat → Nat)
    (dominates : ∀ time, robustEvidence time ≤ cleanEvidence time)
    (threshold : Nat)
    (crossed : ∃ time, threshold ≤ robustEvidence time) :
    ∃ time, threshold ≤ cleanEvidence time := by
  rcases crossed with ⟨time, proof⟩
  exact ⟨time, Nat.le_trans proof (dominates time)⟩

end Evidence

end ACE
