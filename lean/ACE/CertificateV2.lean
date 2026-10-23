/-
ACE v0.7: structure-level binding of decision certificates to externally
supplied commitments. All proofs are unconditional propositional statements.

Limit: Ed25519 security, Merkle log completeness, soundness of the Python
parser/scorer, and the conditional e-process model are separate premises.
-/
import Lean

namespace ACE.CertificateV2

structure Pins where
  protocol : String
  witnessPolicy : String
  clusterPlan : String
  action : String
  authorization : String
  deriving DecidableEq

/-- All five commitments must match trusted values, and v2 is mandatory. -/
def accepted (expected embedded : Pins) (version : Nat) : Prop :=
  version = 2 ∧
  expected.protocol = embedded.protocol ∧
  expected.witnessPolicy = embedded.witnessPolicy ∧
  expected.clusterPlan = embedded.clusterPlan ∧
  expected.action = embedded.action ∧
  expected.authorization = embedded.authorization

theorem v1_rejected (expected embedded : Pins) :
    ¬ accepted expected embedded 1 := by
  intro h
  have impossible : (1 : Nat) = 2 := h.1
  cases impossible

theorem pinned_cluster_plan (expected embedded : Pins) (v : Nat)
    (ok : accepted expected embedded v) :
    expected.clusterPlan = embedded.clusterPlan := by
  exact ok.2.2.2.1

theorem pinned_action (expected embedded : Pins) (v : Nat)
    (ok : accepted expected embedded v) :
    expected.action = embedded.action := by
  exact ok.2.2.2.2.1

theorem altered_action_denied (expected embedded : Pins) (v : Nat)
    (different : expected.action ≠ embedded.action) :
    ¬ accepted expected embedded v := by
  intro ok
  exact different (pinned_action expected embedded v ok)

theorem altered_cluster_denied (expected embedded : Pins) (v : Nat)
    (different : expected.clusterPlan ≠ embedded.clusterPlan) :
    ¬ accepted expected embedded v := by
  intro ok
  exact different (pinned_cluster_plan expected embedded v ok)

/-- The decision layer admits only outcomes satisfying externally pinned
commitments and the independently replayed authorization proposition. -/
def permits (expected embedded : Pins) (version : Nat)
    (replayedAuthorization : Prop) : Prop :=
  accepted expected embedded version ∧ replayedAuthorization

theorem permitted_implies_replayed (expected embedded : Pins) (v : Nat)
    (actual : Prop) (authorized : permits expected embedded v actual) : actual :=
  authorized.2

theorem permitted_implies_cluster_pin (expected embedded : Pins) (v : Nat)
    (actual : Prop) (authorized : permits expected embedded v actual) :
    expected.clusterPlan = embedded.clusterPlan :=
  pinned_cluster_plan expected embedded v authorized.1

end ACE.CertificateV2
