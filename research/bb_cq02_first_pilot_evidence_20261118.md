# BB-CQ-02 first native-model continuation result: provisional negative

**18 November 2026 | Post-result evidence record | `PROVISIONAL_NEGATIVE_UNREPLAYED`.**

This result belongs to the prospective BB-CQ-02 contract in [the previous research note](bb_cq02_native_recurrent_continuation.md). The frozen source resides in [Control-Harness PR #67](https://github.com/MoralityLabAI/Control-Harness/pull/67), with its original numeric first-score log at [CI #44285696950](https://github.com/MoralityLabAI/Control-Harness/actions/runs/44285696950) and the [detailed provenance report](https://github.com/MoralityLabAI/Control-Harness/blob/research/bb-cq02-frozen-recurrent-projection/reports/bb_cq02_first_development.md).

## Source-level observation

The first scorer used **64 new host-entropy synthetic block roots**, containing **290 source issuers** and 1,536 case decisions per arm. The same frozen original ECA-04 trained GRU checkpoint, SHA256 `49bf2db1316942a23b91943843eb0398043c806cadd40421371af571aa15b3d8`, was evaluated with the two-dimensional present-logit projection, two equal-dose readout-null shams, and historical/robust Bayesian controls.

| Registered endpoint | First scorer output |
|---|---:|
| Projected-to-original six-step continuation TV | 0.07768896 |
| Required maximum for approximate closure | 0.05 |
| Sham A continuation TV minus projected continuation TV | -0.01854431 |
| Paired 64-block descriptive bootstrap 95% interval | [-0.03390753, -0.00380996] |
| Predeclared positive improvement floor | +0.02 |
| Maximum independent-block shim-sham difference | 0.16247441 |
| Registered development gate | **REDESIGN_OR_STOP** |
| Exact factor-ledger vs independent Bayes replay TV | 0.0 |
| Mean stale posterior vs post-revocation active Bayes TV | 0.09532506 |

The proposed rank-two projector retains current class probabilities in exact linear algebra, and the development scorer reports that it loses subsequent native recurrent predictive information. The registered approximate-closure and matched-sham improvement gates fail. Its sampled error against the frozen GRU is greater than one equally dosed randomized nullspace intervention's mean error.

For the **same 1,536 synthetic cases**, the logged cost-2 task loss was full frozen GRU 410, rank-two projected GRU 426, sham A 424 and sham B 414. Under named removal of one three-sentinel evidence bundle, exact source-factor replay and exact nine-event full-history Bayes both scored 416. A stale twelve-event posterior scored 415; that coincidental discrete loss proximity does not erase its observed posterior drift.

## Verification and scope

The original pilot's source tests and primary scorer completed. An independent audit incorrectly compared the scorer's Python tuples to JSON-decoded lists, and the workflow skipped artifact publication when audit failed. **Raw original 64-root seed bytes and per-root results are unavailable for fresh independent replay.** The original numeric output therefore has an explicit provenance limitation and must not be treated as a fully reproduced registered neural finding. The post-result audit code and its test now use JSON-normalized value comparison; future workflows publish raw cohort receipts before any optional replay.

The first trial has already exposed the development outcome. No additional BB-CQ-02-v1 random cohort will be presented as a replacement first readout. The prospective stop gate is retained. Any new architecture or independent future cohort requires a fresh protocol, untouched roots and a new causal resolution/power preflight.

## Mathematical consequences for Beyond Bayes

The negative direction is predicted by the distinction between **output equivalence at one time** and **continuation equivalence**. For current classifier difference matrix `D` and recurrent transition `F_e`, exact closure of the quotient `q(h)=D h` requires

```
D h = D h'  =>  D F_e(h) = D F_e(h')
```

for every admissible future input `e` and reachable pair. Under differentiability on convex fibers, the equivalent local requirement is `D J_(F_e)(h) v = 0` for every `v in ker(D)`. The projected physical intervention supplies one dose/horizon probe of this property. Its measured deficit concerns the **specific orthogonal projection**, with one frozen model seed, and does not rule out different low-dimensional nonlinear quotient maps.

The independent exact Bayes revocation algebra uses a **factor bank indexed by source/provenance bundle**, consistent with the existing [Dot Matrix memory lower bound](dot_matrix_continuation_sufficiency_v0_1.md) and the [source-group identifiability model](broken_verifier_identifiability.md). Two probabilities suffice for appending observations in a fixed three-regime model; recovering a named revoked source's contribution requires retained group-indexed factors or an accessible historical replay. This is classical probabilistic reasoning carried forward in an auditable evidence contract.

A future mathematically motivated redesign could compute a reachable-observation closure of the classifier readout using successive recurrent Jacobians, then test its rank and intervention fidelity at a prespecified horizon. The full-history and exact Bayes controls must remain. The current negative outcome offers no reason to spend a new confirmation cohort on the simple classifier-row-space projector.
