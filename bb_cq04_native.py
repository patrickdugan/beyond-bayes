"""BB-CQ-04 original frozen GRU CPU development readout.

Only call after source-only registration/verification. The native checkpoint is
supplied explicitly, verified byte-for-byte against ECA-04 original SHA-256.
The two cohorts are PUBLIC deterministic generator fixtures, NOT sealed
prospective samples. The older ECA-04 heldout seeds/rows are never loaded.
All root-level costs integrate out future case and audit response randomness.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import random
import statistics
from typing import Sequence

from bb_cq04_core import (
    ARMS, CALIBRATION_ROOTS, CASE_PRIORS, DOMAIN, N, ORIGINAL_MODEL_SHA256,
    PILOT_ROOTS, PRACTICAL_FLOOR, PRIORS, brier, exact_population,
    expected_authorization_cost, make_root, policy_action,
    verified_replacement,
)


def _native_model(checkpoint: Path):
    import torch
    from torch import nn
    torch.set_num_threads(1)
    if sha256(checkpoint.read_bytes()).hexdigest() != ORIGINAL_MODEL_SHA256:
        raise ValueError("frozen ECA-04 model hash mismatch")
    class OriginalECA04(nn.Module):
        def __init__(self):
            super().__init__()
            self.gru = nn.GRU(2, 16, batch_first=True)
            self.classifier = nn.Linear(16, 3)

        def forward(self, x):
            if tuple(x.shape[-2:]) != (N,2):
                raise ValueError("expected twelve two-bit sentinel features")
            return self.classifier(self.gru(x)[1][-1])

    model = OriginalECA04()
    model.load_state_dict(torch.load(checkpoint,weights_only=True,map_location="cpu"),
                          strict=True)
    model.eval()
    for p in model.parameters():
        p.requires_grad_(False)
    return model


def _infer(model, records: Sequence[tuple[tuple[int,int],...]]) -> list[tuple[float,float,float]]:
    import torch
    if not records:
        return []
    x = torch.tensor(records, dtype=torch.float32)
    with torch.no_grad():
        outputs = []
        for batch in x.split(128):
            outputs.extend(torch.softmax(model(batch),-1).cpu().tolist())
    probs = [tuple(map(float,p)) for p in outputs]
    if any(len(p)!=3 or abs(sum(p)-1)>1e-5 or any(v<0 or not v<float("inf") for v in p)
           for p in probs):
        raise AssertionError("invalid native probability")
    return probs


def _permutation_controls(model, roots, source_probs, shams: int=8) -> dict:
    """A nuisance control using the same accepted report multiset and count."""
    all_inputs=[]
    owners=[]
    for i,root in enumerate(roots):
        for j in range(shams):
            seed=sha256(f"{DOMAIN}order-sham/{i}/{j}".encode()).digest()
            rng=random.Random(int.from_bytes(seed,"big"))
            records=list(root.accepted)
            rng.shuffle(records)
            all_inputs.append(tuple(records))
            owners.append(i)
    preds=_infer(model,all_inputs)
    gaps={i:[] for i in range(len(roots))}
    mean_abs_tv=[]
    for i,p in zip(owners,preds):
        true=roots[i].regime
        original=source_probs[i]
        loss_delta=abs(float(expected_authorization_cost(p,true)-
                             expected_authorization_cost(original,true)))
        gaps[i].append(loss_delta)
        mean_abs_tv.append(sum(abs(a-b) for a,b in zip(p,original))/2)
    max_spread=[max(gaps[i]) for i in range(len(roots))]
    return {
        "shams_per_independent_calibration_root":shams,
        "independent_public_calibration_roots":len(roots),
        "calibration_mean_root_max_order_loss_variation":statistics.mean(max_spread),
        "calibration_max_root_order_loss_variation":max(max_spread),
        "calibration_mean_order_probability_TV":statistics.mean(mean_abs_tv),
        "interpretation":"public development nuisance screen; not a statistical 95/95 sham tolerance certificate",
    }


def bootstrap_interval(effects:Sequence[float],seed:int,reps:int=4096) -> list[float]:
    if len(effects)<2:
        raise ValueError("requires at least two independent roots")
    rng=random.Random(seed)
    n=len(effects)
    stats=sorted(sum(effects[rng.randrange(n)] for _ in range(n))/n
                 for _ in range(reps))
    return [stats[int(.025*reps)],stats[min(reps-1,int(.975*reps))]]


def _policy_action_change(a,b) -> int:
    return sum(policy_action(a,p,r)!=policy_action(b,p,r)
               for p in CASE_PRIORS for r in (0,1))


def run(checkpoint: Path, out_dir: Path) -> dict:
    import torch
    model=_native_model(checkpoint)
    calibration=[make_root("calibration",i) for i in range(CALIBRATION_ROOTS)]
    pilot=[make_root("pilot",i) for i in range(PILOT_ROOTS)]
    roots=calibration+pilot
    assert len({root.id for root in roots})==len(roots)
    clean_probs=_infer(model,[root.accepted for root in roots])
    before_probs={
        j:_infer(model,[root.frames(j)[0] for root in roots]) for j in ARMS
    }

    nuisance=_permutation_controls(model,calibration,clean_probs[:CALIBRATION_ROOTS])
    rows=[]
    for idx,root in enumerate(roots):
        role="calibration" if idx<CALIBRATION_ROOTS else "pilot"
        for j in ARMS:
            report=verified_replacement(root,j)
            fine=report["fine_posterior"]
            coarse=report["coarse_posterior"]
            fresh=clean_probs[idx]
            stale=before_probs[j][idx]
            policies={
                "full_exact":fine,
                "delta_exact":report["delta_posterior"],
                "aggregate_optimal":coarse,
                "native_replay":fresh,
                "native_stale":stale,
                "pooled_prior":PRIORS,
                "true_regime":tuple(int(k==root.regime) for k in range(3)),
            }
            if policies["full_exact"]!=policies["delta_exact"]:
                raise AssertionError("source-aware replay disagreement")
            costs={arm:float(expected_authorization_cost(prob,root.regime))
                   for arm,prob in policies.items()}
            scores={arm:brier(prob,root.regime) for arm,prob in policies.items()}
            rows.append({
                "cohort":role,
                "root_sha256":root.id,
                "j":j,
                "host_regime":root.regime,
                "old_match_count":report["old_match_count"],
                "new_match_count":report["new_amended_match_count"],
                "changed_provisional_records":report["changed_report_bits"],
                "final_archive_digest":report["archive_digest"],
                "task_cost_per_case":costs,
                "regime_brier":scores,
                "fresh_vs_stale_native_decision_disagreements":
                    _policy_action_change(fresh,stale),
                "full_vs_coarse_bayes_decision_disagreements":
                    _policy_action_change(fine,coarse),
                "native_replay_probability_TV_from_full_bayes":
                    sum(abs(float(x)-y) for x,y in zip(fine,fresh))/2,
            })

    out_dir.mkdir(parents=True,exist_ok=True)
    rows_name="bb_cq04_native_dev_rows.jsonl"
    rows_bytes="".join(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n"
                       for row in rows).encode("utf-8")
    (out_dir/rows_name).write_bytes(rows_bytes)
    summary={}
    for j in ARMS:
        group=[r for r in rows if r["cohort"]=="pilot" and r["j"]==j]
        assert len(group)==PILOT_ROOTS
        arms=tuple(group[0]["task_cost_per_case"])
        mean_cost={arm:statistics.mean(r["task_cost_per_case"][arm] for r in group)
                   for arm in arms}
        mean_brier={arm:statistics.mean(r["regime_brier"][arm] for r in group)
                    for arm in arms}
        delta=[r["task_cost_per_case"]["native_stale"]-
               r["task_cost_per_case"]["native_replay"] for r in group]
        exact_delta=[r["task_cost_per_case"]["aggregate_optimal"]-
                     r["task_cost_per_case"]["full_exact"] for r in group]
        summary[str(j)]={
            "j":j,
            "pilot_root_count":len(group),
            "mean_expected_task_cost_per_case":mean_cost,
            "mean_regime_brier":mean_brier,
            "native_replay_benefit_over_stale":statistics.mean(delta),
            "native_replay_benefit_descriptive_paired_95_bootstrap":
                bootstrap_interval(delta,20261118+j),
            "sourceaware_benefit_over_coarse":statistics.mean(exact_delta),
            "sourceaware_benefit_descriptive_paired_95_bootstrap":
                bootstrap_interval(exact_delta,20261218+j),
            "mean_native_stale_vs_replay_decision_disagreements_of_10":
                statistics.mean(r["fresh_vs_stale_native_decision_disagreements"] for r in group),
            "mean_full_vs_coarse_decision_disagreements_of_10":
                statistics.mean(r["full_vs_coarse_bayes_decision_disagreements"] for r in group),
            "total_changed_provisional_reports":
                sum(r["changed_provisional_records"] for r in group),
            "native_replay_cost_vs_full_exact":
                mean_cost["native_replay"]-mean_cost["full_exact"],
            "native_replay_mean_TV_from_exact":
                statistics.mean(r["native_replay_probability_TV_from_full_bayes"] for r in group),
        }
    full=exact_population(6)
    exact_headroom=float(full["coarse_minus_fine_cost"])
    main_gate="HEADROOM_PASS" if exact_headroom >= float(PRACTICAL_FLOOR) else "HEADROOM_BLOCKED"
    result={
        "schema":"ace-bb-cq04-native-first-development-v1",
        "evidence_class":"public_deterministic_development_only",
        "source_generator_domain":DOMAIN,
        "checkpoint_sha256":ORIGINAL_MODEL_SHA256,
        "python_torch_version":torch.__version__,
        "pilot_independent_roots":PILOT_ROOTS,
        "calibration_independent_roots":CALIBRATION_ROOTS,
        "source_aware_exact_delta_parity":True,
        "original_eca04_test_roots_used":False,
        "protected_confirmation_roots_used":0,
        "all_arms_reported":True,
        "rows_file":rows_name,
        "rows_sha256":sha256(rows_bytes).hexdigest(),
        "source_only_exact_headroom_j6":exact_headroom,
        "registered_science_minimum":float(PRACTICAL_FLOOR),
        "primary_headroom_gate":main_gate,
        "native_mechanism_claim":"NOT_TESTED",
        "order_nuisance_calibration":nuisance,
        "pilot_results":summary,
    }
    (out_dir/"bb_cq04_native_dev_summary.json").write_text(
        json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return result


def main()->None:
    parser=argparse.ArgumentParser()
    parser.add_argument("--checkpoint",type=Path,required=True)
    parser.add_argument("--out-dir",type=Path,required=True)
    args=parser.parse_args()
    result=run(args.checkpoint,args.out_dir)
    print(json.dumps({k:v for k,v in result.items() if k not in ("pilot_results",)},
                     indent=2,sort_keys=True))
    for j,r in result["pilot_results"].items():
        print("j="+j+" native fresh minus stale:",
              -r["native_replay_benefit_over_stale"],
              "exact coarse minus fine:",r["sourceaware_benefit_over_coarse"])


if __name__=="__main__":
    main()
