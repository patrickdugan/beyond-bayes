"""Synthetic six-arm audit allocation for EvalMath theorem-fidelity defects.

All policies receive the same budget and the same hidden potential audit
outcomes. Audits are conditionally independent given the latent defect.
The terminal decision rule is robust and identical across all six arms.
This is not a calibrated model of AI mathematics or real-world safety.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction as Q
from itertools import product
import json
import random

HYPOTHESES = ("clean", "TF-01", "TF-02", "TF-03", "TF-04", "TF-05", "TF-06")
SEVERITY = {"clean": 0, "TF-01": 8, "TF-02": 5, "TF-03": 6,
            "TF-04": 8, "TF-05": 7, "TF-06": 7}
WITHHOLD_CLEAN_LOSS = 3


@dataclass(frozen=True)
class Audit:
    name: str
    cost: int
    targets: tuple[str, ...]
    sensitivity: Q
    background: Q = Q(1, 20)

    def hit(self, hypothesis: str) -> Q:
        return self.sensitivity if hypothesis in self.targets else self.background


AUDITS = (
    Audit("quantifier_scope", 1, ("TF-01", "TF-03"), Q(9, 10)),
    Audit("constraint_semantics", 2, ("TF-02", "TF-03"), Q(17, 20)),
    Audit("finite_countermodel", 1, ("TF-01", "TF-03", "TF-04"), Q(4, 5)),
    Audit("language_parser", 2, ("TF-04",), Q(19, 20)),
    Audit("complexity_contract", 3, ("TF-05", "TF-06"), Q(9, 10)),
    Audit("formal_replay", 5, tuple(h for h in HYPOTHESES if h != "clean"), Q(19, 20)),
)

NOMINAL = {"clean": Q(3, 5), "TF-01": Q(1, 10), "TF-02": Q(1, 20),
           "TF-03": Q(1, 20), "TF-04": Q(1, 10), "TF-05": Q(1, 20),
           "TF-06": Q(1, 20)}
SHIFTED = {"clean": Q(1, 4), "TF-01": Q(1, 20), "TF-02": Q(1, 20),
           "TF-03": Q(1, 10), "TF-04": Q(1, 10), "TF-05": Q(1, 4),
           "TF-06": Q(1, 5)}
CREDAL_SET = (NOMINAL, SHIFTED)
ARMS = ("uniform", "cheapest", "random", "bayes_evi", "robust_evi", "adversarial")


def check_prior(p: dict[str, Q]) -> None:
    if set(p) != set(HYPOTHESES) or sum(p.values()) != 1 or any(v <= 0 for v in p.values()):
        raise ValueError("prior must have full support and unit mass")


def loss(decision: str, hypothesis: str) -> int:
    if decision == "publish":
        return SEVERITY[hypothesis]
    if decision == "withhold":
        return WITHHOLD_CLEAN_LOSS if hypothesis == "clean" else 0
    raise ValueError("invalid decision")


def expected_loss(prior: dict[str, Q], decision: str) -> Q:
    return sum(prior[h] * loss(decision, h) for h in HYPOTHESES)


def terminal_decision(priors: tuple[dict[str, Q], ...]) -> str:
    return min(("publish", "withhold"), key=lambda d: (max(expected_loss(p, d) for p in priors), d))


def terminal_risk(priors: tuple[dict[str, Q], ...]) -> Q:
    return max(expected_loss(p, terminal_decision(priors)) for p in priors)


def likelihood(audit: Audit, h: str, outcome: bool) -> Q:
    p = audit.hit(h)
    return p if outcome else 1 - p


def update_prior(prior: dict[str, Q], audit: Audit, outcome: bool) -> dict[str, Q]:
    weights = {h: prior[h] * likelihood(audit, h, outcome) for h in HYPOTHESES}
    z = sum(weights.values())
    if not z:
        raise ValueError("outcome outside prior support")
    return {h: weights[h] / z for h in HYPOTHESES}


def posterior_risk(priors: tuple[dict[str, Q], ...], audit: Audit) -> Q:
    """Minimize over binary-contingent policies, then maximize across priors.

    A singleton prior yields ordinary Bayesian expected post-audit risk.
    The robust variant commits to one outcome-dependent decision policy
    before nature selects a prior from the declared credal set.
    """
    decisions = ("publish", "withhold")
    return min(max(sum(p[h] * likelihood(audit, h, o) * loss(policy[int(o)], h)
                       for h in HYPOTHESES for o in (False, True))
                   for p in priors)
               for policy in product(decisions, repeat=2))


def value_of_information(priors: tuple[dict[str, Q], ...], audit: Audit) -> Q:
    return terminal_risk(priors) - posterior_risk(priors, audit)


def choose_arm(arm: str, priors: tuple[dict[str, Q], ...],
               remaining: tuple[Audit, ...], budget: int, rng: random.Random) -> Audit | None:
    allowed = tuple(a for a in remaining if a.cost <= budget)
    if not allowed:
        return None
    if arm == "uniform":
        return allowed[0]  # precommitted, cost-blind audit-category sweep
    if arm == "cheapest":
        return min(allowed, key=lambda a: (a.cost, a.name))
    if arm == "random":
        return rng.choice(allowed)
    if arm == "bayes_evi":
        priors = (priors[0],)
    if arm in ("bayes_evi", "robust_evi"):
        return max(allowed, key=lambda a: (value_of_information(priors, a) / a.cost,
                                           -a.cost, a.name))
    if arm == "adversarial":
        return max(allowed, key=lambda a: (
            max(sum(p[h] * SEVERITY[h] * (a.hit(h) - a.background)
                    for h in HYPOTHESES) for p in priors) / a.cost,
            -a.cost, a.name))
    raise ValueError("unknown arm")


def single_case(arm: str, truth: str, outcomes: dict[str, bool], *,
                budget: int = 5, seed: int = 0) -> dict:
    if truth not in HYPOTHESES or budget < 0 or arm not in ARMS:
        raise ValueError("invalid case")
    rng = random.Random(seed)
    priors = tuple(dict(p) for p in CREDAL_SET)
    remaining = AUDITS
    spent = 0
    selected = []
    while True:
        audit = choose_arm(arm, priors, remaining, budget - spent, rng)
        if audit is None:
            break
        selected.append(audit.name)
        spent += audit.cost
        priors = tuple(update_prior(p, audit, outcomes[audit.name]) for p in priors)
        remaining = tuple(a for a in remaining if a != audit)
    verdict = terminal_decision(priors)
    return {"spent": spent, "selected": selected, "verdict": verdict,
            "loss": loss(verdict, truth),
            "false_confidence": int(truth != "clean" and verdict == "publish"),
            "true_defect_flagged": int(truth != "clean" and
                                       any(outcomes[name] for name in selected))}


def sample_prior(rng: random.Random, prior: dict[str, Q]) -> str:
    u = rng.random()
    total = 0.0
    for h in HYPOTHESES:
        total += float(prior[h])
        if u < total:
            return h
    return HYPOTHESES[-1]


def simulate(trials: int = 1000, seed: int = 10227, budget: int = 5) -> dict:
    if trials < 1 or budget < 0:
        raise ValueError("invalid configuration")
    for p in CREDAL_SET:
        check_prior(p)
    rng = random.Random(seed)
    results = {}
    for world_name, true_prior in (("nominal", NOMINAL), ("shifted", SHIFTED)):
        sums = {arm: {"loss": 0, "false_confidence": 0,
                      "true_defect_flagged": 0, "spent": 0} for arm in ARMS}
        for t in range(trials):
            truth = sample_prior(rng, true_prior)
            # Outcomes are pre-generated but invisible until an audit is chosen.
            # Reusing them produces paired comparisons across allocation arms.
            outcomes = {a.name: rng.random() < float(a.hit(truth)) for a in AUDITS}
            for arm in ARMS:
                result = single_case(arm, truth, outcomes, budget=budget, seed=seed + t)
                for key in sums[arm]:
                    sums[arm][key] += result[key]
        results[world_name] = {
            arm: {key + "_per_trial": sums[arm][key] / trials for key in sums[arm]}
            for arm in ARMS
        }
    return {"seed": seed, "trials_per_world": trials, "budget": budget,
            "worlds": results,
            "note": "Synthetic likelihoods, paired outcomes, common robust terminal decision; no real-model calibration."}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--trials", type=int, default=1000)
    p.add_argument("--seed", type=int, default=10227)
    p.add_argument("--budget", type=int, default=5)
    p.add_argument("--output")
    args = p.parse_args()
    result = simulate(args.trials, args.seed, args.budget)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        from pathlib import Path
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
