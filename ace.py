"""ACE v0.1: an educational prototype of adversarial constraint epistemics.

This is an experimental research scaffold, not a validated statistical package.
Statistical guarantees belong to the e-process under its stated null model.
Source grouping is a provenance safeguard, not an inference of independence.
"""

from dataclasses import dataclass
import math
from typing import Dict, Iterable, Mapping, Optional


class EvidenceConflict(ValueError):
    """Reports tracing to the same raw observation disagree."""


class UncertifiedIndependence(ValueError):
    """A calculation requires an explicit independence assumption."""


@dataclass(frozen=True)
class Report:
    report_id: str
    root_observation_id: str
    likelihood_ratio: float

    def __post_init__(self):
        if not math.isfinite(self.likelihood_ratio) or self.likelihood_ratio <= 0:
            raise ValueError("likelihood ratio must be positive and finite")


class ProvenanceLedger:
    """Deduplicate downstream copies of an observation before inference.

    Important: different root IDs need not be independent. The caller must
    certify *conditional* independence before multiplying their factors.
    A full ACE engine would verify source-specific DAG assumptions.
    """

    def __init__(self) -> None:
        self._reports: Dict[str, Report] = {}

    def add(self, report: Report) -> None:
        if report.report_id in self._reports:
            raise ValueError(f"duplicate report ID: {report.report_id}")
        self._reports[report.report_id] = report

    def root_factors(self) -> Dict[str, float]:
        result: Dict[str, float] = {}
        for report in self._reports.values():
            root = report.root_observation_id
            if root in result and not math.isclose(
                result[root], report.likelihood_ratio, rel_tol=1e-12, abs_tol=1e-12
            ):
                raise EvidenceConflict(f"conflicting factors attributed to root {root}")
            result[root] = report.likelihood_ratio
        return result

    def independent_origin_count(self) -> int:
        """Number of distinct *claimed* root observations, not verified independence."""
        return len(self.root_factors())

    def evidence_factor(self, *, conditional_independence_certified: bool = False) -> float:
        roots = self.root_factors()
        if len(roots) > 1 and not conditional_independence_certified:
            raise UncertifiedIndependence(
                "Cannot multiply across separate roots until conditional independence is certified"
            )
        return math.prod(roots.values())


class BernoulliEProcess:
    """Test a simple Bernoulli null p against a predictable Bernoulli bet q.

    Product_i q(Y_i) / p(Y_i) is a nonnegative martingale under iid null p,
    so P_p(sup_t E_t >= 1/alpha) <= alpha by Ville's inequality.
    """

    def __init__(self, null_p: float, alternative_p: float, alpha: float = .05):
        if not (0 < null_p < 1 and 0 < alternative_p < 1 and 0 < alpha < 1):
            raise ValueError("p, q, and alpha must be in (0,1)")
        self.null_p = null_p
        self.alternative_p = alternative_p
        self.alpha = alpha
        self.n = 0
        self.log_e = 0.0
        self.max_log_e = 0.0

    def observe(self, outcome: int, *, alternative_p: Optional[float] = None) -> None:
        if outcome not in (0, 1):
            raise ValueError("Bernoulli outcome must be 0 or 1")
        q = self.alternative_p if alternative_p is None else alternative_p
        if not (0 < q < 1):
            raise ValueError("predictable bet must be in (0,1)")
        p = self.null_p
        self.log_e += math.log(q / p) if outcome else math.log((1-q) / (1-p))
        self.max_log_e = max(self.max_log_e, self.log_e)
        self.n += 1

    @property
    def evidence(self) -> float:
        return math.exp(self.log_e)

    @property
    def rejected(self) -> bool:
        return self.max_log_e >= math.log(1 / self.alpha)

    @property
    def maximum_evidence(self) -> float:
        return math.exp(self.max_log_e)


def surviving_models(
    observations: Iterable[int], candidates: Mapping[str, float], *,
    alternative_p: float, alpha: float = .05
) -> Dict[str, BernoulliEProcess]:
    tests = {
        name: BernoulliEProcess(null_p=p, alternative_p=alternative_p, alpha=alpha)
        for name, p in candidates.items()
    }
    for y in observations:
        for test in tests.values():
            test.observe(y)
    return {name: test for name, test in tests.items() if not test.rejected}


def minimax_regret(cost_by_model: Mapping[str, Mapping[str, float]]):
    """Find an action minimizing max regret over live models.

    Entries are expected losses from the *interventional* model for that action.
    The caller must estimate those from a causal design, not correlations.
    """
    if not cost_by_model:
        raise ValueError("At least one live model is required")
    actions = set(next(iter(cost_by_model.values())))
    if not actions or any(set(costs) != actions for costs in cost_by_model.values()):
        raise ValueError("Every model must provide costs for the same actions")
    regrets = {
        action: max(costs[action] - min(costs.values()) for costs in cost_by_model.values())
        for action in actions
    }
    best = min(sorted(actions), key=lambda action: (regrets[action], action))
    return best, dict(sorted(regrets.items()))

class SupportGraph:
    """Small DAG of evidence-carrying channels for a claim.

    A minimum channel cut is the fewest *allowed-to-be-corrupted* nodes that
    hit every root-to-claim support path. This is a topological resilience
    number, not a likelihood or a certificate that a source tells the truth.
    The naive hitting-set search is deliberately limited to small graphs.
    """

    def __init__(self, roots: Iterable[str]):
        self.roots = frozenset(roots)
        self.edges: Dict[str, set[str]] = {}

    def _reachable(self, source: str, target: str) -> bool:
        pending = [source]
        seen = set()
        while pending:
            node = pending.pop()
            if node == target:
                return True
            if node not in seen:
                seen.add(node)
                pending.extend(self.edges.get(node, ()))
        return False

    def add_path(self, *nodes: str) -> None:
        if len(nodes) < 2:
            raise ValueError("path requires at least two nodes")
        for parent, child in zip(nodes, nodes[1:]):
            if parent == child or self._reachable(child, parent):
                raise ValueError("evidence graph must remain acyclic")
            self.edges.setdefault(parent, set()).add(child)
            self.edges.setdefault(child, set())

    def support_paths(self, claim: str, max_paths: int = 10000):
        paths: list[frozenset[str]] = []

        def walk(node: str, trail: tuple[str, ...]):
            if node == claim:
                paths.append(frozenset(trail))
                if len(paths) > max_paths:
                    raise ValueError("too many support paths for prototype")
                return
            for child in sorted(self.edges.get(node, ())):
                walk(child, trail + (child,))

        for root in sorted(self.roots):
            walk(root, (root,))
        return paths

    def minimum_channel_cut(self, claim: str, *, corruptible: Optional[Iterable[str]] = None) -> float:
        """Polynomial-time vertex-capacitated max-flow implementation."""
        from mincut import minimum_channel_cut_flow
        return minimum_channel_cut_flow(self.roots, self.edges, claim, corruptible)

    def minimum_channel_cut_bruteforce(self, claim: str, *, corruptible: Optional[Iterable[str]] = None) -> float:
        """Exhaustive path-hitting-set oracle for small-graph tests."""
        from itertools import combinations
        paths = self.support_paths(claim)
        if not paths:
            return 0
        vertices = set().union(*paths) - {claim}
        candidate_nodes = vertices if corruptible is None else vertices.intersection(corruptible)
        if len(candidate_nodes) > 18:
            raise ValueError("prototype cut search is limited to 18 corruptible nodes")
        if any(not path.intersection(candidate_nodes) for path in paths):
            return math.inf
        ordered = sorted(candidate_nodes)
        for size in range(1, len(ordered) + 1):
            for subset in combinations(ordered, size):
                removed = set(subset)
                if all(path.intersection(removed) for path in paths):
                    return size
        return math.inf
