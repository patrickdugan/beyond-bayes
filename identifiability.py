"""Bounded exact identifiability audit for ACE. Research-only; no action authority.

Unary observations anchor a bit; binary observations report XOR parity. A fault
budget counts distinct externally specified source groups, allowing arbitrary
correlated errors within each faulty group. Missing/revoked reports constrain
nothing. Trusted groups are an external assumption, never inferred from votes.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from fractions import Fraction
import hashlib
from itertools import product
import json
from typing import Mapping

MAX_VARIABLES = 12
MAX_SLOTS = 128
MAX_WORK = 2_000_000
SCHEMA = "ace-identifiability-v1"


class WorkLimit(ValueError):
    """A bounded calculation was refused; this is not an inconsistency proof."""


def _name(value: str) -> None:
    if type(value) is not str or not value or len(value) > 128:
        raise ValueError("names must be nonempty strings of at most 128 characters")


def _bit(value: int) -> None:
    if type(value) is not int or value not in (0, 1):
        raise ValueError("a bit must be the integer 0 or 1")


def _natural(value: int, *, positive: bool = False) -> None:
    if type(value) is not int or value < int(positive):
        raise ValueError("expected a nonnegative integer (positive for costs)")


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Slot:
    """A preregistered report slot. Cost describes hypothetical audit effort."""

    id: str
    root: str
    variables: tuple[str, ...]
    cost: int = 1

    def __post_init__(self) -> None:
        _name(self.id)
        _name(self.root)
        _natural(self.cost, positive=True)
        if type(self.variables) is not tuple or len(self.variables) not in (1, 2):
            raise ValueError("a slot must have one or two variables in a tuple")
        for variable in self.variables:
            _name(variable)
        if len(set(self.variables)) != len(self.variables):
            raise ValueError("repeated variables are not admissible")


@dataclass(frozen=True)
class Contract:
    """External model: fixed roster, fault groups, trusted roots and fault cap.

    Roots are fault domains, not statistically independent samples. A digest
    binds the supplied grouping; establishing its truth remains external.
    """

    variables: tuple[str, ...]
    slots: tuple[Slot, ...]
    trusted_roots: tuple[str, ...] = ()
    max_faulty_roots: int = 0

    def __post_init__(self) -> None:
        if type(self.variables) is not tuple or not self.variables:
            raise ValueError("nonempty variable tuple required")
        if len(self.variables) > MAX_VARIABLES:
            raise WorkLimit("variable count exceeds the exact-audit limit")
        for variable in self.variables:
            _name(variable)
        if len(set(self.variables)) != len(self.variables):
            raise ValueError("duplicate variable")
        if type(self.slots) is not tuple or len(self.slots) > MAX_SLOTS:
            raise ValueError("bounded slot tuple required")
        if any(type(slot) is not Slot for slot in self.slots):
            raise ValueError("each slot must be a Slot")
        if len({slot.id for slot in self.slots}) != len(self.slots):
            raise ValueError("duplicate slot ID")
        if any(not set(slot.variables) <= set(self.variables) for slot in self.slots):
            raise ValueError("slot uses an unknown variable")
        if type(self.trusted_roots) is not tuple:
            raise ValueError("trusted roots must be a tuple")
        for root in self.trusted_roots:
            _name(root)
        roots = {slot.root for slot in self.slots}
        if len(set(self.trusted_roots)) != len(self.trusted_roots):
            raise ValueError("duplicate trusted root")
        if not set(self.trusted_roots) <= roots:
            raise ValueError("trusted root is outside the roster")
        _natural(self.max_faulty_roots)
        if self.max_faulty_roots > len(roots - set(self.trusted_roots)):
            raise ValueError("fault budget exceeds the untrusted root count")

    @property
    def digest(self) -> str:
        return _digest({"schema": SCHEMA, "contract": asdict(self)})


@dataclass(frozen=True)
class Event:
    kind: str
    id: str
    value: int | None = None

    def __post_init__(self) -> None:
        _name(self.id)
        if self.kind == "observe":
            _bit(self.value)
        elif self.kind == "revoke":
            if self.value is not None:
                raise ValueError("a revocation has no bit value")
        else:
            raise ValueError("unknown event kind")


@dataclass(frozen=True)
class Snapshot:
    """Immutable event history, preserving earlier observations after revocation.

    Revocation erases a root's constraints and never refunds the fault budget.
    Reinstatement/model changes require a new externally pinned contract.
    """

    contract: Contract
    events: tuple[Event, ...] = ()

    def __post_init__(self) -> None:
        if type(self.contract) is not Contract or type(self.events) is not tuple:
            raise ValueError("Contract and immutable event tuple required")
        self.replay()

    def replay(self) -> tuple[dict[str, int], frozenset[str]]:
        slots = {slot.id: slot for slot in self.contract.slots}
        roots = {slot.root for slot in self.contract.slots}
        if len(self.events) > len(slots) + len(roots):
            raise ValueError("history exceeds the roster's one-use event bound")
        observations: dict[str, int] = {}
        revoked: set[str] = set()
        for event in self.events:
            if type(event) is not Event:
                raise ValueError("history must contain Event objects")
            if event.kind == "observe":
                if event.id not in slots or event.id in observations:
                    raise ValueError("unknown or already observed slot")
                if slots[event.id].root in revoked:
                    raise ValueError("observations from revoked roots are forbidden")
                observations[event.id] = event.value
            else:
                if event.id not in roots or event.id in revoked:
                    raise ValueError("unknown or already revoked root")
                revoked.add(event.id)
        return observations, frozenset(revoked)

    def observe(self, slot: str, value: int) -> Snapshot:
        return Snapshot(self.contract, self.events + (Event("observe", slot, value),))

    def revoke(self, root: str) -> Snapshot:
        return Snapshot(self.contract, self.events + (Event("revoke", root),))

    @property
    def digest(self) -> str:
        return _digest({"contract": self.contract.digest,
                        "events": [asdict(event) for event in self.events]})


def _target(snapshot: Snapshot, target: str) -> int:
    _name(target)
    if target not in snapshot.contract.variables:
        raise ValueError("unknown target")
    return snapshot.contract.variables.index(target)


def _work(snapshot: Snapshot, repetitions: int = 1) -> None:
    estimate = repetitions * (1 << len(snapshot.contract.variables)) * max(
        1, len(snapshot.contract.slots))
    if estimate > MAX_WORK:
        raise WorkLimit("exact audit work limit exceeded")


def compatible_worlds(snapshot: Snapshot) -> tuple[tuple[int, ...], ...]:
    """Enumerate all assignments compatible with the declared corruption model.

    A world fails a root if ANY observed constraint from that root is false.
    Count that root once, regardless of how many clones/reports it produced.
    """
    _work(snapshot)
    observations, revoked = snapshot.replay()
    contract = snapshot.contract
    indices = {variable: i for i, variable in enumerate(contract.variables)}
    trusted = frozenset(contract.trusted_roots)
    rows = [(slot.root, tuple(indices[v] for v in slot.variables), observations[slot.id])
            for slot in contract.slots
            if slot.id in observations and slot.root not in revoked]
    worlds = []
    for world in product((0, 1), repeat=len(indices)):
        bad = set()
        for root, positions, observed in rows:
            prediction = world[positions[0]]
            if len(positions) == 2:
                prediction ^= world[positions[1]]
            if prediction != observed:
                if root in trusted:
                    break
                bad.add(root)
                if len(bad) > contract.max_faulty_roots:
                    break
        else:
            worlds.append(world)
    return tuple(worlds)


def _summary(worlds: tuple[tuple[int, ...], ...], index: int) -> dict:
    examples = {}
    for world in worlds:
        examples.setdefault(str(world[index]), list(world))
    if not worlds:
        status, value = "model_conflict", None
    elif len(examples) == 1:
        status, value = "identified", int(next(iter(examples)))
    else:
        status, value = "undetermined", None
    return {"status": status, "value": value,
            "compatible_world_count": len(worlds), "witnesses": examples}


def diagnose(snapshot: Snapshot, target: str) -> dict:
    """Replayable, unsigned diagnostic receipt; never authorizes an action."""
    index = _target(snapshot, target)
    observations, revoked = snapshot.replay()
    active = [slot for slot in snapshot.contract.slots if slot.root not in revoked]
    return {"schema": SCHEMA, "authorizes_action": False,
            "contract_digest": snapshot.contract.digest,
            "history_digest": snapshot.digest,
            "target": target, "variables": list(snapshot.contract.variables),
            "missing_slots": [slot.id for slot in active if slot.id not in observations],
            "revoked_roots": sorted(revoked),
            **_summary(compatible_worlds(snapshot), index)}


def verify_receipt(receipt: Mapping, snapshot: Snapshot, *,
                   expected_contract_digest: str, expected_history_digest: str,
                   expected_target: str) -> None:
    """Compare to caller-held pins and fully recompute using this implementation.

    Freshness depends on the caller supplying its actual latest history pin.
    This is replay verification, not a second implementation or a signature.
    """
    if (snapshot.contract.digest != expected_contract_digest
            or snapshot.digest != expected_history_digest):
        raise ValueError("external contract/history pin mismatch")
    if _canonical(dict(receipt)) != _canonical(diagnose(snapshot, expected_target)):
        raise ValueError("receipt differs from the full pinned replay")


def credal_target_interval(snapshot: Snapshot, target: str) -> tuple[Fraction, Fraction]:
    """Matched comparator: all point masses on compatible worlds are admissible.

    Returns the exact lower/upper target probability over that credal set.
    An empty model class is an error, never a vacuous interval or certainty.
    """
    index = _target(snapshot, target)
    worlds = compatible_worlds(snapshot)
    if not worlds:
        raise ValueError("empty credal model class")
    values = [world[index] for world in worlds]
    return Fraction(min(values)), Fraction(max(values))


def recommend_audit(snapshot: Snapshot, target: str, budget: int) -> dict | None:
    """Cheapest one-step query resolving target for every compatible reply.

    Forecasts both possible reports under the SAME source-fault model. Queries
    can be untrusted. No reply is obtained and no statistical budget is spent.
    Multi-step planning and operational expenditure belong to future work.
    """
    _natural(budget)
    index = _target(snapshot, target)
    observations, revoked = snapshot.replay()
    eligible = [slot for slot in snapshot.contract.slots
                if slot.id not in observations and slot.root not in revoked
                and slot.cost <= budget]
    _work(snapshot, 1 + 2 * len(eligible))
    if _summary(compatible_worlds(snapshot), index)["status"] != "undetermined":
        return None
    for slot in sorted(eligible, key=lambda item: (item.cost, item.id)):
        branches = {str(bit): _summary(compatible_worlds(snapshot.observe(slot.id, bit)), index)
                    for bit in (0, 1)}
        feasible = [branch for branch in branches.values()
                    if branch["status"] != "model_conflict"]
        if feasible and all(branch["status"] == "identified" for branch in feasible):
            return {"slot": slot.id, "cost": slot.cost, "branches": branches,
                    "contract_digest": snapshot.contract.digest,
                    "history_digest": snapshot.digest, "authorizes_action": False}
    return None


def target_separation(snapshot: Snapshot, target: str) -> dict:
    """Exact root-block distance for opposite target values on the observed roster.

    XOR differences are linear, so enumerate 2**n difference vectors rather
    than 4**n world pairs. A distance greater than 2*k guarantees target
    identification for every admissible transcript under the declared model.
    When the threshold fails, construct a SYNTHETIC colliding transcript.
    """
    index = _target(snapshot, target)
    _work(snapshot, 2)
    contract = snapshot.contract
    observations, revoked = snapshot.replay()
    slots = [s for s in contract.slots if s.id in observations and s.root not in revoked]
    trusted = set(contract.trusted_roots)
    indices = {v: i for i, v in enumerate(contract.variables)}

    def prediction(world, slot):
        return sum(world[indices[v]] for v in slot.variables) % 2

    base = next((w for w in product((0, 1), repeat=len(indices))
                 if all(prediction(w, slot) == observations[slot.id]
                        for slot in slots if slot.root in trusted)), None)
    result = {"contract_digest": contract.digest, "history_digest": snapshot.digest,
              "target": target, "authorizes_action": False,
              "minimum_root_distance": None, "difference_witness": None,
              "uniformly_identifiable_under_declared_model": False,
              "synthetic_collision": None}
    if base is None:
        return dict(result, status="trusted_model_conflict")
    best = None
    best_roots = None
    for difference in product((0, 1), repeat=len(indices)):
        if difference[index] != 1:
            continue
        if any(prediction(difference, slot) for slot in slots if slot.root in trusted):
            continue
        roots = sorted({slot.root for slot in slots
                        if slot.root not in trusted and prediction(difference, slot)})
        if best_roots is None or len(roots) < len(best_roots):
            best, best_roots = difference, roots
            if not roots:
                break
    if best is None:
        return dict(result, status="fixed_by_trusted_observations",
                    uniformly_identifiable_under_declared_model=True)
    distance = len(best_roots)
    result.update(status="bounded_distance", minimum_root_distance=distance,
                  difference_witness=list(best),
                  uniformly_identifiable_under_declared_model=distance > 2 * contract.max_faulty_roots)
    if distance <= 2 * contract.max_faulty_roots:
        other = tuple(x ^ z for x, z in zip(base, best))
        from_other = set(best_roots[:contract.max_faulty_roots])
        reports = {slot.id: prediction(other if slot.root in from_other else base, slot)
                   for slot in slots}
        result["synthetic_collision"] = {
            "label": "constructed counterexample, not observed evidence",
            "worlds": [list(base), list(other)], "reports": reports}
    return result
