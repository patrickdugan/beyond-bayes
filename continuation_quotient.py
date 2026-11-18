"""Exact finite continuation-equivalence diagnostic for ACE research.

This module analyzes declared finite deterministic transition contracts. It does
not authenticate observations, establish stochastic validity, or authorize any
protected action. Invalid events need an explicit sink state when admissibility
is part of the contract.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from itertools import combinations
from typing import Sequence

MAX_STATES = 256
MAX_ACTIONS = 32


@dataclass(frozen=True)
class FiniteMachine:
    """Total deterministic machine with an output at every state.

    transitions[state][action] is the index of the successor state. The state
    names and event alphabet are part of the externally selected contract.
    """

    states: tuple[str, ...]
    actions: tuple[str, ...]
    outputs: tuple[str, ...]
    transitions: tuple[tuple[int, ...], ...]

    def __post_init__(self) -> None:
        if not self.states or len(self.states) > MAX_STATES:
            raise ValueError("state count outside the finite-audit range")
        if len(self.actions) > MAX_ACTIONS:
            raise ValueError("event count outside the finite-audit range")
        for items in (self.states, self.actions, self.outputs):
            if type(items) is not tuple or any(type(v) is not str or not v for v in items):
                raise ValueError("names and outputs must be nonempty strings in tuples")
        if len(set(self.states)) != len(self.states) or len(set(self.actions)) != len(self.actions):
            raise ValueError("duplicate state or event name")
        n = len(self.states)
        if len(self.outputs) != n or type(self.transitions) is not tuple or len(self.transitions) != n:
            raise ValueError("each state requires one output and one transition row")
        for row in self.transitions:
            if type(row) is not tuple or len(row) != len(self.actions):
                raise ValueError("transition rows must cover the declared alphabet")
            if any(type(dst) is not int or not 0 <= dst < n for dst in row):
                raise ValueError("transition target is outside the state space")


def _partition(keys: Sequence[object]) -> tuple[int, ...]:
    ids: dict[object, int] = {}
    result: list[int] = []
    for key in keys:
        if key not in ids:
            ids[key] = len(ids)
        result.append(ids[key])
    return tuple(result)


def _refine(machine: FiniteMachine, current: tuple[int, ...]) -> tuple[int, ...]:
    return _partition(tuple((current[s], tuple(current[t] for t in machine.transitions[s]))
                            for s in range(len(machine.states))))


def quotient_partition(machine: FiniteMachine, *, horizon: int | None = None,
                       retained_labels: Sequence[str] | None = None) -> tuple[int, ...]:
    """Greatest output-preserving right congruence; optional horizon H.

    H=0 compares present outputs. H+1 additionally compares one step followed
    by an H-step continuation. A fixed-H partition alone does *not* define a
    same-H online updater: the next event consumes one unit of that horizon.

    With retained_labels, the quotient preserves that label at every future
    step as well as the machine output. This is the coarsest stable refinement
    of the original representation, which is stronger than output equivalence.
    """
    if horizon is not None and (type(horizon) is not int or horizon < 0):
        raise ValueError("horizon must be a nonnegative integer or None")
    if retained_labels is not None:
        labels = _labels(machine, retained_labels)
        current = _partition(tuple((o, z) for o, z in zip(machine.outputs, labels)))
    else:
        current = _partition(machine.outputs)
    rounds = len(machine.states) if horizon is None else min(horizon, len(machine.states))
    for _ in range(rounds):
        nxt = _refine(machine, current)
        if nxt == current:
            break
        current = nxt
    return current


def _labels(machine: FiniteMachine, labels: Sequence[str]) -> tuple[str, ...]:
    if len(labels) != len(machine.states) or any(type(v) is not str or not v for v in labels):
        raise ValueError("each state needs a nonempty representation label")
    return tuple(labels)


def _bits(count: int) -> int:
    return (count - 1).bit_length()


def _max_classes_in_fiber(labels: tuple[str, ...], part: tuple[int, ...]) -> int:
    fibers: dict[str, set[int]] = {}
    for label, cls in zip(labels, part):
        fibers.setdefault(label, set()).add(cls)
    return max(map(len, fibers.values()))


def shortest_witness(machine: FiniteMachine, left: int, right: int, *,
                     retained_labels: Sequence[str] | None = None) -> tuple[str, ...] | None:
    """Independent pair-product BFS for the shortest distinguishing suffix.

    Empty tuple means outputs differ already. None means equivalent at every
    continuation in this finite contract. The BFS is independent of the
    partition-refinement code used to compute quotient classes.
    """
    n = len(machine.states)
    if any(type(i) is not int or not 0 <= i < n for i in (left, right)):
        raise ValueError("unknown state index")
    labels = None if retained_labels is None else _labels(machine, retained_labels)
    def observed(i: int) -> object:
        return machine.outputs[i] if labels is None else (machine.outputs[i], labels[i])
    queue = deque([(left, right, ())])
    seen = {(left, right)}
    while queue:
        a, b, suffix = queue.popleft()
        if observed(a) != observed(b):
            return suffix
        for k, event in enumerate(machine.actions):
            pair = (machine.transitions[a][k], machine.transitions[b][k])
            if pair not in seen:
                seen.add(pair)
                queue.append((*pair, suffix + (event,)))
    return None


def repair_tags(machine: FiniteMachine, retained_labels: Sequence[str]) -> tuple[int, ...]:
    """Smallest-width tags for a stable online refinement retaining the labels.

    Tags may be reused across different original-label fibers. Within a fiber,
    distinct classes of the label-and-output continuation quotient need
    distinct tags. The resulting (label, tag) state is incrementally realizable.
    """
    labels = _labels(machine, retained_labels)
    part = quotient_partition(machine, retained_labels=labels)
    tags: dict[str, dict[int, int]] = {}
    for label, cls in zip(labels, part):
        table = tags.setdefault(label, {})
        if cls not in table:
            table[cls] = len(table)
    return tuple(tags[label][cls] for label, cls in zip(labels, part))


def audit_projection(machine: FiniteMachine, retained_labels: Sequence[str]) -> dict:
    """Exact finite structural certificate for a proposed compressed state.

    The repair bit counts refer to a worst-case fixed-width tag that must be
    stored *alongside* the original labels. They do not count the original
    label's storage, proof costs, cryptographic evidence or archive bytes.
    """
    labels = _labels(machine, retained_labels)
    output_part = quotient_partition(machine)
    online_part = quotient_partition(machine, retained_labels=labels)
    output_witness = None
    update_witness = None
    for left, right in combinations(range(len(machine.states)), 2):
        if labels[left] != labels[right]:
            continue
        if output_part[left] != output_part[right] and output_witness is None:
            suffix = shortest_witness(machine, left, right)
            assert suffix is not None
            output_witness = {"states": [machine.states[left], machine.states[right]],
                              "events": list(suffix)}
        if update_witness is None:
            for action_index, action in enumerate(machine.actions):
                a = machine.transitions[left][action_index]
                b = machine.transitions[right][action_index]
                if labels[a] != labels[b]:
                    update_witness = {"states": [machine.states[left], machine.states[right]],
                                      "event": action, "next_labels": [labels[a], labels[b]]}
                    break
    behavioral = output_witness is None
    incremental = update_witness is None and all(
        machine.outputs[i] == machine.outputs[j]
        for i, j in combinations(range(len(machine.states)), 2)
        if labels[i] == labels[j]
    )
    tags = repair_tags(machine, labels)
    return {
        "schema": "ace-continuation-quotient-v1",
        "scope": "finite-deterministic-research-only",
        "authorizes_action": False,
        "states": len(machine.states),
        "actions": len(machine.actions),
        "minimal_output_classes": len(set(output_part)),
        "minimal_output_bits": _bits(len(set(output_part))),
        "behaviorally_sufficient": behavioral,
        "incrementally_realizable": incremental,
        "first_output_collision": output_witness,
        "first_update_collision": update_witness,
        "additional_bits_for_output_only": _bits(_max_classes_in_fiber(labels, output_part)),
        "additional_bits_for_online_repair": _bits(_max_classes_in_fiber(labels, online_part)),
        "online_repair_tags": list(tags),
    }


def revocable_support_machine(roots: int = 3) -> FiniteMachine:
    """The DS-m revocation contract: each active logical root supports GO.

    Revocations are idempotent in this *abstract* model. ACE's actual Snapshot
    contract rejects duplicate revocations, so applying this toy quotient to
    it would require an explicitly totalized legal-history automaton.
    """
    if type(roots) is not int or roots < 1 or roots > 7:
        raise ValueError("roots must be an integer in [1,7]")
    n = 1 << roots
    return FiniteMachine(
        states=tuple(f"support:{mask:0{roots}b}" for mask in range(n)),
        actions=tuple(f"revoke:{r}" for r in range(roots)),
        outputs=tuple("GO" if mask else "STOP" for mask in range(n)),
        transitions=tuple(tuple(mask & ~(1 << r) for r in range(roots)) for mask in range(n)),
    )


def delayed_swap_machine() -> FiniteMachine:
    """Discrete analogue of the BPD-CQ-01 delayed-observer swap witness.

    State (x,y) has current output y. A recurrence tick swaps x and y, so
    information hidden from the present readout appears one step later.
    """
    return FiniteMachine(
        states=("00", "01", "10", "11"),
        actions=("tick",),
        outputs=("0", "1", "0", "1"),
        transitions=((0,), (2,), (1,), (3,)),
    )
