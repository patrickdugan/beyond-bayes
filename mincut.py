"""Minimum corruptible-vertex cut by node-splitting maximum flow.

Supports directed evidence graphs with multiple roots, non-corruptible nodes,
and a designated claim. A cut cannot remove the claim node itself.
This is a graph/channel availability measure; its statistical semantics must
be certified separately. Returns infinity when no finite allowed cut exists.
"""
from __future__ import annotations

from collections import deque
import math
from typing import Iterable, Mapping


class _Dinic:
    def __init__(self, n: int):
        self.g: list[list[list[int]]] = [[] for _ in range(n)]

    def add(self, u: int, v: int, capacity: int) -> None:
        a = [v, capacity, len(self.g[v])]
        b = [u, 0, len(self.g[u])]
        self.g[u].append(a)
        self.g[v].append(b)

    def flow(self, src: int, sink: int, limit: int) -> int:
        total = 0
        N = len(self.g)
        while total < limit:
            distance = [-1] * N
            queue = deque([src])
            distance[src] = 0
            while queue:
                u = queue.popleft()
                for v, cap, _ in self.g[u]:
                    if cap > 0 and distance[v] < 0:
                        distance[v] = distance[u] + 1
                        queue.append(v)
            if distance[sink] == -1:
                break
            cursor = [0] * N

            def augment(u: int, available: int) -> int:
                if u == sink:
                    return available
                while cursor[u] < len(self.g[u]):
                    edge = self.g[u][cursor[u]]
                    v, cap, reverse = edge
                    if cap > 0 and distance[v] == distance[u] + 1:
                        pushed = augment(v, min(cap, available))
                        if pushed:
                            edge[1] -= pushed
                            self.g[v][reverse][1] += pushed
                            return pushed
                    cursor[u] += 1
                return 0

            while total < limit:
                added = augment(src, limit - total)
                if not added:
                    break
                total += added
        return total


def minimum_channel_cut_flow(
    roots: Iterable[str], edges: Mapping[str, Iterable[str]], claim: str,
    corruptible: Iterable[str] | None = None
) -> float:
    roots = frozenset(roots)
    nodes = {claim, *roots}
    for parent, children in edges.items():
        nodes.add(parent)
        nodes.update(children)
    if corruptible is None:
        possible = nodes - {claim}
    else:
        possible = nodes.intersection(corruptible) - {claim}
    ids = {name: ix for ix, name in enumerate(sorted(nodes))}
    inf = len(possible) + 1
    graph = _Dinic(2 * len(nodes) + 2)
    source = 2 * len(nodes)
    sink = source + 1
    for name, index in ids.items():
        graph.add(2 * index, 2 * index + 1, 1 if name in possible else inf)
    for parent, children in edges.items():
        for child in children:
            graph.add(2 * ids[parent] + 1, 2 * ids[child], inf)
    for root in roots:
        graph.add(source, 2 * ids[root], inf)
    graph.add(2 * ids[claim] + 1, sink, inf)
    # If no root connects to the claim, the residual max flow is zero.
    value = graph.flow(source, sink, inf)
    return math.inf if value >= inf else float(value)
