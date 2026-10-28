"""All-path agency checks for Verifier Standard (VSTD) consequence graphs.

An ancestor in the dominator tree occurs on every path from the selected roots.
Applied to reversed effect edges, this identifies a mandatory agent without
enumerating paths or repeating a graph search for every wrapper. This is graph
structure only, never evidence of runtime enforcement or termination.

The simple Lengauer-Tarjan algorithm uses path-compressed ancestor queries;
see https://doi.org/10.1145/357062.357071. All traversals are iterative so a long
declared chain does not consume the Python call stack. Storage is linear in
vertices and edges; two interval comparisons answer each dominance query.
"""
from __future__ import annotations


def dominance_intervals(graph: dict[str, set[str]], roots: set[str]) -> dict[str, tuple[int, int]]:
    """Return dominator-subtree intervals for vertices reachable from any root.

    Inputs are already bounded and reference-validated by namespace admission.
    A private numeric root connects all selected roots: each effect is a possible
    endpoint, so passing through one endpoint cannot hide a second bypass.
    Unreachable vertices are absent, not vacuously verified.
    """
    names = sorted(graph)
    index = {name: position for position, name in enumerate(names)}
    entry = len(names)
    successors = [sorted(index[target] for target in graph[name]) for name in names]
    successors.append(sorted(index[name] for name in roots))
    size = len(successors)
    predecessors: list[list[int]] = [[] for _ in range(size)]
    for source, targets in enumerate(successors):
        for target in targets:
            predecessors[target].append(source)

    # Number precisely the depth-first tree, retaining the parent used by link.
    order = [entry]
    number = [-1] * size
    number[entry] = 0
    parent = [-1] * size
    pending = [(entry, iter(successors[entry]))]
    while pending:
        vertex, children = pending[-1]
        target = next(children, None)
        if target is None:
            pending.pop()
        elif number[target] == -1:
            parent[target] = vertex
            number[target] = len(order)
            order.append(target)
            pending.append((target, iter(successors[target])))

    semi = number.copy()
    best = list(range(size))
    ancestor = [-1] * size
    immediate = [-1] * size
    buckets: list[list[int]] = [[] for _ in range(size)]

    def evaluate(vertex: int) -> int:
        # Compress bottom-up while retaining the earliest semidominator along
        # each compressed segment; mere union-find ancestry loses this value.
        path = []
        current = vertex
        while ancestor[current] != -1 and ancestor[ancestor[current]] != -1:
            path.append(current)
            current = ancestor[current]
        for current in reversed(path):
            above = ancestor[current]
            if semi[best[above]] < semi[best[current]]:
                best[current] = best[above]
            ancestor[current] = ancestor[above]
        return best[vertex]

    for vertex in reversed(order[1:]):
        for source in predecessors[vertex]:
            if number[source] != -1:
                semi[vertex] = min(semi[vertex], semi[evaluate(source)])
        buckets[order[semi[vertex]]].append(vertex)
        above = parent[vertex]
        ancestor[vertex] = above
        for waiting in buckets[above]:
            candidate = evaluate(waiting)
            immediate[waiting] = candidate if semi[candidate] < semi[waiting] else above
        buckets[above].clear()
    for vertex in order[1:]:
        if immediate[vertex] != order[semi[vertex]]:
            immediate[vertex] = immediate[immediate[vertex]]

    # Subtree containment replaces a walk through ancestors for every query.
    children_by_parent: list[list[int]] = [[] for _ in range(size)]
    for vertex in order[1:]:
        children_by_parent[immediate[vertex]].append(vertex)
    intervals = {}
    starts = [0] * size
    clock = 0
    visits = [(entry, False)]
    while visits:
        vertex, leaving = visits.pop()
        if leaving:
            if vertex != entry:
                intervals[names[vertex]] = (starts[vertex], clock)
        else:
            starts[vertex] = clock
            clock += 1
            visits.append((vertex, True))
            visits.extend((child, False) for child in reversed(children_by_parent[vertex]))
    return intervals


def dominates(intervals: dict[str, tuple[int, int]], required: str, subject: str) -> bool:
    """Require a reachable subject and containment in the required subtree."""
    if required not in intervals or subject not in intervals:
        return False
    outer, inner = intervals[required], intervals[subject]
    return outer[0] <= inner[0] and inner[1] <= outer[1]
