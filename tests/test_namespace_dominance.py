"""Independent cut-search oracle for Verifier Standard (VSTD) agency dominance.

The oracle deletes one vertex and searches again. It deliberately shares no
semidominator or interval algorithm with production and is used only on small
graphs. A separate long-chain test challenges stack and storage behavior.
"""
from __future__ import annotations

from copy import deepcopy
from itertools import product
import random

from verifier.runtime.namespace_dominance import dominance_intervals, dominates


def _reachable(graph: dict[str, set[str]], roots: set[str], removed: str | None = None) -> set[str]:
    seen = roots - {removed}
    pending = list(seen)
    while pending:
        for target in graph[pending.pop()]:
            if target != removed and target not in seen:
                seen.add(target)
                pending.append(target)
    return seen


def _check(graph: dict[str, set[str]], roots: set[str]) -> None:
    before = deepcopy(graph)
    reached = _reachable(graph, roots)
    intervals = dominance_intervals(graph, roots)
    assert set(intervals) == reached
    for required in graph:
        avoiding = _reachable(graph, roots, required)
        for subject in graph:
            assert dominates(intervals, required, subject) == (subject in reached and subject not in avoiding), (
                graph, roots, required, subject, intervals)
    assert graph == before


def test_every_three_vertex_graph_and_root_subset_matches_vertex_cuts():
    names = ["a", "b", "c"]
    edges = list(product(names, repeat=2))
    for mask in range(1 << len(edges)):
        graph: dict[str, set[str]] = {name: set() for name in names}
        for bit, (source, target) in enumerate(edges):
            if mask & (1 << bit):
                graph[source].add(target)
        for roots in range(1 << len(names)):
            _check(graph, {name for bit, name in enumerate(names) if roots & (1 << bit)})


def test_seeded_branching_cycles_and_disconnected_graphs_match_vertex_cuts():
    generator = random.Random(3824)
    names = [str(index) for index in range(15)]
    for _ in range(200):
        density = generator.choice((0.05, 0.2, 0.5))
        graph = {source: {target for target in names if generator.random() < density} for source in names}
        roots = {name for name in names if generator.random() < 0.2}
        _check(graph, roots)


def test_long_chain_uses_no_recursive_search_and_keeps_all_mandatory_vertices():
    names = [str(index) for index in range(10000)]
    graph = {name: {names[index + 1]} if index + 1 < len(names) else set() for index, name in enumerate(names)}
    intervals = dominance_intervals(graph, {names[0]})
    assert len(intervals) == len(names)
    for index, name in enumerate(names):
        assert dominates(intervals, name, names[-1])
        if index:
            assert not dominates(intervals, name, names[index - 1])


def test_two_effect_roots_do_not_share_a_false_mandatory_agent():
    graph = {"physical": {"agent"}, "money": {"bot"}, "agent": {"bot"}, "bot": set()}
    assert dominates(dominance_intervals(graph, {"physical"}), "agent", "bot")
    assert not dominates(dominance_intervals(graph, {"money"}), "agent", "bot")
    assert not dominates(dominance_intervals(graph, {"physical", "money"}), "agent", "bot")
    assert not dominates(dominance_intervals(graph, set()), "agent", "bot")
