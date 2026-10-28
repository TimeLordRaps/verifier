"""Predeclared reserve verifier adapters; never selected after evaluation starts."""

from __future__ import annotations

from time import perf_counter_ns
from typing import Any, Callable

import networkx as nx
import sympy
from matching.games import StableMarriage

from .canonical import canonical_digest
from .contracts import NativeVerdict, VerificationObservation


RESERVES = {
    "stable_matching": "matching==1.4.3",
    "graph_isomorphism": "networkx==3.5",
    "integer_factorization": "sympy==1.14.0",
}


def verify_with_reserve(
    domain: str, instance: dict[str, Any], candidate: dict[str, Any]
) -> VerificationObservation:
    verifier: Callable[[dict[str, Any], dict[str, Any]], bool] = {
        "stable_matching": _stable,
        "graph_isomorphism": _graph,
        "integer_factorization": _factor,
    }[domain]
    started = perf_counter_ns()
    diagnostics: tuple[str, ...] = ()
    try:
        accepted = verifier(instance, candidate)
        verdict = NativeVerdict.ACCEPTED if accepted else NativeVerdict.REJECTED
    except Exception as exc:
        verdict = NativeVerdict.ERROR
        diagnostics = (f"{type(exc).__name__}: {exc}",)
    return VerificationObservation(
        verdict=verdict,
        elapsed_ns=perf_counter_ns() - started,
        diagnostics=diagnostics,
        instance_digest=canonical_digest(instance),
        candidate_digest=canonical_digest(candidate),
    )


def _stable(instance: dict[str, Any], candidate: dict[str, Any]) -> bool:
    matching = candidate.get("matching")
    n = len(instance["proposer_prefs"])
    if not isinstance(matching, list) or len(matching) != n or sorted(matching) != list(range(n)):
        return False
    suitor_prefs = {
        f"p{proposer}": [f"r{receiver}" for receiver in preferences]
        for proposer, preferences in enumerate(instance["proposer_prefs"])
    }
    reviewer_prefs = {
        f"r{receiver}": [f"p{proposer}" for proposer in preferences]
        for receiver, preferences in enumerate(instance["receiver_prefs"])
    }
    game = StableMarriage.create_from_dictionaries(suitor_prefs, reviewer_prefs)
    reviewer_by_name = {reviewer.name: reviewer for reviewer in game.reviewers}
    selected = {}
    for proposer, receiver_index in zip(game.suitors, matching):
        receiver = reviewer_by_name[f"r{receiver_index}"]
        proposer._match(receiver)  # upstream package exposes only the internal primitive
        receiver._match(proposer)
        selected[proposer] = receiver
    game.matching = selected
    return bool(game.check_validity() and game.check_stability())


def _graph(instance: dict[str, Any], candidate: dict[str, Any]) -> bool:
    mapping = candidate.get("mapping")
    n = int(instance["num_nodes"])
    if not isinstance(mapping, list) or len(mapping) != n or sorted(mapping) != list(range(n)):
        return False
    left = nx.Graph()
    right = nx.Graph()
    left.add_nodes_from(range(n))
    right.add_nodes_from(range(n))
    left.add_edges_from(instance["edges_g1"])
    right.add_edges_from(instance["edges_g2"])
    relabeled = nx.relabel_nodes(left, {node: mapping[node] for node in range(n)}, copy=True)
    return nx.utils.graphs_equal(relabeled, right)


def _factor(instance: dict[str, Any], candidate: dict[str, Any]) -> bool:
    p = candidate.get("p")
    q = candidate.get("q")
    if isinstance(p, bool) or isinstance(q, bool) or not isinstance(p, int) or not isinstance(q, int):
        return False
    return p > 1 and q > 1 and p * q == int(instance["composite"]) and sympy.isprime(p) and sympy.isprime(q)
