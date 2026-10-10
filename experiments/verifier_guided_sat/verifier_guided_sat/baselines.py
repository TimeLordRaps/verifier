"""Independently justified complete encodings used only by comparison Arm A."""

from __future__ import annotations

from math import isqrt
from typing import Any

import sympy

from .route import ROUTE_VERSION


def canonical_route(domain: str, instance: dict[str, Any]) -> dict[str, Any]:
    """Return a complete finite-domain route for one bounded benchmark instance."""

    if domain == "stable_matching":
        return _stable_matching(instance)
    if domain == "graph_isomorphism":
        return _graph_isomorphism(instance)
    if domain == "integer_factorization":
        return _integer_factorization(instance)
    raise KeyError(domain)


def _stable_matching(instance: dict[str, Any]) -> dict[str, Any]:
    proposer_prefs = [list(row) for row in instance["proposer_prefs"]]
    receiver_prefs = [list(row) for row in instance["receiver_prefs"]]
    n = len(proposer_prefs)
    slots = [{"id": f"p{p}", "domain": list(range(n))} for p in range(n)]
    constraints: list[dict[str, Any]] = [
        {"kind": "all_different", "slots": [f"p{p}" for p in range(n)]}
    ]
    receiver_rank = [
        {proposer: rank for rank, proposer in enumerate(preferences)}
        for preferences in receiver_prefs
    ]
    # A blocking pair (p, r) exists when p is matched to a less-preferred c and
    # r is matched to a proposer q whom r likes less than p. Forbid every such
    # pair of slot assignments. Together with all-different this is complete.
    for proposer in range(n):
        rank = {receiver: position for position, receiver in enumerate(proposer_prefs[proposer])}
        for receiver in range(n):
            for current in range(n):
                if rank[receiver] >= rank[current]:
                    continue
                for other in range(n):
                    if other == proposer or receiver_rank[receiver][proposer] >= receiver_rank[receiver][other]:
                        continue
                    constraints.append(
                        {
                            "kind": "forbidden_pair",
                            "left_slot": f"p{proposer}",
                            "left_value": current,
                            "right_slot": f"p{other}",
                            "right_value": receiver,
                        }
                    )
    return {
        "route_version": ROUTE_VERSION,
        "declared_statement": "complete bounded stable-matching encoding",
        "slots": slots,
        "constraints": constraints,
        "decoder": {
            "kind": "list_field",
            "field": "matching",
            "slots": [f"p{p}" for p in range(n)],
        },
    }


def _graph_isomorphism(instance: dict[str, Any]) -> dict[str, Any]:
    n = int(instance["num_nodes"])
    slots = [{"id": f"n{node}", "domain": list(range(n))} for node in range(n)]
    constraints: list[dict[str, Any]] = [
        {"kind": "all_different", "slots": [f"n{node}" for node in range(n)]}
    ]
    edges_left = {tuple(sorted(map(int, edge))) for edge in instance["edges_g1"]}
    edges_right = {tuple(sorted(map(int, edge))) for edge in instance["edges_g2"]}
    for left_u in range(n):
        for left_v in range(left_u + 1, n):
            left_is_edge = (left_u, left_v) in edges_left
            for right_u in range(n):
                for right_v in range(n):
                    if right_u == right_v:
                        continue
                    right_is_edge = tuple(sorted((right_u, right_v))) in edges_right
                    if left_is_edge != right_is_edge:
                        constraints.append(
                            {
                                "kind": "forbidden_pair",
                                "left_slot": f"n{left_u}",
                                "left_value": right_u,
                                "right_slot": f"n{left_v}",
                                "right_value": right_v,
                            }
                        )
    return {
        "route_version": ROUTE_VERSION,
        "declared_statement": "complete bounded graph-isomorphism encoding",
        "slots": slots,
        "constraints": constraints,
        "decoder": {
            "kind": "list_field",
            "field": "mapping",
            "slots": [f"n{node}" for node in range(n)],
        },
    }


def _integer_factorization(instance: dict[str, Any]) -> dict[str, Any]:
    composite = int(instance["composite"])
    root = isqrt(composite)
    bit_length = composite.bit_length()
    # The selected generator creates two similarly sized primes. Both domains
    # cover every prime of either plausible factor bit length. They are derived
    # from the public generator contract, never from a hidden reference answer.
    factor_bits = max(2, bit_length // 2)
    lower = 1 << max(1, factor_bits - 1)
    upper = min((1 << (factor_bits + 1)) - 1, composite // 2)
    values = [value for value in range(lower, upper + 1) if sympy.isprime(value)]
    if not values or len(values) > 256 or root < 2:
        raise ValueError("factor instance is outside the preregistered bounded baseline surface")
    return {
        "route_version": ROUTE_VERSION,
        "declared_statement": "complete bounded semiprime-factor encoding under the generator bit-size contract",
        "slots": [{"id": "p", "domain": values}, {"id": "q", "domain": values}],
        "constraints": [
            {"kind": "product_equals", "left_slot": "p", "right_slot": "q", "target": composite}
        ],
        "decoder": {"kind": "object_fields", "fields": {"p": "p", "q": "q"}},
    }
