"""Derive the declared package dependency GRAPH for Verifier Standard (VSTD).

The root's direct members are the nodes; every member's operand reference is an
edge. This is a checkable projection of the selected declaration, not discovery
of program calls, dynamic effects or physical causality. No source code executes.
"""
from __future__ import annotations

from typing import Any

from verifier.core.namespace import NamespaceObject


def dependency_inputs(objects: tuple[NamespaceObject, ...], graph_id: str) -> dict[str, Any]:
    """Build sorted exact arrays, refusing to silently drop an external endpoint."""
    by_id = {item.object_id: item for item in objects}
    if len(by_id) != len(objects) or graph_id not in by_id or by_id[graph_id].kind.value != "GRAPH":
        raise ValueError("PACKAGE_GRAPH_SUBJECT_INVALID")
    graph = by_id[graph_id]
    nodes = dict(graph.operands).get("members", ())
    if set(nodes) != set(by_id) - {graph_id} or len(nodes) != len(set(nodes)):
        raise ValueError("PACKAGE_GRAPH_MEMBERS_INCOMPLETE")
    edges = set()
    for identifier in nodes:
        for _, targets in by_id[identifier].operands:
            for target in targets:
                if target not in by_id or target == graph_id:
                    raise ValueError("PACKAGE_GRAPH_OPERAND_OUTSIDE_MEMBERS")
                edges.add((identifier, target))
    return {"nodes": sorted(nodes),
            "edges": [{"source": source, "target": target} for source, target in sorted(edges)]}
