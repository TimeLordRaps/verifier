"""Pull Request Domain Explanation Language (PRDEL) variadic type controls.

The abstract syntax tree (AST) annotations establish finite syntactic dependencies.
Unknown types cannot be silently omitted from a completed relationship graph.
"""
from __future__ import annotations

import pytest

from verifier.runtime import prdel
from verifier.runtime.prdel_graph import build_impact_graph


@pytest.mark.parametrize("parameter", ["*values", "**values"])
@pytest.mark.parametrize("declaration", ["def", "async def"])
def test_variadic_type_dependency_is_retained_on_both_sides(
    parameter: str, declaration: str,
) -> None:
    suffix = f"{declaration} consume({parameter}: Contract):\n    return values\n".encode()
    old = {"types.py": b"class Contract:\n    version = 0\n" + suffix}
    new = {"types.py": b"class Contract:\n    version = 1\n" + suffix}
    changes = prdel._changes(old, new)
    graph = build_impact_graph(old, new, changes)
    assert graph["status"] == "BOUNDED_ANALYSIS_COMPLETE"
    nodes = {row["id"]: row for row in graph["nodes"]}
    edges = [row for row in graph["edges"] if row["relationship"] == "annotation"]
    assert {(row["side"], nodes[row["source"]]["symbol"], nodes[row["target"]]["symbol"])
            for row in edges} == {("before", "Contract", "consume"), ("after", "Contract", "consume")}
    assert len(edges) == 2
    assert all(row["source_obligations"] == [changes[0]["id"]] for row in edges)
    assert all(row["source_ref"]["blob_sha256"] for row in edges)


@pytest.mark.parametrize("parameter", ["*values", "**values"])
@pytest.mark.parametrize("declaration", ["def", "async def"])
def test_unresolved_variadic_type_is_an_explicit_source_bound_frontier(
    parameter: str, declaration: str,
) -> None:
    new = {"consumer.py": f"{declaration} consume({parameter}: Missing):\n    return values\n".encode()}
    changes = prdel._changes({}, new)
    graph = build_impact_graph({}, new, changes)
    assert graph["status"] == "UNKNOWN"
    assert graph["edges"] == []
    frontier = [row for row in graph["frontier"] if row["kind"] == "unresolved_annotation"]
    assert len(frontier) == 1 and "Missing" in frontier[0]["question"]
    assert frontier[0]["source_obligations"] == [changes[0]["id"]]
    assert frontier[0]["source_ref"]["blob_sha256"]


@pytest.mark.parametrize(
    "consumer",
    [
        "def consume(value): # type: (Contract) -> Contract\n    return value\n",
        "def consume(\n    value, # type: Contract\n):\n    return value\n",
        "def consume():\n    value = None # type: Contract\n    return value\n",
    ],
    ids=["function", "argument", "assignment"],
)
def test_legacy_type_comment_dependency_is_not_silently_omitted(
    consumer: str,
) -> None:
    suffix = consumer.encode()
    old = {"types.py": b"class Contract:\n    version = 0\n" + suffix}
    new = {"types.py": b"class Contract:\n    version = 1\n" + suffix}
    changes = prdel._changes(old, new)

    graph = build_impact_graph(old, new, changes)
    nodes = {row["id"]: row for row in graph["nodes"]}
    edges = [row for row in graph["edges"] if row["relationship"] == "annotation"]

    assert {
        (row["side"], nodes[row["source"]]["symbol"], nodes[row["target"]]["symbol"])
        for row in edges
    } == {("before", "Contract", "consume"), ("after", "Contract", "consume")}
    assert all(row["source_obligations"] == [changes[0]["id"]] for row in edges)
    assert all(row["source_ref"]["blob_sha256"] for row in edges)
