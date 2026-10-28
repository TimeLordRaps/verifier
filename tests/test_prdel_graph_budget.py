"""Pull Request Domain Explanation Language (PRDEL) graph budget controls.

The abstract syntax tree (AST) indexing still visits literal nodes. Relationship
analysis must retain its meaningful syntax without replaying inert AST leaves.
These finite syntax checks establish no runtime or complete application claim.
"""
from __future__ import annotations

from typing import Any

from verifier.runtime import prdel
from verifier.runtime.prdel_graph import _Graph, build_impact_graph


def _literal_source(first: int, suffix: bytes = b"") -> bytes:
    return b"payload = [" + str(first).encode() + b",0" * 59999 + b"]\n" + suffix


def _graph(before: bytes, after: bytes, **bounds: int) -> dict[str, Any]:
    old, new = {"literal.py": before}, {"literal.py": after}
    return build_impact_graph(old, new, prdel._changes(old, new), **bounds)


def test_literal_heavy_finite_graph_finishes_with_existing_operation_ceiling() -> None:
    graph = _graph(_literal_source(0), _literal_source(1))
    # This fixture contains only a literal assignment: no call, import,
    # inheritance or annotation relationship can exist on either side.
    assert graph["status"] == "BOUNDED_ANALYSIS_COMPLETE"
    assert graph["bounds"] == {"max_nodes": 10000, "max_edges": 20000, "max_operations": 200000}
    assert graph["counters"]["operations"] <= 200000
    assert {(node["side"], node["symbol"]) for node in graph["nodes"]} == {
        ("before", "<module>"), ("after", "<module>"),
    }
    assert graph["edges"] == graph["obligations"] == graph["frontier"] == graph["dag_edges"] == []
    assert len(graph["components"]) == 2 and all(not row["cyclic"] for row in graph["components"])
    assert all(node["source_obligations"] for node in graph["nodes"])


def test_large_literal_payload_keeps_real_call_and_annotation_relationships() -> None:
    suffix = (
        b"class Contract:\n    pass\n"
        b"def producer(value: Contract) -> Contract:\n    return value\n"
        b"def consumer(value: Contract) -> Contract:\n    return producer(value)\n"
    )
    graph = _graph(_literal_source(0, suffix), _literal_source(1, suffix))
    assert graph["status"] == "BOUNDED_ANALYSIS_COMPLETE"
    nodes = {row["id"]: row for row in graph["nodes"]}
    actual = {(row["side"], row["relationship"], nodes[row["source"]]["symbol"],
               nodes[row["target"]]["symbol"]) for row in graph["edges"]}
    assert actual == {(side, relation, producer, consumer)
        for side in ("before", "after") for relation, producer, consumer in (
            ("call", "producer", "consumer"),
            ("annotation", "Contract", "producer"),
            ("annotation", "Contract", "consumer"),
        )}
    assert all(row["evidence_state"] == "resolved_relationship" for row in graph["edges"])
    assert graph["counters"]["operations"] <= 200000


def test_literal_index_work_remains_charged_and_global_stop_retains_all_sources() -> None:
    old = {"literal.py": _literal_source(0), "z.py": b"later = 0\n"}
    new = {"literal.py": _literal_source(1), "z.py": b"later = 1\n"}
    changes = prdel._changes(old, new)
    graph = build_impact_graph(old, new, changes, max_operations=10000)
    assert graph["status"] == "UNKNOWN"
    assert graph["counters"]["operations"] == 10000
    assert graph["components"] == graph["dag_edges"] == []
    stopped = next(row for row in graph["frontier"] if row["kind"] == "analysis_bound")
    assert stopped["source_obligations"] == sorted(row["id"] for row in changes)


def test_unresolved_dynamic_relationship_stays_unknown_with_literal_payload() -> None:
    suffix = b"def invoke(callback):\n    return callback()\n"
    after = {"literal.py": _literal_source(1, suffix)}
    changes = prdel._changes({}, after)
    graph = build_impact_graph({}, after, changes)
    assert graph["status"] == "UNKNOWN"
    assert not any(row["kind"].endswith("_bound") for row in graph["frontier"])
    unresolved = [row for row in graph["frontier"] if row["kind"] == "unresolved_call"]
    assert len(unresolved) == 1 and "callback" in unresolved[0]["question"]
    assert unresolved[0]["source_obligations"] == sorted(row["id"] for row in changes)
    assert not any(row["relationship"] == "call" for row in graph["edges"])


def test_frontier_bound_conservatively_retains_every_selected_change() -> None:
    after = {
        "a.py": b"external_a()\n",
        "b.py": b"external_b()\n",
        "c.py": b"external_c()\n",
    }
    changes = prdel._changes({}, after)

    graph = build_impact_graph({}, after, changes, max_edges=1)

    assert graph["status"] == "UNKNOWN"
    bounds = [row for row in graph["frontier"] if row["kind"] == "frontier_bound"]
    assert len(bounds) == 1
    assert bounds[0]["source_obligations"] == sorted(
        str(change["id"]) for change in changes
    )
    assert bounds[0]["side"] == "both"
    assert bounds[0]["source_ref"] is None
    assert bounds[0]["consumer_id"] is None


def test_frontier_bound_write_is_idempotent_after_first_overflow() -> None:
    changes = [
        {"id": name, "path": name + ".py"}
        for name in ("selected-a", "selected-b", "selected-c")
    ]
    graph = _Graph(
        changes,
        {"max_nodes": 10, "max_edges": 1, "max_operations": 100},
    )
    ref = {
        "path": "subject.py",
        "start_line": 1,
        "end_line": 1,
        "blob_sha256": "0" * 64,
    }
    graph.boundary("unresolved_call", "a.py", "after", ref, "first")
    graph.boundary("unresolved_call", "b.py", "after", ref, "second")
    retained = graph.frontier["frontier:frontier_bound"]

    graph.boundary("unresolved_call", "c.py", "after", ref, "third")

    assert graph.frontier["frontier:frontier_bound"] is retained
    assert graph.frontier_context["frontier:frontier_bound"] == (
        None,
        None,
        None,
        None,
    )
