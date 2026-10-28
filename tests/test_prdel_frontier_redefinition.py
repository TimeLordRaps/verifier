"""Repeated-symbol frontier attribution for PRDEL native version two."""

from __future__ import annotations

from typing import Any

from verifier.runtime import prdel
from verifier.runtime.prdel_graph import build_source_bound_impact_graph


def _sources(graph: dict[str, Any], row: dict[str, Any]) -> list[str]:
    source_sets = {
        item["id"]: item["source_obligations"]
        for item in graph["source_obligation_sets"]
    }
    return source_sets[row["source_obligation_set_id"]]


def _assert_reached_frontier(before_source: bytes, after_source: bytes) -> None:
    before = {"subject.py": before_source}
    after = {"subject.py": after_source}
    changes = prdel._changes(before, after)
    graph = build_source_bound_impact_graph(before, after, changes)
    selected = sorted(row["id"] for row in changes)

    assert graph["status"] == "UNKNOWN"
    assert len(graph["frontier"]) == 2
    assert {row["side"] for row in graph["frontier"]} == {"before", "after"}
    assert all(row["kind"] == "unresolved_call" for row in graph["frontier"])
    assert all(_sources(graph, row) == selected for row in graph["frontier"])
    assert graph["whole_estate_diagnostics"]["omitted_frontiers"] == 0


def test_changed_call_in_redefined_symbol_keeps_frontier_unknown() -> None:
    _assert_reached_frontier(
        b"def f():\n    return 0\ndef f():\n    return external_a()\n",
        b"def f():\n    return 0\ndef f():\n    return external_b()\n",
    )


def test_changed_redefined_symbol_header_keeps_nested_frontier_unknown() -> None:
    _assert_reached_frontier(
        b"def f():\n    return 0\ndef f(value=0):\n    return external()\n",
        b"def f():\n    return 0\ndef f(value=1):\n    return external()\n",
    )
