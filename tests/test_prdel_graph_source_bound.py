"""Source-bound pull request graph materialization refutation tests.

Pull Request Domain Explanation Language (PRDEL) version-one bytes remain
unchanged.  These tests exercise an opt-in version-two projection whose compact
output does not turn omitted whole-estate diagnostics into verified independence.
"""

from __future__ import annotations

import json
from typing import Any

from verifier.runtime.prdel_graph import build_source_bound_impact_graph


def _change(path: str, identifier: str, end: int = 2) -> dict[str, Any]:
    return {
        "id": identifier,
        "path": path,
        "old_range": [1, end],
        "new_range": [1, end],
        "symbols": [],
        "kind": "modified",
    }


def _sources(graph: dict[str, Any], row: dict[str, Any]) -> list[str]:
    sets = {item["id"]: item["source_obligations"] for item in graph["source_obligation_sets"]}
    return sets[row["source_obligation_set_id"]]


def _canonical_size(value: dict[str, Any]) -> int:
    return len(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def test_unrelated_estate_is_digest_summarized_not_materialized() -> None:
    before = {
        "producer.py": b"def produce(value):\n    return value\n",
        "consumer.py": (
            b"from producer import produce\n"
            b"def consume(value):\n    return produce(value)\n"
        ),
        "client.py": (
            b"from consumer import consume\n"
            b"def run(value):\n    return consume(value)\n"
        ),
    }
    for index in range(500):
        before[f"unrelated_{index:04d}.py"] = (
            f"def unrelated_{index}():\n    return missing_{index}()\n".encode()
        )
    after = dict(before)
    after["producer.py"] = b"def produce(value):\n    return value + 1\n"

    graph = build_source_bound_impact_graph(
        before,
        after,
        [_change("producer.py", "selected")],
    )

    assert graph["schema_version"] == "verifier-prdel-impact-2"
    assert graph["projection"] == "changed_source_bound"
    assert graph["status"] == "BOUNDED_ANALYSIS_COMPLETE"
    assert graph["whole_estate_diagnostics"]["status"] == "UNKNOWN"
    assert graph["whole_estate_diagnostics"]["omitted_frontiers"] == 1000
    assert graph["whole_estate_diagnostics"]["omitted_frontier_digest"]
    assert not any(row["path"].startswith("unrelated_") for row in graph["nodes"])
    assert not graph["frontier"]
    assert _canonical_size(graph) <= 256 * 1024


def test_only_reached_unresolved_frontier_is_required_unknown() -> None:
    before = {
        "producer.py": b"def produce(value):\n    return value\n",
        "consumer.py": (
            b"from producer import produce\n"
            b"def consume(value):\n"
            b"    retained = produce(value)\n"
            b"    return missing(retained)\n"
        ),
        "unrelated.py": b"def unrelated():\n    return missing(0)\n",
    }
    after = dict(before)
    after["producer.py"] = b"def produce(value):\n    return value + 1\n"

    graph = build_source_bound_impact_graph(
        before,
        after,
        [_change("producer.py", "selected")],
    )

    assert graph["status"] == "UNKNOWN"
    assert {(row["side"], row["path"]) for row in graph["frontier"]} == {
        ("before", "consumer.py"),
        ("after", "consumer.py"),
    }
    assert all(_sources(graph, row) == ["selected"] for row in graph["frontier"])
    assert graph["whole_estate_diagnostics"]["omitted_frontiers"] == 2
    assert not any(row["path"] == "unrelated.py" for row in graph["nodes"])


def test_dense_changed_chain_interns_provenance_under_resource_gate() -> None:
    count = 150
    before: dict[str, bytes] = {}
    after: dict[str, bytes] = {}
    changes: list[dict[str, Any]] = []
    for index in range(count):
        prefix = b"" if index == 0 else f"from module_{index - 1} import value_{index - 1}\n".encode()
        returned = "marker" if index == 0 else f"value_{index - 1}() + marker"
        before[f"module_{index}.py"] = prefix + (
            f"def value_{index}():\n"
            f"    marker = {index}\n"
            f"    return {returned}\n"
        ).encode()
        after[f"module_{index}.py"] = prefix + (
            f"def value_{index}():\n"
            f"    marker = {index + 1}\n"
            f"    return {returned}\n"
        ).encode()
        changes.append(_change(f"module_{index}.py", f"change-{index:03d}", 4))

    graph = build_source_bound_impact_graph(before, after, changes)
    selected = sorted(row["id"] for row in changes)

    assert graph["status"] == "BOUNDED_ANALYSIS_COMPLETE"
    assert len(graph["edges"]) == 4 * (count - 1)
    assert len(graph["obligations"]) == len(graph["edges"])
    call_edges = [row for row in graph["edges"] if row["relationship"] == "call"]
    import_edges = [
        row for row in graph["edges"] if row["relationship"] == "import"
    ]
    assert len(call_edges) == len(import_edges) == 2 * (count - 1)
    assert all(_sources(graph, row) == selected for row in call_edges)
    for row in import_edges:
        importing_index = int(
            row["source_ref"]["path"].removeprefix("module_").removesuffix(".py")
        )
        assert _sources(graph, row) == selected[: importing_index + 1]
    assert graph["counters"]["operations"] < 100000
    assert _canonical_size(graph) <= 4 * 1024 * 1024


def test_disconnected_chain_does_not_cross_bind_projection() -> None:
    before = {
        "a0.py": b"def a0():\n    return 0\n",
        "a1.py": b"from a0 import a0\ndef a1():\n    return a0()\n",
        "b0.py": b"def b0():\n    return 0\n",
        "b1.py": b"from b0 import b0\ndef b1():\n    return b0()\n",
    }
    after = dict(before)
    after["a0.py"] = b"def a0():\n    return 1\n"

    graph = build_source_bound_impact_graph(
        before,
        after,
        [_change("a0.py", "selected")],
    )

    assert {row["path"] for row in graph["nodes"]} == {"a0.py", "a1.py"}
    assert all(_sources(graph, row) == ["selected"] for row in graph["edges"])
    assert graph["whole_estate_diagnostics"]["omitted_nodes"] > 0
    assert graph["whole_estate_diagnostics"]["omitted_edges"] > 0


def test_output_bound_returns_unknown_without_partial_scope() -> None:
    before = {"changed.py": b"def value():\n    return 0\n"}
    after = {"changed.py": b"def value():\n    return 1\n"}
    graph = build_source_bound_impact_graph(
        before,
        after,
        [_change("changed.py", "selected")],
        max_output_bytes=1024,
    )

    assert graph["status"] == "UNKNOWN"
    assert graph["nodes"] == graph["edges"] == graph["obligations"] == []
    assert len(graph["frontier"]) == 1
    assert graph["frontier"][0]["kind"] == "output_bound"
    assert _sources(graph, graph["frontier"][0]) == ["selected"]
    assert graph["counters"]["attempted_output_bytes"] > 1024


def test_exact_materialized_size_is_admitted_and_one_byte_less_is_unknown() -> None:
    before = {"changed.py": b"def value():\n    return 0\n"}
    after = {"changed.py": b"def value():\n    return 1\n"}
    changes = [_change("changed.py", "selected")]
    roomy = build_source_bound_impact_graph(before, after, changes)
    accepted = build_source_bound_impact_graph(
        before,
        after,
        changes,
        max_output_bytes=roomy["counters"]["materialized_bytes"],
    )
    exact = accepted["counters"]["materialized_bytes"]

    assert accepted["status"] == "BOUNDED_ANALYSIS_COMPLETE"
    assert _canonical_size(accepted) == exact
    assert exact <= accepted["bounds"]["max_output_bytes"]

    refused = build_source_bound_impact_graph(
        before,
        after,
        changes,
        max_output_bytes=exact - 1,
    )
    assert refused["status"] == "UNKNOWN"
    assert refused["nodes"] == refused["edges"] == refused["obligations"] == []
    assert refused["frontier"][0]["kind"] == "output_bound"
    assert _sources(refused, refused["frontier"][0]) == ["selected"]
    assert refused["counters"]["attempted_output_bytes"] == exact


def test_analysis_bound_retains_every_selected_change_as_unknown() -> None:
    before = {
        "a.py": b"def a():\n    return 0\n",
        "b.py": b"def b():\n    return 0\n",
    }
    after = {
        "a.py": b"def a():\n    return 1\n",
        "b.py": b"def b():\n    return 1\n",
    }
    graph = build_source_bound_impact_graph(
        before,
        after,
        [_change("a.py", "change-a"), _change("b.py", "change-b")],
        max_operations=1,
    )

    assert graph["status"] == "UNKNOWN"
    assert graph["nodes"] == graph["edges"] == graph["obligations"] == []
    assert len(graph["frontier"]) == 1
    assert graph["frontier"][0]["kind"] == "analysis_bound"
    assert _sources(graph, graph["frontier"][0]) == ["change-a", "change-b"]


def test_source_bound_projection_is_input_order_deterministic() -> None:
    before = {
        "producer.py": b"def produce():\n    return 0\n",
        "consumer.py": b"from producer import produce\ndef consume():\n    return produce()\n",
    }
    after = dict(before)
    after["producer.py"] = b"def produce():\n    return 1\n"
    changes = [_change("producer.py", "selected")]

    first = build_source_bound_impact_graph(before, after, changes)
    second = build_source_bound_impact_graph(
        dict(reversed(list(before.items()))),
        dict(reversed(list(after.items()))),
        list(reversed(changes)),
    )

    assert first == second
