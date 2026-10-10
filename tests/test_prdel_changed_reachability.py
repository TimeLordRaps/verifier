"""Pull Request Domain Explanation Language (PRDEL) reachability controls.

The abstract syntax tree (AST) impact graph must bind an unresolved boundary to a
selected change only after source reachability is established. Unknown boundaries
remain explicit without becoming evidence about an unrelated change.
"""

from __future__ import annotations

from typing import Any

from verifier.runtime.prdel_graph import build_impact_graph


def _change(
    path: str,
    start: int,
    end: int,
    *,
    identifier: str = "change-1",
    kind: str = "modified",
) -> dict[str, Any]:
    return {
        "id": identifier,
        "path": path,
        "old_range": [start, end],
        "new_range": [start, end],
        "symbols": [],
        "kind": kind,
    }


def _nodes(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["id"]: row for row in graph["nodes"]}


def test_whole_estate_unrelated_frontier_has_no_source_binding() -> None:
    before = {
        "producer.py": b"def changed():\n    return 1\n",
        "unrelated.py": b"retained = missing_name()\n",
    }
    after = dict(
        before,
        **{"producer.py": b"def changed():\n    return 2\n"},
    )
    graph = build_impact_graph(before, after, [_change("producer.py", 2, 2)])
    unresolved = [
        row
        for row in graph["frontier"]
        if row["kind"] == "unresolved_call" and "missing_name" in row["question"]
    ]
    assert {(row["side"], row["source_ref"]["start_line"]) for row in unresolved} == {
        ("before", 1),
        ("after", 1),
    }
    assert all(row["source_obligations"] == [] for row in unresolved)
    assert graph["status"] == "UNKNOWN"


def test_changed_producer_binds_transitive_consumer_unknown_frontier() -> None:
    before = {
        "producer.py": b"def parse(value):\n    return value\n",
        "consumer.py": (
            b"from producer import parse\n"
            b"def consume(value):\n"
            b"    parsed = parse(value)\n"
            b"    return unrelated_missing(parsed)\n"
        ),
        "client.py": (
            b"from consumer import consume\n"
            b"def run(value):\n"
            b"    return consume(value)\n"
        ),
    }
    after = dict(
        before,
        **{"producer.py": b"def parse(value):\n    return value + 1\n"},
    )
    graph = build_impact_graph(
        before,
        after,
        [_change("producer.py", 2, 2, identifier="producer-change")],
    )
    nodes = _nodes(graph)
    after_calls = [
        row
        for row in graph["edges"]
        if row["side"] == "after" and row["relationship"] == "call"
    ]
    assert {
        (nodes[row["source"]]["symbol"], nodes[row["target"]]["symbol"])
        for row in after_calls
    } == {("parse", "consume"), ("consume", "run")}
    assert all(row["source_obligations"] == ["producer-change"] for row in after_calls)
    assert next(
        row
        for row in graph["nodes"]
        if row["side"] == "after" and row["symbol"] == "run"
    )["source_obligations"] == ["producer-change"]

    unrelated = [
        row
        for row in graph["frontier"]
        if row["kind"] == "unresolved_call"
        and "unrelated_missing" in row["question"]
    ]
    assert {(row["side"], row["path"]) for row in unrelated} == {
        ("before", "consumer.py"),
        ("after", "consumer.py"),
    }
    assert {
        (row["side"], tuple(row["source_obligations"])) for row in unrelated
    } == {
        ("before", ("producer-change",)),
        ("after", ("producer-change",)),
    }
    assert graph["status"] == "UNKNOWN"


def test_unindexed_consumer_with_changed_import_stays_conservatively_bound() -> None:
    before = {
        "producer.py": b"def parse(value):\n    return value\n",
        "broken_consumer.py": (
            b"def broken(\n"
            b"from producer import parse\n"
            b"parse('retained')\n"
        ),
        "other.py": b"value = 1\n",
    }
    after = dict(
        before,
        **{
            "producer.py": b"def parse(value):\n    return value + 1\n",
            "other.py": b"value = 2\n",
        },
    )
    graph = build_impact_graph(
        before,
        after,
        [
            _change("producer.py", 2, 2, identifier="producer-change"),
            _change("other.py", 1, 1, identifier="other-change"),
        ],
    )
    failures = [
        row
        for row in graph["frontier"]
        if row["kind"] == "parse_failure" and row["path"] == "broken_consumer.py"
    ]
    assert {(row["side"], row["source_ref"]["start_line"]) for row in failures} == {
        ("before", 1),
        ("after", 1),
    }
    assert {
        (row["side"], tuple(row["source_obligations"])) for row in failures
    } == {
        ("before", ("other-change", "producer-change")),
        ("after", ("other-change", "producer-change")),
    }
    assert all("establish applicability" in row["question"] for row in failures)
    assert graph["status"] == "UNKNOWN"


def test_changed_unindexed_consumer_keeps_all_selected_producers_bound() -> None:
    before = {
        "producer.py": b"def parse(value):\n    return value\n",
        "broken_consumer.py": (
            b"def broken(\n"
            b"from producer import parse\n"
            b"parse('before')\n"
        ),
    }
    after = {
        "producer.py": b"def parse(value):\n    return value + 1\n",
        "broken_consumer.py": (
            b"def broken(\n"
            b"from producer import parse\n"
            b"parse('after')\n"
        ),
    }
    graph = build_impact_graph(
        before,
        after,
        [
            _change("producer.py", 2, 2, identifier="producer-change"),
            _change("broken_consumer.py", 3, 3, identifier="consumer-change"),
        ],
    )
    failures = [
        row
        for row in graph["frontier"]
        if row["kind"] == "parse_failure" and row["path"] == "broken_consumer.py"
    ]
    assert {(row["side"], row["source_ref"]["start_line"]) for row in failures} == {
        ("before", 1),
        ("after", 1),
    }
    assert {
        (row["side"], tuple(row["source_obligations"])) for row in failures
    } == {
        ("before", ("consumer-change", "producer-change")),
        ("after", ("consumer-change", "producer-change")),
    }
    assert graph["status"] == "UNKNOWN"


def test_syntactic_candidate_cannot_transmit_provenance_downstream() -> None:
    before = {
        "worker.py": (
            b"class Worker:\n"
            b"    def check(self):\n"
            b"        return 1\n"
            b"    def run(self):\n"
            b"        return self.check()\n"
            b"def consume():\n"
            b"    worker = Worker()\n"
            b"    return worker.run()\n"
            b"def publish():\n"
            b"    return consume()\n"
        )
    }
    after = {
        "worker.py": before["worker.py"].replace(
            b"        return 1\n", b"        return 2\n", 1
        )
    }
    graph = build_impact_graph(
        before,
        after,
        [_change("worker.py", 3, 3, identifier="check-change")],
    )
    nodes = _nodes(graph)
    candidate_edges = [
        row
        for row in graph["edges"]
        if row["side"] == "after" and row["evidence_state"] == "syntactic_candidate"
    ]
    assert candidate_edges
    assert any(
        nodes[row["source"]]["symbol"] == "Worker.check"
        and row["source_obligations"] == ["check-change"]
        for row in candidate_edges
    )
    downstream = next(
        row
        for row in graph["edges"]
        if row["side"] == "after"
        and nodes[row["source"]]["symbol"] == "consume"
        and nodes[row["target"]]["symbol"] == "publish"
    )
    assert downstream["evidence_state"] == "resolved_relationship"
    assert downstream["source_obligations"] == []
    assert not any(
        row["edge_id"] == downstream["id"] for row in graph["obligations"]
    )


def test_before_resolution_does_not_side_bridge_after_unresolved_rename() -> None:
    before = {
        "producer.py": b"def old():\n    return 1\n",
        "consumer.py": (
            b"from producer import old\n"
            b"def consume():\n"
            b"    return old()\n"
        ),
    }
    after = {
        "producer.py": b"def replacement():\n    return 2\n",
        "consumer.py": (
            b"from producer import old\n"
            b"def consume():\n"
            b"    return replacement()\n"
        ),
    }
    graph = build_impact_graph(
        before,
        after,
        [
            _change("producer.py", 1, 2, identifier="producer-rename"),
            _change("consumer.py", 3, 3, identifier="consumer-call"),
        ],
    )
    nodes = _nodes(graph)
    before_edge = next(
        row
        for row in graph["edges"]
        if row["side"] == "before"
        and nodes[row["source"]]["symbol"] == "old"
        and nodes[row["target"]]["symbol"] == "consume"
    )
    assert before_edge["source_obligations"] == [
        "consumer-call",
        "producer-rename",
    ]
    after_frontier = next(
        row
        for row in graph["frontier"]
        if row["side"] == "after"
        and row["path"] == "consumer.py"
        and row["source_ref"]["start_line"] == 3
        and "replacement" in row["question"]
    )
    assert after_frontier["source_obligations"] == ["consumer-call"]


def test_modified_change_with_missing_after_path_cannot_be_complete() -> None:
    before = {"changed.py": b"def answer():\n    return 1\n"}
    graph = build_impact_graph(
        before,
        {},
        [_change("changed.py", 2, 2, identifier="missing-after")],
    )
    assert graph["status"] == "UNKNOWN"
    assert any(
        row["side"] == "after"
        and row["source_obligations"] == ["missing-after"]
        for row in graph["frontier"]
    )


def test_operation_exhaustion_before_after_index_marks_after_incomplete() -> None:
    before = {"changed.py": b"def answer():\n    return 1\n"}
    after = {"changed.py": b"def answer():\n    return 2\n"}
    graph = build_impact_graph(
        before,
        after,
        [_change("changed.py", 2, 2, identifier="selected-change")],
        max_operations=1,
    )
    assert not any(row["side"] == "after" for row in graph["nodes"])
    assert graph["status"] == "UNKNOWN"
    assert {
        (row["side"], row["kind"], tuple(row["source_obligations"]))
        for row in graph["frontier"]
        if "selected-change" in row["source_obligations"]
    } == {("after", "analysis_bound", ("selected-change",))}


def test_spanning_diff_retains_module_and_nested_seed_attribution() -> None:
    before = {
        "dependency.py": b"def work():\n    return 1\n",
        "consumer.py": (
            b"from dependency import work\n"
            b"work()\n"
            b"def nested():\n"
            b"    return 1\n"
        ),
    }
    after = {
        "dependency.py": before["dependency.py"],
        "consumer.py": (
            b"from dependency import work\n"
            b"work()\n"
            b"def nested():\n"
            b"    return 2\n"
        ),
    }
    graph = build_impact_graph(
        before,
        after,
        [_change("consumer.py", 1, 4, identifier="spanning-change")],
    )
    nodes = _nodes(graph)
    for side in ("before", "after"):
        module = next(
            row
            for row in graph["nodes"]
            if row["side"] == side
            and row["path"] == "consumer.py"
            and row["symbol"] == "<module>"
        )
        nested = next(
            row
            for row in graph["nodes"]
            if row["side"] == side
            and row["path"] == "consumer.py"
            and row["symbol"] == "nested"
        )
        assert module["source_obligations"] == ["spanning-change"]
        assert nested["source_obligations"] == ["spanning-change"]
        module_edges = [
            row
            for row in graph["edges"]
            if row["side"] == side and row["target"] == module["id"]
        ]
        assert {row["relationship"] for row in module_edges} == {"call", "import"}
        assert all(
            row["source_obligations"] == ["spanning-change"]
            for row in module_edges
        )


def test_structural_pruning_keeps_changed_flag_and_direct_sources_consistent() -> None:
    before_source = (
        b"class Container:\n"
        b"    def outer(self):\n"
        b"        def nested():\n"
        b"            return 1\n"
        b"        return 0\n"
    )
    after_source = before_source.replace(b"return 1", b"return 2")
    expected_symbols = {
        "<module>",
        "Container",
        "Container.outer",
        "Container.outer.nested",
    }

    delegated = build_impact_graph(
        {"nested.py": before_source},
        {"nested.py": after_source},
        [_change("nested.py", 4, 4, identifier="nested-change")],
    )
    for side in ("before", "after"):
        nodes = {
            row["symbol"]: row
            for row in delegated["nodes"]
            if row["side"] == side and row["path"] == "nested.py"
        }
        assert set(nodes) == expected_symbols
        assert {
            symbol: (row["changed"], tuple(row["source_obligations"]))
            for symbol, row in nodes.items()
        } == {
            "<module>": (False, ()),
            "Container": (False, ()),
            "Container.outer": (False, ()),
            "Container.outer.nested": (True, ("nested-change",)),
        }

    spanning = build_impact_graph(
        {"nested.py": before_source},
        {"nested.py": after_source},
        [_change("nested.py", 1, 5, identifier="spanning-change")],
    )
    for side in ("before", "after"):
        nodes = {
            row["symbol"]: row
            for row in spanning["nodes"]
            if row["side"] == side and row["path"] == "nested.py"
        }
        assert set(nodes) == expected_symbols
        assert all(row["changed"] is True for row in nodes.values())
        assert all(
            row["source_obligations"] == ["spanning-change"]
            for row in nodes.values()
        )


def test_unbound_dynamic_unknown_and_non_python_exclusions_remain_explicit() -> None:
    before = {
        "producer.py": b"def answer():\n    return 1\n",
        "dynamic.py": (
            b"class Worker:\n"
            b"    def check(self):\n"
            b"        return 1\n"
            b"    def run(self):\n"
            b"        return self.check()\n"
        ),
        "policy.json": b'{"revision":1}\n',
    }
    after = dict(
        before,
        **{
            "producer.py": b"def answer():\n    return 2\n",
            "policy.json": b'{"revision":2}\n',
        },
    )
    graph = build_impact_graph(
        before,
        after,
        [
            _change("producer.py", 2, 2, identifier="producer-change"),
            _change("policy.json", 1, 1, identifier="policy-change"),
        ],
    )
    dynamic = [row for row in graph["frontier"] if row["kind"] == "dynamic_dispatch"]
    assert {(row["side"], row["path"]) for row in dynamic} == {
        ("before", "dynamic.py"),
        ("after", "dynamic.py"),
    }
    assert all(row["source_obligations"] == [] for row in dynamic)

    unsupported = [
        row for row in graph["frontier"] if row["kind"] == "unsupported_language"
    ]
    assert {(row["side"], tuple(row["source_obligations"])) for row in unsupported} == {
        ("before", ("policy-change",)),
        ("after", ("policy-change",)),
    }
    assert graph["status"] == "UNKNOWN"
