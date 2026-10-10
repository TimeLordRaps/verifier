"""abstract syntax tree (AST) impact graph counterexamples and bounded evidence.

Pull Request Domain Explanation Language (PRDEL) graph data represents syntax,
not verified contracts or complete runtime impact. Strongly connected components
(SCCs) retain cycles in directed acyclic graph (DAG) presentation.
"""

from __future__ import annotations

from typing import Any

import pytest

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
    return {node["id"]: node for node in graph["nodes"]}


def test_changed_producer_exposes_unchanged_consumer_and_transitive_caller() -> None:
    before = {
        "src/pkg/producer.py": b"def parse(value):\n    return value\n",
        ("src/pkg/consumer.py"): (
            b"from pkg.producer import parse\ndef consume(value):\n    "
            b"return parse(value)\n"
        ),
        ("src/pkg/client.py"): (
            b"from pkg.consumer import consume\ndef run(value):\n    "
            b"return consume(value)\n"
        ),
    }
    after = dict(
        before, **{"src/pkg/producer.py": b"def parse(value):\n    return value + 1\n"}
    )
    graph = build_impact_graph(before, after, [_change("src/pkg/producer.py", 2, 2)])
    nodes = _nodes(graph)
    call_edges = [
        edge
        for edge in graph["edges"]
        if edge["side"] == "after" and edge["relationship"] == "call"
    ]
    assert {
        (nodes[edge["source"]]["symbol"], nodes[edge["target"]]["symbol"])
        for edge in call_edges
    } == {
        ("parse", "consume"),
        ("consume", "run"),
    }
    consumer = next(
        node
        for node in graph["nodes"]
        if node["side"] == "after" and node["symbol"] == "consume"
    )
    assert not consumer["changed"]
    assert consumer["source_obligations"] == ["change-1"]
    assert all(edge["source_obligations"] == ["change-1"] for edge in call_edges)
    assert (
        len(
            [
                item
                for item in graph["obligations"]
                if item["path"] == "src/pkg/client.py"
            ]
        )
        >= 1
    )
    assert all(edge["evidence_state"] != "verified_contract" for edge in graph["edges"])


def test_changed_caller_preserves_transitive_callee_blast_radius() -> None:
    before = {
        "leaf.py": b"def leaf(value):\n    return value\n",
        "middle.py": b"from leaf import leaf\ndef middle(value):\n    return leaf(value)\n",
        "caller.py": b"from middle import middle\ndef caller(value):\n    return middle(value)\n",
    }
    after = dict(
        before,
        **{
            "caller.py": (
                b"from middle import middle\ndef caller(value):\n"
                b"    return middle(value) + 1\n"
            )
        },
    )
    graph = build_impact_graph(
        before,
        after,
        [_change("caller.py", 3, 3, identifier="caller-change")],
    )
    nodes = _nodes(graph)
    after_calls = [
        edge
        for edge in graph["edges"]
        if edge["side"] == "after" and edge["relationship"] == "call"
    ]
    by_symbols = {
        (nodes[edge["source"]]["symbol"], nodes[edge["target"]]["symbol"]): edge
        for edge in after_calls
    }
    assert by_symbols[("middle", "caller")]["source_obligations"] == ["caller-change"]
    assert by_symbols[("leaf", "middle")]["source_obligations"] == ["caller-change"]
    assert next(
        row
        for row in graph["nodes"]
        if row["side"] == "after" and row["symbol"] == "leaf"
    )["source_obligations"] == ["caller-change"]


def test_rename_and_removal_preserve_old_relationship_and_new_missing_boundary() -> (
    None
):
    before = {
        "a.py": b"def old():\n    return 1\n",
        "b.py": b"from a import old\ndef call():\n    return old()\n",
    }
    after = {"a.py": b"def replacement():\n    return 2\n", "b.py": before["b.py"]}
    graph = build_impact_graph(before, after, [_change("a.py", 1, 2)])
    nodes = _nodes(graph)
    assert any(
        edge["side"] == "before"
        and nodes[edge["source"]]["symbol"] == "old"
        and edge["relationship"] == "call"
        for edge in graph["edges"]
    )
    assert any(
        item["kind"] == "unresolved_call"
        and item["side"] == "after"
        and "old" in item["question"]
        for item in graph["frontier"]
    )
    assert any(
        item["kind"] == "unresolved_call"
        and item["side"] == "after"
        and item["source_obligations"] == ["change-1"]
        for item in graph["frontier"]
    )
    assert graph["status"] == "UNKNOWN"


def test_file_removal_remains_source_bound_before_graph() -> None:
    before = {
        "a.py": b"def removed():\n    return 1\n",
        "b.py": b"from a import removed\nremoved()\n",
    }
    change = _change("a.py", 1, 2, kind="removed")
    change["new_range"] = [0, 0]
    graph = build_impact_graph(before, {"b.py": before["b.py"]}, [change])
    assert any(
        node["side"] == "before" and node["path"] == "a.py" and node["changed"]
        for node in graph["nodes"]
    )
    assert not any(
        node["side"] == "after" and node["path"] == "a.py" for node in graph["nodes"]
    )
    assert any(
        item["source_obligations"] == ["change-1"] for item in graph["obligations"]
    )


def test_cycles_retained_and_components_form_dag() -> None:
    files = {
        ("a.py"): (
            b"def first():\n    return second()\ndef second():\n    "
            b"return first()\n"
        )
    }
    graph = build_impact_graph({}, files, [_change("a.py", 1, 4, kind="added")])
    nodes = _nodes(graph)
    cyclic = [part for part in graph["components"] if part["cyclic"]]
    assert len(cyclic) == 1
    assert {nodes[key]["symbol"] for key in cyclic[0]["members"]} == {"first", "second"}
    assert len([edge for edge in graph["edges"] if edge["relationship"] == "call"]) == 2
    assert all(edge["source"] != edge["target"] for edge in graph["dag_edges"])
    assert graph["dag_edges"] == []


def test_inheritance_override_and_shared_type_relationships() -> None:
    files = {
        ("types.py"): (
            b"class Payload:\n    pass\nclass Base:\n    def run(self):\n "
            b"       return 1\n"
        ),
        ("consumer.py"): (
            b"from types import Base, Payload\nclass Child(Base):\n    "
            b"def run(self):\n        return 2\ndef consume(value: "
            b"Payload):\n    return value\n"
        ),
    }
    graph = build_impact_graph({}, files, [_change("types.py", 1, 5, kind="added")])
    relationships = {edge["relationship"] for edge in graph["edges"]}
    assert {"inheritance", "override", "annotation", "import"}.issubset(relationships)
    assert any(item["path"] == "consumer.py" for item in graph["obligations"])
    nodes = _nodes(graph)
    annotation = next(
        edge for edge in graph["edges"] if edge["relationship"] == "annotation"
    )
    assert nodes[annotation["target"]]["symbol"] == "consume"


def test_dynamic_and_external_calls_are_explicit_unresolved_boundaries() -> None:
    files = {
        ("worker.py"): (
            b"import external\ndef run(obj):\n    obj.compute()\n    "
            b"external.call()\n    getattr(obj, 'compute')()\n"
        )
    }
    graph = build_impact_graph({}, files, [_change("worker.py", 1, 5, kind="added")])
    assert graph["status"] == "UNKNOWN"
    questions = [item["question"] for item in graph["frontier"]]
    assert any("obj.compute" in question for question in questions)
    assert any("external.call" in question for question in questions)
    assert any("dynamic expression" in question for question in questions)
    assert all(item["source_ref"]["blob_sha256"] for item in graph["frontier"])


@pytest.mark.parametrize(
    "consumer",
    [
        b"from a import parse\ndef consume(parse):\n    return parse()\n",
        (
            b"from a import parse\ndef consume():\n    parse = unknown\n "
            b"   return parse()\n"
        ),
        b"from a import parse\nparse = unknown\ndef consume():\n    return parse()\n",
    ],
)
def test_shadowed_import_is_not_resolved_to_wrong_producer(consumer: bytes) -> None:
    files = {"a.py": b"def parse():\n    return 1\n", "b.py": consumer}
    graph = build_impact_graph({}, files, [_change("a.py", 1, 2)])
    assert not any(edge["relationship"] == "call" for edge in graph["edges"])
    assert any(item["kind"] == "unresolved_call" for item in graph["frontier"])


def test_single_local_constructor_relationship_but_ambiguous_reassignment_unknown() -> (
    None
):
    source = (
        b"class Worker:\n    def run(self):\n        return 1\ndef "
        b"call():\n    worker = Worker()\n    return worker.run()\n"
    )
    graph = build_impact_graph({}, {"a.py": source}, [_change("a.py", 1, 6)])
    nodes = _nodes(graph)
    assert any(
        edge["relationship"] == "call"
        and nodes[edge["source"]]["symbol"] == "Worker.run"
        for edge in graph["edges"]
    )
    method = next(
        edge
        for edge in graph["edges"]
        if nodes[edge["source"]]["symbol"] == "Worker.run"
    )
    assert method["evidence_state"] == "syntactic_candidate"
    assert any(
        item["kind"] == "dynamic_dispatch"
        and item["source_obligations"] == ["change-1"]
        for item in graph["frontier"]
    )
    assert graph["status"] == "UNKNOWN"
    changed = source.replace(
        b"    return worker.run()", b"    worker = external\n    return worker.run()"
    )
    ambiguous = build_impact_graph({}, {"a.py": changed}, [_change("a.py", 1, 7)])
    ambiguous_nodes = _nodes(ambiguous)
    assert not any(
        edge["relationship"] == "call"
        and ambiguous_nodes[edge["source"]]["symbol"] == "Worker.run"
        for edge in ambiguous["edges"]
    )
    assert any(
        item["kind"] == "unresolved_call" and "worker.run" in item["question"]
        for item in ambiguous["frontier"]
    )


@pytest.mark.parametrize("receiver", ["self", "cls"])
def test_self_or_cls_target_requires_runtime_dispatch_evidence(receiver: str) -> None:
    source = (
        f"class Worker:\n    def check({receiver}):\n        return 1\n"
        f"    def run({receiver}):\n        return {receiver}.check()\n"
    ).encode()
    graph = build_impact_graph({}, {"worker.py": source}, [_change("worker.py", 2, 3)])
    edges = [edge for edge in graph["edges"] if edge["relationship"] == "call"]
    assert len(edges) == 1
    assert edges[0]["evidence_state"] == "syntactic_candidate"
    frontier = next(
        item for item in graph["frontier"] if item["kind"] == "dynamic_dispatch"
    )
    assert frontier["source_obligations"] == ["change-1"]
    assert "not a resolved runtime target" in frontier["question"]
    assert graph["status"] == "UNKNOWN"
    assert edges[0]["id"] not in {
        row["edge_id"] for row in graph["obligations"]
    }


def test_relative_import_and_registration_argument_surface_shared_checker() -> None:
    files = {
        "src/pkg/checker.py": b"def verify():\n    return True\n",
        ("src/pkg/routes.py"): (
            b"from .checker import verify\ndef register(name, "
            b"checker):\n    return checker\nregister('route', verify)\n"
        ),
    }
    graph = build_impact_graph({}, files, [_change("src/pkg/checker.py", 1, 2)])
    nodes = _nodes(graph)
    registration = [
        edge for edge in graph["edges"] if edge["relationship"] == "registration_input"
    ]
    assert len(registration) == 1
    assert nodes[registration[0]["source"]]["symbol"] == "verify"
    assert registration[0]["source_obligations"] == ["change-1"]


def test_generic_annotation_preserves_local_schema_and_builtin_unknown() -> None:
    files = {
        ("a.py"): (
            b"class Payload:\n    pass\ndef consume(value: "
            b"list[Payload]):\n    return value\n"
        )
    }
    graph = build_impact_graph({}, files, [_change("a.py", 1, 2)])
    nodes = _nodes(graph)
    assert any(
        edge["relationship"] == "annotation"
        and nodes[edge["source"]]["symbol"] == "Payload"
        and nodes[edge["target"]]["symbol"] == "consume"
        for edge in graph["edges"]
    )
    assert any(
        item["kind"] == "unresolved_annotation" and "list" in item["question"]
        for item in graph["frontier"]
    )


def test_candidate_source_is_parsed_without_import_or_execution(tmp_path: Any) -> None:
    marker = tmp_path / "must-not-exist"
    source = ("open(" + repr(str(marker)) + ", 'w').write('executed')\n").encode()
    graph = build_impact_graph(
        {}, {"untrusted.py": source}, [_change("untrusted.py", 1, 1)]
    )
    assert not marker.exists()
    assert graph["status"] == "UNKNOWN"


@pytest.mark.parametrize(
    "bound,value", [("max_nodes", 1), ("max_edges", 1), ("max_operations", 1)]
)
def test_bound_exhaustion_cannot_claim_complete(bound: str, value: int) -> None:
    files = {
        ("a.py"): (
            b"def first():\n    return second()\ndef second():\n    "
            b"return first()\n"
        )
    }
    graph = build_impact_graph({}, files, [_change("a.py", 1, 4)], **{bound: value})
    assert graph["status"] == "UNKNOWN"
    assert any(item["kind"].endswith("_bound") for item in graph["frontier"])
    assert graph["counters"]["operations"] <= graph["bounds"]["max_operations"]


def test_non_python_and_invalid_source_have_explicit_frontiers() -> None:
    files = {"schema.json": b'{"type":"object"}', "bad.py": b"def broken(\n"}
    graph = build_impact_graph(
        {},
        files,
        [_change("schema.json", 1, 1), _change("bad.py", 1, 1, identifier="bad")],
    )
    assert {item["kind"] for item in graph["frontier"]} == {
        "unsupported_language",
        "parse_failure",
    }
    assert graph["status"] == "UNKNOWN"
    parse_boundary = next(
        item for item in graph["frontier"] if item["kind"] == "parse_failure"
    )
    # Parsing failed before source relationships could exclude the other
    # selected change, so the malformed path conservatively retains both.
    assert parse_boundary["source_obligations"] == ["bad", "change-1"]
    assert parse_boundary["consumer_id"] in _nodes(graph)


def test_unindexed_unchanged_consumer_cannot_silently_drop_impact_scope() -> None:
    before = {
        "producer.py": b"def parse():\n    return 1\n",
        "consumer.py": b"from producer import parse\ndef consume(\n",
    }
    after = dict(before, **{"producer.py": b"def parse():\n    return 2\n"})
    graph = build_impact_graph(before, after, [_change("producer.py", 2, 2)])
    failures = [item for item in graph["frontier"] if item["kind"] == "parse_failure"]
    assert len(failures) == 2
    assert all(item["source_obligations"] == ["change-1"] for item in failures)
    assert all("establish applicability" in item["question"] for item in failures)
    assert graph["status"] == "UNKNOWN"


def test_source_size_bound_stays_bound_to_changed_or_potentially_affected_path() -> (
    None
):
    source = b"# retained comment\n" * 1000
    graph = build_impact_graph(
        {}, {"large.py": source}, [_change("large.py", 1, 1000)], max_operations=100
    )
    frontier = next(
        item for item in graph["frontier"] if item["kind"] == "source_size_bound"
    )
    assert frontier["source_obligations"] == ["change-1"]
    assert frontier["consumer_id"] in _nodes(graph)
    assert graph["status"] == "UNKNOWN"


def test_repeated_analysis_and_input_order_are_deterministic() -> None:
    files = {
        "b.py": b"from a import parse\nparse()\n",
        "a.py": b"def parse():\n    return 1\n",
    }
    changes = [_change("a.py", 1, 2)]
    first = build_impact_graph({}, files, changes)
    second = build_impact_graph({}, dict(reversed(list(files.items()))), changes)
    assert first == second


@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_invalid_bounds_rejected(value: Any) -> None:
    with pytest.raises(ValueError, match="positive integers"):
        build_impact_graph({}, {}, [], max_nodes=value)



@pytest.mark.parametrize("bound", ["max_nodes", "max_edges", "max_operations"])
def test_global_bound_preserves_every_selected_producer(bound: str) -> None:
    files = {
        "a.py": b"def first():\n    return second()\ndef second():\n    return first()\n",
        "z.py": b"def later():\n    return 1\n",
    }
    changes = [
        _change("z.py", 2, 2, identifier="unvisited-z"),
        _change("a.py", 2, 2, identifier="visited-a"),
    ]
    graph = build_impact_graph({}, files, changes, **{bound: 1})
    frontier = next(row for row in graph["frontier"] if row["kind"] in {"analysis_bound", "frontier_bound"})
    assert frontier["source_obligations"] == ["unvisited-z", "visited-a"]
    assert graph["status"] == "UNKNOWN"
    assert graph["counters"]["operations"] <= graph["bounds"]["max_operations"]
    assert graph["counters"]["nodes"] <= graph["bounds"]["max_nodes"]
    assert graph["counters"]["edges"] <= graph["bounds"]["max_edges"]
    assert graph["components"] == graph["dag_edges"] == []


def test_unvisited_changed_path_cannot_drop_from_global_bound_scope() -> None:
    files = {"a.py": b"value = 1\n", "z.py": b"value = 2\n"}
    graph = build_impact_graph({}, files, [_change("z.py", 1, 1, identifier="later")], max_operations=1)
    assert not any(node["path"] == "z.py" for node in graph["nodes"])
    frontier = next(row for row in graph["frontier"] if row["kind"] == "analysis_bound")
    assert frontier["source_obligations"] == ["later"]
    assert graph["status"] == "UNKNOWN"


def test_global_bound_change_scope_is_unique_and_input_order_independent() -> None:
    files = {"a.py": b"value = 1\n", "z.py": b"value = 2\n"}
    changes = [
        _change("z.py", 1, 1, identifier="z"),
        _change("a.py", 1, 1, identifier="a"),
        _change("z.py", 1, 1, identifier="z"),
    ]
    first = build_impact_graph({}, files, changes, max_operations=1)
    second = build_impact_graph({}, files, list(reversed(changes)), max_operations=1)
    assert first == second
    frontier = next(row for row in first["frontier"] if row["kind"] == "analysis_bound")
    assert frontier["source_obligations"] == ["a", "z"]
    assert first["status"] == "UNKNOWN"


def test_completed_finite_graph_does_not_invent_a_global_bound() -> None:
    files = {"a.py": b"def answer():\n    return 1\n"}
    graph = build_impact_graph({}, files, [_change("a.py", 2, 2)])
    assert not any(row["kind"] == "analysis_bound" for row in graph["frontier"])
    assert graph["status"] == "BOUNDED_ANALYSIS_COMPLETE"
