"""Adversarial bounded graph interpretations; no physical causal assertions.

Terminology: JavaScript Object Notation (JSON); Verifier Standard (VSTD).
"""

from __future__ import annotations

import copy
import json
from typing import Any, Iterable, Mapping

import pytest

from verifier.data.assurance import AssuranceFlowError, AssuranceLedger
from verifier.data.models import (
    ArtifactNode, ArtifactType, HyperedgePort, ProvenanceHypergraph,
    TransformationHyperedge, TransformationType,
)
from verifier.interoperability import graph_topology as topology
from verifier.interoperability.graph_topology import (
    GRAPH_TOPOLOGY_SCHEMA_VERSION, GraphTopologyContract, GraphTopologyError,
    GraphTopologyStatus, analyze_graph_topology, graph_topology_binding_digest,
)


def _graph(names: tuple[str, ...] = ("x", "y"), links: list[tuple[str, tuple[str, ...], tuple[str, ...]]] | None = None) -> ProvenanceHypergraph:
    graph = ProvenanceHypergraph()
    for name in names:
        graph.add_artifact(ArtifactNode(name, name, ArtifactType.CONFIG, "a" * 64))
    if links is None:
        links = [(f"edge:{name}", (name,), (name,)) for name in names]
    for identifier, sources, targets in links:
        graph.add_transformation(TransformationHyperedge(
            identifier, identifier, TransformationType.EVALUATION,
            tuple(HyperedgePort(source, "IN") for source in sources),
            tuple(HyperedgePort(target, "OUT") for target in targets), {}, {}, {},
        ))
    return graph


def _payload(graph: ProvenanceHypergraph, equations: Iterable[Mapping[str, Any]] = (), temporal: Iterable[Mapping[str, Any]] = (), candidates: Iterable[Mapping[str, Any]] = (), variables: Iterable[str] | None = None) -> dict[str, Any]:
    bindings = []
    for variable in sorted(graph.artifacts if variables is None else variables):
        choices = [(identifier, direction, port.role)
                   for identifier, edge in sorted(graph.transformations.items())
                   for direction, ports in (("input", edge.inputs), ("output", edge.outputs))
                   for port in ports if port.artifact_id == variable]
        if not choices:
            continue
        identifier, direction, role = choices[0]
        bindings.append({"variable_id": variable, "artifact_id": variable,
            "transformation_id": identifier, "port_direction": direction, "role": role})
    return {"schema_version": GRAPH_TOPOLOGY_SCHEMA_VERSION,
        "graph_digest": graph_topology_binding_digest(graph), "bindings": bindings,
        "constraint_logic": "classical-boolean-equations-v1", "equations": list(equations),
        "temporal_relations": list(temporal), "paradox_candidates": list(candidates)}


def _eq(identifier: str, target: str, operator: str, *arguments: str) -> dict[str, Any]:
    return {"id": identifier, "target": target, "operator": operator, "arguments": list(arguments)}


def _time(identifier: str, source: str, target: str, offset: int, clock: str = "clock", unit: str = "tick") -> dict[str, Any]:
    return {"id": identifier, "source": source, "target": target, "clock_id": clock,
        "unit": unit, "offset": offset,
        "meaning": "backward_time" if offset < 0 else "forward_time" if offset > 0 else "same_time"}


def _analyze(graph: ProvenanceHypergraph, payload: Mapping[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
    return analyze_graph_topology(graph, GraphTopologyContract.from_dict(
        _payload(graph) if payload is None else payload), **kwargs).to_dict()


@pytest.mark.parametrize("operator,status", [("identity", "CONSISTENT"), ("not", "CONFLICTED")])
def test_self_reference_is_structural_not_automatically_a_paradox(operator: str, status: str) -> None:
    graph = _graph(("x",))
    result = _analyze(graph, _payload(graph, [_eq("eq", "x", operator, "x")]))
    assert result["structural"]["status"] == "CONSISTENT"
    assert result["structural"]["self_references"] == [{"transformation_id": "edge:x",
        "source": "x", "source_role": "IN", "target": "x", "target_role": "OUT"}]
    assert result["boolean_consistency"]["status"] == status
    assert result["temporal_consistency"]["status"] == "NOT_ESTABLISHED"
    assert result["verification_effect"] == "NONE"
    assert "status" not in result and "conformance" not in result


def test_mutual_negation_has_a_joint_witness() -> None:
    graph = _graph(links=[("xy", ("x",), ("y",)), ("yx", ("y",), ("x",))])
    result = _analyze(graph, _payload(graph, [_eq("one", "x", "not", "y"), _eq("two", "y", "not", "x")]))
    assert result["structural"]["mutually_reachable_groups"] == [["x", "y"]]
    assert result["boolean_consistency"]["status"] == "CONSISTENT"
    witness = result["boolean_consistency"]["witness"]
    assert witness["x"] is not witness["y"]


def test_contradictory_constants_conflict_without_a_graph_cycle() -> None:
    graph = _graph(links=[("xy", ("x",), ("y",))])
    result = _analyze(graph, _payload(graph, [_eq("one", "y", "true"), _eq("two", "y", "false")]))
    assert result["structural"]["self_references"] == []
    assert result["structural"]["mutually_reachable_groups"] == []
    assert result["boolean_consistency"]["status"] == "CONFLICTED"
    assert result["boolean_consistency"]["assignments_checked"] == 2


@pytest.mark.parametrize("operator,arguments,expected", [
    ("true", (), True), ("false", (), False), ("identity", ("x",), True),
    ("not", ("x",), False), ("and", ("x", "y"), False),
    ("or", ("x", "y"), True), ("xor", ("x", "y"), True),
    ("xor", ("x", "x"), False),
])
def test_boolean_operators_are_checked_jointly(operator: str, arguments: tuple[str, ...], expected: bool) -> None:
    graph = _graph(("x", "y", "z"))
    result = _analyze(graph, _payload(graph, [_eq("x-true", "x", "true"),
        _eq("y-false", "y", "false"), _eq("result", "z", operator, *arguments)]))
    assert result["boolean_consistency"]["status"] == "CONSISTENT"
    assert result["boolean_consistency"]["witness"] == {"x": True, "y": False, "z": expected}


def test_forward_negating_transition_is_not_simultaneous_self_negation() -> None:
    graph = _graph(("now", "next"), [("transition", ("now",), ("next",))])
    payload = _payload(graph, [_eq("initial", "now", "false"), _eq("step", "next", "not", "now")],
                       [_time("time-step", "now", "next", 1)])
    result = _analyze(graph, payload)
    assert all(result[facet]["status"] == "CONSISTENT"
               for facet in ("structural", "boolean_consistency", "temporal_consistency"))
    assert result["boolean_consistency"]["witness"] == {"next": True, "now": False}


def test_paradox_candidates_are_retained_annotations_only() -> None:
    graph = _graph(("x",))
    candidate = {"id": "candidate", "variables": ["x"], "description": "A proposed liar-like interpretation, not a proof."}
    result = _analyze(graph, _payload(graph, candidates=[candidate]))
    assert result["paradox_candidates"] == [candidate]
    assert result["boolean_consistency"]["status"] == "NOT_ESTABLISHED"
    assert result["temporal_consistency"]["status"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("offset", [-9, 0, 7])
def test_relative_time_including_backward_time_is_not_automatically_conflicted(offset: int) -> None:
    graph = _graph()
    result = _analyze(graph, _payload(graph, temporal=[_time("time", "x", "y", offset)]))
    facet = result["temporal_consistency"]
    assert facet["status"] == "CONSISTENT"
    potentials = facet["clocks"][0]["spanning_tree_potentials"]
    assert potentials["y"] - potentials["x"] == offset


@pytest.mark.parametrize("return_offset,status", [(-1, "CONSISTENT"), (1, "CONFLICTED")])
def test_temporal_loop_uses_exact_offset_sum(return_offset: int, status: str) -> None:
    graph = _graph()
    result = _analyze(graph, _payload(graph, temporal=[_time("forward", "x", "y", 1),
        _time("return", "y", "x", return_offset)]))
    facet = result["temporal_consistency"]
    assert facet["status"] == status
    if status == "CONFLICTED":
        conflicts = facet["clocks"][0]["conflicts"]
        assert conflicts and conflicts[0]["declared_offset"] != conflicts[0]["implied_offset"]
        assert conflicts[0]["supporting_relation_ids"]


def test_nonzero_temporal_self_relation_conflicts() -> None:
    graph = _graph(("x",))
    result = _analyze(graph, _payload(graph, temporal=[_time("back", "x", "x", -1)]))
    assert result["temporal_consistency"]["status"] == "CONFLICTED"


def test_separate_clocks_and_disconnected_origins_do_not_compare() -> None:
    graph = _graph(("x", "y", "z"))
    result = _analyze(graph, _payload(graph, temporal=[_time("one", "x", "y", 1, "A"),
        _time("two", "x", "y", -3, "B", "nanosecond"), _time("isolated", "z", "z", 0, "A")]))
    assert result["temporal_consistency"]["status"] == "CONSISTENT"
    assert [clock["clock_id"] for clock in result["temporal_consistency"]["clocks"]] == ["A", "B"]


def test_disconnected_pairs_in_one_clock_have_separate_arbitrary_origins() -> None:
    graph = _graph(("a", "b", "c", "d"))
    result = _analyze(graph, _payload(graph, temporal=[_time("one", "a", "b", 2), _time("two", "c", "d", 5)]))
    clock = result["temporal_consistency"]["clocks"][0]
    assert clock["relative_components"] == [
        {"origin_variable": "a", "variable_ids": ["a", "b"]},
        {"origin_variable": "c", "variable_ids": ["c", "d"]},
    ]
    assert "no between-component offset is established" in clock["origin_scope"]
    assert clock["spanning_tree_potentials"] == {"a": 0, "b": 2, "c": 0, "d": 5}


def test_mixed_units_on_one_clock_are_rejected() -> None:
    graph = _graph()
    payload = _payload(graph, temporal=[_time("one", "x", "y", 1), _time("two", "x", "y", 1, unit="nanosecond")])
    with pytest.raises(GraphTopologyError, match="mix units"):
        GraphTopologyContract.from_dict(payload)


@pytest.mark.parametrize("field,value", [("artifact_id", "missing"), ("transformation_id", "missing"),
    ("role", "OTHER"), ("port_direction", "output")])
def test_exact_binding_substitutions_are_invalid_even_for_unsupported_logic(field: str, value: str) -> None:
    graph = _graph()
    payload = _payload(graph)
    payload["constraint_logic"] = "unimplemented-logic"
    payload["bindings"][0][field] = value
    result = _analyze(graph, payload)
    assert all(result[facet]["status"] == "INVALID"
               for facet in ("structural", "boolean_consistency", "temporal_consistency"))


def test_graph_substitution_and_metadata_change_invalidate_old_binding() -> None:
    graph = _graph()
    payload = _payload(graph)
    graph.artifacts["x"].attributes["declared-purpose"] = "changed"
    result = _analyze(graph, payload)
    assert result["structural"]["status"] == "INVALID"
    assert result["graph_digest"] != result["expected_graph_digest"]


def test_unsupported_logic_is_not_reinterpreted() -> None:
    graph = _graph(("x",))
    payload = _payload(graph, [_eq("eq", "x", "not", "x")])
    payload["constraint_logic"] = "three-valued-logic"
    result = _analyze(graph, payload)
    assert result["structural"]["status"] == "CONSISTENT"
    assert result["boolean_consistency"]["status"] == "NOT_ESTABLISHED"


def test_assignment_exhaustion_is_unknown_not_refutation() -> None:
    graph = _graph(("x",))
    payload = _payload(graph, [_eq("eq", "x", "true")])
    limited = _analyze(graph, payload, max_assignments=1)
    assert limited["boolean_consistency"]["status"] == "NOT_ESTABLISHED"
    assert limited["boolean_consistency"]["assignments_checked"] == 1
    assert _analyze(graph, payload, max_assignments=2)["boolean_consistency"]["witness"] == {"x": True}


@pytest.mark.parametrize("budget", [True, False, 0, -1, 4097, 1.0, "1"])
def test_assignment_budget_is_strictly_typed_and_bounded(budget: Any) -> None:
    with pytest.raises(GraphTopologyError, match="max_assignments"):
        _analyze(_graph(), max_assignments=budget)


@pytest.mark.parametrize("kind", ["variables", "equations", "offset"])
def test_semantic_work_limits_preserve_unknown(kind: str) -> None:
    graph = _graph(tuple(f"v{index}" for index in range(13)))
    payload = _payload(graph)
    if kind == "variables":
        payload["equations"] = [_eq(f"eq{index}", f"v{index}", "true") for index in range(13)]
        facet = "boolean_consistency"
    elif kind == "equations":
        payload["equations"] = [_eq(f"eq{index}", "v0", "true") for index in range(129)]
        facet = "boolean_consistency"
    else:
        payload["temporal_relations"] = [_time("time", "v0", "v1", topology.MAX_ABS_OFFSET + 1)]
        facet = "temporal_consistency"
    assert _analyze(graph, payload)[facet]["status"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("mutation", ["unknown-top", "unknown-row", "digest", "boolean-offset", "float-offset",
    "duplicate-variable", "alias-port", "duplicate-id", "operator", "arity", "unknown-variable", "sign", "unit", "array", "unicode"])
def test_malformed_contracts_raise_without_coercion(mutation: str) -> None:
    graph = _graph()
    payload = _payload(graph, [_eq("eq", "x", "identity", "x")], [_time("time", "x", "y", 1)])
    if mutation == "unknown-top": payload["extra"] = 1
    elif mutation == "unknown-row": payload["equations"][0]["extra"] = 1
    elif mutation == "digest": payload["graph_digest"] = "sha256:" + "A" * 64
    elif mutation == "boolean-offset": payload["temporal_relations"][0]["offset"] = True
    elif mutation == "float-offset": payload["temporal_relations"][0]["offset"] = 1.0
    elif mutation == "duplicate-variable": payload["bindings"].append(copy.deepcopy(payload["bindings"][0]))
    elif mutation == "alias-port": payload["bindings"].append({**payload["bindings"][0], "variable_id": "alias"})
    elif mutation == "duplicate-id": payload["temporal_relations"][0]["id"] = "eq"
    elif mutation == "operator": payload["equations"][0]["operator"] = "nand"
    elif mutation == "arity": payload["equations"][0]["arguments"] = []
    elif mutation == "unknown-variable": payload["equations"][0]["target"] = "missing"
    elif mutation == "sign": payload["temporal_relations"][0]["meaning"] = "backward_time"
    elif mutation == "unit": payload["temporal_relations"][0]["unit"] = "seconds"
    elif mutation == "array": payload["bindings"] = tuple(payload["bindings"])
    else: payload["constraint_logic"] = "bad\ud800"
    with pytest.raises(GraphTopologyError):
        GraphTopologyContract.from_dict(payload)


def test_repeated_actual_ports_are_ambiguous_but_distinct_roles_are_not_aliases() -> None:
    graph = _graph(("x",))
    graph.transformations["edge:x"].inputs = (HyperedgePort("x", "IN"), HyperedgePort("x", "IN"))
    result = _analyze(graph)
    assert result["structural"]["status"] == "INVALID"
    graph.transformations["edge:x"].inputs = (HyperedgePort("x", "IN"), HyperedgePort("x", "OTHER"))
    payload = _payload(graph)
    payload["bindings"].append({**payload["bindings"][0], "variable_id": "other", "role": "OTHER"})
    payload["equations"] = [_eq("one", "x", "true"), _eq("two", "other", "false")]
    assert _analyze(graph, payload)["boolean_consistency"]["witness"] == {"other": False, "x": True}


def test_forks_joins_parallel_edges_and_disconnected_components() -> None:
    graph = _graph(("a", "b", "c", "d", "isolated"), [("fork", ("a",), ("b", "c")),
        ("join", ("b", "c"), ("d",)), ("parallel", ("a",), ("b",))])
    facet = _analyze(graph)["structural"]
    assert facet["forks"] == [{"artifact_id": "a", "targets": ["b", "c"]}]
    assert facet["joins"] == [{"artifact_id": "d", "sources": ["b", "c"]}]
    assert facet["disconnected_components"] == [["a", "b", "c", "d"], ["isolated"]]
    assert len(facet["edge_witnesses"]) == 5


def test_deep_graph_uses_iterative_traversal() -> None:
    names = tuple(f"node:{index:04}" for index in range(1200))
    links = [(f"edge:{index:04}", (names[index],), (names[index + 1],)) for index in range(len(names) - 1)]
    graph = _graph(names, links)
    payload = _payload(graph, variables=())
    result = _analyze(graph, payload)
    assert result["structural"]["status"] == "CONSISTENT"
    assert result["structural"]["mutually_reachable_groups"] == []
    assert len(result["structural"]["disconnected_components"][0]) == 1200


@pytest.mark.parametrize("limit", ["MAX_GRAPH_NODES", "MAX_GRAPH_TRANSFORMATIONS", "MAX_GRAPH_PORTS", "MAX_PROJECTED_PAIRS"])
def test_graph_work_bounds_fail_closed(monkeypatch: pytest.MonkeyPatch, limit: str) -> None:
    graph = _graph()
    payload = _payload(graph)
    monkeypatch.setattr(topology, limit, 1)
    result = _analyze(graph, payload)
    assert result["structural"]["status"] == "NOT_ESTABLISHED"
    assert result["graph_digest"] is None


def test_source_and_contract_are_unchanged_and_report_order_is_stable() -> None:
    graph = _graph()
    before = copy.deepcopy(graph.to_dict())
    payload = _payload(graph, [_eq("x", "x", "not", "y"), _eq("y", "y", "not", "x")],
                       [_time("one", "x", "y", 1), _time("two", "y", "x", -1)])
    contract = GraphTopologyContract.from_dict(payload)
    first = analyze_graph_topology(graph, contract).to_dict()
    for key in ("bindings", "equations", "temporal_relations"):
        payload[key].reverse()
    assert _analyze(graph, payload) == first
    changed = contract.to_dict()
    changed["equations"].clear()
    assert analyze_graph_topology(graph, contract).to_dict() == first
    assert graph.to_dict() == before
    assert graph.verify_acyclicity() is False
    with pytest.raises(AssuranceFlowError, match="cyclic provenance"):
        AssuranceLedger(graph)
    assert set(first["checker_coordinate"]["source_digests"]) == {
        "verifier.interoperability.graph_topology", "verifier.data.models"}
    assert first["contract_digest"].startswith("sha256:")
    assert not any(path in json.dumps(first) for path in ("E:\\", "C:\\", "/home/", "/Users/"))


def test_invalid_recorded_graph_is_not_accepted_as_a_model() -> None:
    graph = _graph()
    graph.transformations["edge:x"].outputs = (HyperedgePort("missing", "OUT"),)
    result = _analyze(graph)
    assert result["structural"]["status"] == "INVALID"


def test_enum_is_not_an_aggregate_verification_status() -> None:
    assert {value.value for value in GraphTopologyStatus} == {"CONSISTENT", "CONFLICTED", "NOT_ESTABLISHED", "INVALID"}


@pytest.mark.parametrize("document", [
    b"[" * 10000 + b"0" + b"]" * 10000,
    b'{"schema_version":1,"schema_version":2}',
    b" " * (topology.MAX_DOCUMENT_BYTES + 1),
    b"null", b"{", "not bytes",
], ids=["over-depth", "duplicate-key", "over-bytes", "non-object", "truncated", "non-bytes"])
def test_forged_direct_contract_records_fail_at_the_bounded_decoder(document: Any) -> None:
    with pytest.raises(GraphTopologyError):
        analyze_graph_topology(_graph(), GraphTopologyContract(document))


def test_checker_coordinate_does_not_claim_loaded_code_attestation() -> None:
    coordinate = _analyze(_graph())["checker_coordinate"]
    assert coordinate["mechanism_id"] == "mechanism:graph-topology-analysis"
    assert coordinate["implementation_ref"] == "verifier.interoperability.graph_topology:analyze_graph_topology"
    assert coordinate["coordinate_kind"] == "LOCAL_SOURCE_BYTES_NOT_RUNTIME_ATTESTATION"
