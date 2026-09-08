"""Bounded interpretation of an exact recorded graph, without profile admission.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Verifier Standard (VSTD). A tick is one integer logical time step;
a nanosecond is an integer coordinate measured in 1e-9 seconds. Neither a
backward-time declaration nor simultaneous equations establish physical causality.

Malformed contracts raise GraphTopologyError. Analysis reports INVALID for graph
or port substitution and NOT_ESTABLISHED for unsupported semantics or exhausted
work bounds. Structural CONSISTENT means projection completed, not acyclicity.
No result changes provenance admission, establishes conformance, or emits TRUST.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any, Mapping

from verifier.data import models as _models
from verifier.data.models import ProvenanceHypergraph


GRAPH_TOPOLOGY_SCHEMA_VERSION = "VSTD-GRAPH-TOPOLOGY-EXPERIMENTAL-0.1"
GRAPH_TOPOLOGY_REPORT_SCHEMA_VERSION = "VSTD-GRAPH-TOPOLOGY-REPORT-EXPERIMENTAL-0.1"
SUPPORTED_CONSTRAINT_LOGIC = "classical-boolean-equations-v1"
MAX_GRAPH_NODES = 4096
MAX_GRAPH_TRANSFORMATIONS = 4096
MAX_GRAPH_PORTS = 16384
MAX_PROJECTED_PAIRS = 65536
MAX_BINDINGS = 256
MAX_EQUATIONS = 128
MAX_TEMPORAL_RELATIONS = 512
MAX_PARADOX_CANDIDATES = 128
MAX_BOOLEAN_VARIABLES = 12
MAX_ASSIGNMENTS = 4096
MAX_ABS_OFFSET = 10**12
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_DOCUMENT_DEPTH = 32
MAX_DOCUMENT_VALUES = 100000
_ARITY = {"true": 0, "false": 0, "identity": 1, "not": 1,
          "and": 2, "or": 2, "xor": 2}


class GraphTopologyError(ValueError):
    """Malformed input or unavailable exact source coordinate."""


class _Limit(GraphTopologyError):
    """A declared, bounded implementation surface was exceeded."""


class GraphTopologyStatus(str, Enum):
    """Facet-specific results; CONSISTENT is not a provenance verdict."""

    CONSISTENT = "CONSISTENT"
    CONFLICTED = "CONFLICTED"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"
    INVALID = "INVALID"


def _json_bytes(value: Any) -> bytes:
    stack = [(value, 0)]
    count = size = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if depth > MAX_DOCUMENT_DEPTH or count > MAX_DOCUMENT_VALUES:
            raise _Limit("document depth or value-count bound exceeded")
        if isinstance(item, Mapping):
            if len(item) + count > MAX_DOCUMENT_VALUES:
                raise _Limit("document value-count bound exceeded")
            for key, child in item.items():
                if type(key) is not str:
                    raise GraphTopologyError("JSON object keys must be strings")
                stack.extend(((key, depth + 1), (child, depth + 1)))
        elif isinstance(item, (list, tuple)):
            if len(item) + count > MAX_DOCUMENT_VALUES:
                raise _Limit("document value-count bound exceeded")
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item) > MAX_DOCUMENT_BYTES:
                raise _Limit("document byte bound exceeded")
            try:
                size += len(item.encode("utf-8"))
            except UnicodeError as exc:
                raise GraphTopologyError("document contains invalid Unicode") from exc
        elif item is None or type(item) is bool:
            size += 5
        elif type(item) is int:
            if item.bit_length() > 4096:
                raise _Limit("document integer-size bound exceeded")
            size += len(str(item))
        elif type(item) is float and math.isfinite(item):
            size += 32
        else:
            raise GraphTopologyError("document contains a non-JSON value")
        if size > MAX_DOCUMENT_BYTES:
            raise _Limit("document byte bound exceeded")
    try:
        document = json.dumps(value, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError) as exc:
        raise GraphTopologyError("document cannot be serialized exactly") from exc
    if len(document) > MAX_DOCUMENT_BYTES:
        raise _Limit("document byte bound exceeded")
    return document


def _digest(document: bytes) -> str:
    return "sha256:" + hashlib.sha256(document).hexdigest()


def _decode_document(document: bytes) -> dict[str, Any]:
    """Bound direct record-constructor input before invoking the JSON decoder."""
    if type(document) is not bytes:
        raise GraphTopologyError("record document must contain bytes")
    if len(document) > MAX_DOCUMENT_BYTES:
        raise _Limit("record document byte bound exceeded")
    depth = 0
    quoted = escaped = False
    for byte in document:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_DOCUMENT_DEPTH:
                raise _Limit("record document depth bound exceeded")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise GraphTopologyError("record document has unbalanced delimiters")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise GraphTopologyError("record document contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(document, object_pairs_hook=unique_object)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise GraphTopologyError("record document is not unambiguous bounded JSON") from exc
    if type(value) is not dict:
        raise GraphTopologyError("record document must contain an object")
    _json_bytes(value)
    return value


def _object(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise GraphTopologyError(f"{label} must have exactly {sorted(keys)}")
    return value


def _text(value: Any, label: str, *, limit: int = 256) -> str:
    if type(value) is not str or not value or value != value.strip() or len(value) > limit:
        raise GraphTopologyError(f"{label} must be a nonempty trimmed string <= {limit} characters")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if type(value) is not list:
        raise GraphTopologyError(f"{label} must be an array")
    return value


@dataclass(frozen=True)
class GraphTopologyContract:
    """Immutable, separately versioned interpretation contract, not a receipt.

    Use from_dict for admission. Row order is canonicalized by identifier; equation
    argument order remains bound. Semantic work limits are assessed by the analyzer.
    """

    _document: bytes

    @classmethod
    def from_dict(cls, mapping: Mapping[str, Any]) -> GraphTopologyContract:
        _json_bytes(mapping)
        data = _object(mapping, {"schema_version", "graph_digest", "bindings",
            "constraint_logic", "equations", "temporal_relations", "paradox_candidates"}, "contract")
        if data["schema_version"] != GRAPH_TOPOLOGY_SCHEMA_VERSION:
            raise GraphTopologyError("unsupported topology contract schema_version")
        if type(data["graph_digest"]) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", data["graph_digest"]) is None:
            raise GraphTopologyError("graph_digest must be a lowercase sha256: digest")
        result: dict[str, Any] = {"schema_version": data["schema_version"],
            "graph_digest": data["graph_digest"],
            "constraint_logic": _text(data["constraint_logic"], "constraint_logic")}
        variables: set[str] = set()
        bound_ports: set[tuple[str, str, str, str]] = set()
        bindings = []
        for item in _array(data["bindings"], "bindings"):
            row = dict(_object(item, {"variable_id", "artifact_id", "transformation_id", "port_direction", "role"}, "binding"))
            for key in row:
                row[key] = _text(row[key], f"binding.{key}")
            if row["port_direction"] not in {"input", "output"}:
                raise GraphTopologyError("port_direction must be input or output")
            if row["variable_id"] in variables:
                raise GraphTopologyError("duplicate variable_id")
            port = tuple(row[key] for key in ("artifact_id", "transformation_id", "port_direction", "role"))
            if port in bound_ports:
                raise GraphTopologyError("duplicate exact port binding requires unsupported alias semantics")
            bound_ports.add(port)
            variables.add(row["variable_id"])
            bindings.append(row)
        result["bindings"] = sorted(bindings, key=lambda row: row["variable_id"])
        identifiers: set[str] = set()
        clock_units: dict[str, str] = {}
        for field, keys in (
            ("equations", {"id", "target", "operator", "arguments"}),
            ("temporal_relations", {"id", "source", "target", "clock_id", "unit", "offset", "meaning"}),
            ("paradox_candidates", {"id", "variables", "description"}),
        ):
            rows = []
            for item in _array(data[field], field):
                row = dict(_object(item, keys, field))
                identifier = _text(row["id"], f"{field}.id")
                if identifier in identifiers:
                    raise GraphTopologyError("duplicate equation/relation/candidate id")
                identifiers.add(identifier)
                references: list[str]
                if field == "equations":
                    operator = _text(row["operator"], "equation.operator")
                    arguments = [_text(arg, "equation argument") for arg in _array(row["arguments"], "arguments")]
                    if operator not in _ARITY or len(arguments) != _ARITY[operator]:
                        raise GraphTopologyError("unknown equation operator or wrong arity")
                    row["arguments"] = arguments
                    references = [_text(row["target"], "equation.target"), *arguments]
                elif field == "temporal_relations":
                    references = [_text(row[key], f"temporal.{key}") for key in ("source", "target")]
                    clock = _text(row["clock_id"], "clock_id")
                    unit = _text(row["unit"], "unit")
                    if unit not in {"tick", "nanosecond"}:
                        raise GraphTopologyError("unit must be tick or nanosecond")
                    if clock in clock_units and clock_units[clock] != unit:
                        raise GraphTopologyError("one clock cannot mix units")
                    clock_units[clock] = unit
                    offset = row["offset"]
                    if type(offset) is not int:
                        raise GraphTopologyError("temporal offset must be an integer, not a Boolean")
                    meaning = _text(row["meaning"], "temporal.meaning")
                    expected = "backward_time" if offset < 0 else "forward_time" if offset > 0 else "same_time"
                    if meaning != expected:
                        raise GraphTopologyError("temporal meaning must match the offset sign")
                else:
                    references = [_text(arg, "candidate variable") for arg in _array(row["variables"], "candidate.variables")]
                    if not references or len(references) != len(set(references)):
                        raise GraphTopologyError("candidate variables must be nonempty and unique")
                    row["variables"] = sorted(references)
                    row["description"] = _text(row["description"], "candidate.description", limit=4096)
                if not set(references) <= variables:
                    raise GraphTopologyError("equation, temporal relation, or candidate references an unbound variable")
                rows.append(row)
            result[field] = sorted(rows, key=lambda row: row["id"])
        return cls(_json_bytes(result))

    def to_dict(self) -> dict[str, Any]:
        return _decode_document(self._document)


@dataclass(frozen=True)
class GraphTopologyReport:
    """Deterministic facet results; no aggregate semantic or provenance verdict."""

    _document: bytes

    def to_dict(self) -> dict[str, Any]:
        return _decode_document(self._document)


def _snapshot(graph: ProvenanceHypergraph) -> tuple[dict[str, Any], bytes]:
    if not isinstance(graph, ProvenanceHypergraph):
        raise GraphTopologyError("graph must be a ProvenanceHypergraph")
    if len(graph.artifacts) > MAX_GRAPH_NODES or len(graph.transformations) > MAX_GRAPH_TRANSFORMATIONS:
        raise _Limit("graph node or transformation bound exceeded")
    ports = pairs = 0
    for transform in graph.transformations.values():
        ports += len(transform.inputs) + len(transform.outputs)
        pairs += len(transform.inputs) * len(transform.outputs)
    if ports > MAX_GRAPH_PORTS or pairs > MAX_PROJECTED_PAIRS:
        raise _Limit("graph port or projected-pair bound exceeded")
    # Inspect metadata before the model serializer copies its dictionaries.
    for artifact in graph.artifacts.values():
        _json_bytes(artifact.attributes)
    for transform in graph.transformations.values():
        for metadata in (transform.parameters, transform.software_provenance, transform.execution_environment):
            _json_bytes(metadata)
    payload = graph.to_dict()
    return payload, _json_bytes(payload)


def graph_topology_binding_digest(graph: ProvenanceHypergraph) -> str:
    """Bind the exact serialized graph, preserving list order and all metadata.

    Raises GraphTopologyError for malformed or over-bound source representations;
    it never calls the provenance acyclicity-admission mechanism.
    """
    try:
        return _digest(_snapshot(graph)[1])
    except (AttributeError, TypeError, KeyError, ValueError) as exc:
        if isinstance(exc, GraphTopologyError):
            raise
        raise GraphTopologyError("graph cannot be bound exactly") from exc


def _facet(status: GraphTopologyStatus, detail: str, **values: Any) -> dict[str, Any]:
    return {"status": status.value, "detail": detail, **values}


def _groups(adjacency: dict[str, set[str]]) -> list[list[str]]:
    """Iterative strongly connected components, with deterministic output."""
    seen: set[str] = set()
    finished: list[str] = []
    for start in sorted(adjacency):
        if start in seen:
            continue
        seen.add(start)
        stack = [(start, iter(sorted(adjacency[start])))]
        while stack:
            node, children = stack[-1]
            child = next(children, None)
            if child is None:
                finished.append(node)
                stack.pop()
            elif child not in seen:
                seen.add(child)
                stack.append((child, iter(sorted(adjacency[child]))))
    reverse: dict[str, set[str]] = {node: set() for node in adjacency}
    for source, targets in adjacency.items():
        for target in targets:
            reverse[target].add(source)
    seen.clear()
    groups = []
    for start in reversed(finished):
        if start in seen:
            continue
        pending = [start]
        seen.add(start)
        group = []
        while pending:
            node = pending.pop()
            group.append(node)
            for child in sorted(reverse[node], reverse=True):
                if child not in seen:
                    seen.add(child)
                    pending.append(child)
        groups.append(sorted(group))
    return sorted(groups)


def _structure(graph: ProvenanceHypergraph) -> dict[str, Any]:
    adjacency = {node: set() for node in sorted(graph.artifacts)}
    reverse = {node: set() for node in adjacency}
    witnesses = set()
    for identifier, transform in sorted(graph.transformations.items()):
        for source in transform.inputs:
            for target in transform.outputs:
                adjacency[source.artifact_id].add(target.artifact_id)
                reverse[target.artifact_id].add(source.artifact_id)
                witnesses.add((identifier, source.artifact_id, source.role, target.artifact_id, target.role))
    edges = [{"transformation_id": edge, "source": source, "source_role": source_role,
              "target": target, "target_role": target_role}
             for edge, source, source_role, target, target_role in sorted(witnesses)]
    undirected = {node: adjacency[node] | reverse[node] for node in adjacency}
    return _facet(GraphTopologyStatus.CONSISTENT, "Directed input/output projection completed; cycles are descriptive, not admission.",
        artifact_count=len(adjacency), transformation_count=len(graph.transformations),
        self_references=[edge for edge in edges if edge["source"] == edge["target"]],
        mutually_reachable_groups=[group for group in _groups(adjacency) if len(group) > 1],
        forks=[{"artifact_id": node, "targets": sorted(targets)} for node, targets in adjacency.items() if len(targets) > 1],
        joins=[{"artifact_id": node, "sources": sorted(sources)} for node, sources in reverse.items() if len(sources) > 1],
        disconnected_components=_groups(undirected), edge_witnesses=edges)


def _boolean(data: dict[str, Any], max_assignments: int) -> dict[str, Any]:
    equations = data["equations"]
    if data["constraint_logic"] != SUPPORTED_CONSTRAINT_LOGIC:
        return _facet(GraphTopologyStatus.NOT_ESTABLISHED, "Unsupported constraint logic.")
    if not equations:
        return _facet(GraphTopologyStatus.NOT_ESTABLISHED, "No Boolean equations were supplied.")
    variables = sorted({variable for row in equations for variable in (row["target"], *row["arguments"])})
    if len(equations) > MAX_EQUATIONS or len(variables) > MAX_BOOLEAN_VARIABLES:
        return _facet(GraphTopologyStatus.NOT_ESTABLISHED, "Boolean equation or variable bound exceeded.")
    total = 1 << len(variables)
    for assignment in range(min(total, max_assignments)):
        values = {variable: bool(assignment & (1 << position)) for position, variable in enumerate(variables)}
        satisfied = True
        for equation in equations:
            args = [values[arg] for arg in equation["arguments"]]
            operator = equation["operator"]
            if operator in {"true", "false"}:
                expected = operator == "true"
            elif operator in {"identity", "not"}:
                expected = args[0] if operator == "identity" else not args[0]
            elif operator == "and":
                expected = args[0] and args[1]
            elif operator == "or":
                expected = args[0] or args[1]
            else:
                expected = args[0] != args[1]
            if values[equation["target"]] != expected:
                satisfied = False
                break
        if satisfied:
            return _facet(GraphTopologyStatus.CONSISTENT, "One assignment satisfies all simultaneous Boolean equations.",
                witness=values, assignments_checked=assignment + 1, total_assignments=total)
    status = GraphTopologyStatus.CONFLICTED if max_assignments >= total else GraphTopologyStatus.NOT_ESTABLISHED
    return _facet(status, "All assignments refuted." if status is GraphTopologyStatus.CONFLICTED else "Assignment budget exhausted without a witness.",
        witness=None, assignments_checked=min(total, max_assignments), total_assignments=total,
        equation_ids=[row["id"] for row in equations])


def _temporal(data: dict[str, Any]) -> dict[str, Any]:
    relations = data["temporal_relations"]
    if not relations:
        return _facet(GraphTopologyStatus.NOT_ESTABLISHED, "No temporal relations were supplied.")
    if len(relations) > MAX_TEMPORAL_RELATIONS or any(abs(row["offset"]) > MAX_ABS_OFFSET for row in relations):
        return _facet(GraphTopologyStatus.NOT_ESTABLISHED, "Temporal relation or offset bound exceeded.")
    clocks = []
    any_conflict = False
    for clock in sorted({row["clock_id"] for row in relations}):
        selected = [row for row in relations if row["clock_id"] == clock]
        adjacency: dict[str, list[tuple[str, int, str]]] = {}
        for row in selected:
            adjacency.setdefault(row["source"], []).append((row["target"], row["offset"], row["id"]))
            adjacency.setdefault(row["target"], []).append((row["source"], -row["offset"], row["id"]))
        potentials: dict[str, int] = {}
        parents: dict[str, tuple[str, str]] = {}
        relative_components = []
        for start in sorted(adjacency):
            if start in potentials:
                continue
            potentials[start] = 0
            pending = [start]
            component = [start]
            while pending:
                source = pending.pop()
                for target, offset, relation_id in sorted(adjacency[source]):
                    if target not in potentials:
                        potentials[target] = potentials[source] + offset
                        parents[target] = (source, relation_id)
                        pending.append(target)
                        component.append(target)
            relative_components.append({"origin_variable": start, "variable_ids": sorted(component)})
        conflicts = []
        for row in selected:
            implied = potentials[row["target"]] - potentials[row["source"]]
            if implied != row["offset"]:
                supporting = set()
                for endpoint in (row["source"], row["target"]):
                    while endpoint in parents:
                        endpoint, relation_id = parents[endpoint]
                        supporting.add(relation_id)
                conflicts.append({"relation_id": row["id"], "source": row["source"], "target": row["target"],
                    "declared_offset": row["offset"], "implied_offset": implied,
                    "supporting_relation_ids": sorted(supporting)})
        any_conflict |= bool(conflicts)
        clocks.append({"clock_id": clock, "unit": selected[0]["unit"],
            "status": (GraphTopologyStatus.CONFLICTED if conflicts else GraphTopologyStatus.CONSISTENT).value,
            "spanning_tree_potentials": dict(sorted(potentials.items())),
            "relative_components": relative_components,
            "origin_scope": "Each component has an arbitrary zero origin; no between-component offset is established.",
            "conflicts": conflicts})
    return _facet(GraphTopologyStatus.CONFLICTED if any_conflict else GraphTopologyStatus.CONSISTENT,
        "Exact relative-offset equations checked separately per clock; no physical retrocausation is established.", clocks=clocks)


def analyze_graph_topology(
    graph: ProvenanceHypergraph,
    contract: GraphTopologyContract,
    *,
    max_assignments: int = MAX_ASSIGNMENTS,
) -> GraphTopologyReport:
    """Analyze exact bound incidence and simultaneous/temporal equations separately.

    Temporal equality is time(target) = time(source) + offset. Clock components
    choose arbitrary zero origins; clocks and units never undergo implicit conversion.
    Unsupported or omitted semantics remain NOT_ESTABLISHED, even if topology exists.
    """
    if type(max_assignments) is not int or not 1 <= max_assignments <= MAX_ASSIGNMENTS:
        raise GraphTopologyError("max_assignments must be an integer in 1..4096")
    if not isinstance(contract, GraphTopologyContract):
        raise GraphTopologyError("contract must be a GraphTopologyContract")
    try:
        data = GraphTopologyContract.from_dict(contract.to_dict()).to_dict()
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise GraphTopologyError("malformed topology contract") from exc
    limits = {name: value for name, value in globals().items() if name.startswith("MAX_")}
    limits["max_assignments"] = max_assignments
    sources = {"verifier.interoperability.graph_topology": Path(__file__),
               "verifier.data.models": Path(_models.__file__)}
    report: dict[str, Any] = {"schema_version": GRAPH_TOPOLOGY_REPORT_SCHEMA_VERSION,
        "graph_digest": None, "expected_graph_digest": data["graph_digest"],
        "contract_digest": _digest(_json_bytes(data)), "limits": limits,
        "checker_coordinate": {}, "verification_effect": "NONE", "findings": [],
        "paradox_candidates": data["paradox_candidates"]}

    def finish(status: GraphTopologyStatus, detail: str) -> GraphTopologyReport:
        report["findings"].append(detail)
        for field in ("structural", "boolean_consistency", "temporal_consistency"):
            report[field] = _facet(status, detail)
        return GraphTopologyReport(_json_bytes(report))

    try:
        source_digests = {name: _digest(path.read_bytes()) for name, path in sources.items()}
        report["checker_coordinate"] = {"mechanism_id": "mechanism:graph-topology-analysis",
            "implementation_ref": "verifier.interoperability.graph_topology:analyze_graph_topology",
            "coordinate_kind": "LOCAL_SOURCE_BYTES_NOT_RUNTIME_ATTESTATION",
            "source_digests": source_digests, "canonical_digest": _digest(_json_bytes(source_digests))}
    except OSError:
        return finish(GraphTopologyStatus.NOT_ESTABLISHED, "Checker source bytes are unavailable.")
    try:
        payload, graph_bytes = _snapshot(graph)
        report["graph_digest"] = _digest(graph_bytes)
        if report["graph_digest"] != data["graph_digest"]:
            return finish(GraphTopologyStatus.INVALID, "Exact graph digest mismatch.")
        snapshot = ProvenanceHypergraph.from_dict(payload, allow_legacy_identifier_overlap=False)
        errors = snapshot.validate_structure()
        if errors:
            return finish(GraphTopologyStatus.INVALID, "Invalid recorded graph structure: " + "; ".join(errors))
        if len(data["bindings"]) > MAX_BINDINGS or len(data["paradox_candidates"]) > MAX_PARADOX_CANDIDATES:
            return finish(GraphTopologyStatus.NOT_ESTABLISHED, "Contract binding or candidate bound exceeded.")
        for row in data["bindings"]:
            transform = snapshot.transformations.get(row["transformation_id"])
            if row["artifact_id"] not in snapshot.artifacts or transform is None:
                return finish(GraphTopologyStatus.INVALID, "Binding references a missing artifact or transformation.")
            ports = transform.inputs if row["port_direction"] == "input" else transform.outputs
            matches = sum(port.artifact_id == row["artifact_id"] and port.role == row["role"] for port in ports)
            if matches != 1:
                return finish(GraphTopologyStatus.INVALID, "Binding must identify exactly one existing direction/role/artifact port.")
        report["structural"] = _structure(snapshot)
        report["boolean_consistency"] = _boolean(data, max_assignments)
        report["temporal_consistency"] = _temporal(data)
        return GraphTopologyReport(_json_bytes(report))
    except _Limit as exc:
        return finish(GraphTopologyStatus.NOT_ESTABLISHED, str(exc))
    except (AttributeError, TypeError, KeyError, ValueError, RecursionError) as exc:
        return finish(GraphTopologyStatus.INVALID, "Malformed source graph: " + type(exc).__name__)


__all__ = ["GRAPH_TOPOLOGY_SCHEMA_VERSION", "GRAPH_TOPOLOGY_REPORT_SCHEMA_VERSION",
    "SUPPORTED_CONSTRAINT_LOGIC", "GraphTopologyContract", "GraphTopologyReport",
    "GraphTopologyError", "GraphTopologyStatus", "graph_topology_binding_digest",
    "analyze_graph_topology"]
