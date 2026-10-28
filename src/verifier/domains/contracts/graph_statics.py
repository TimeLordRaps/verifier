"""Versioned current GRAPH retained directed-edge statics certificate.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Node and edge counts are dimensionless; byte
ceilings count encoded bytes. This check concerns an exact retained finite
directed graph, not provenance ratings or the legacy Graph profile axis.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections import deque
import hashlib
from pathlib import Path
import re
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (
    BoundProposition, EvidenceBounds, EvidenceStore, MechanismDecision,
    MechanismOutcome, VerificationSession,
)
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "GRAPH-3.1"
REQUEST_VERSION = "verifier-current-graph-statics-request-1"
POLICY_VERSION = "verifier-current-graph-statics-policy-1"
CERTIFICATE_VERSION = "verifier-current-graph-statics-certificate-1"
EVIDENCE_VERSION = "verifier-current-graph-statics-evidence-1"
MECHANISM_ID = "verifier.current-graph.retained-edge-statics.1"
SCOPE = "finite_retained_directed_graph"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CEILINGS = {
    # The admitted Verifier package already exceeds 256 records. Keep the
    # checker finite while covering a practical repository graph without
    # slicing away nodes or edges that the GRAPH claims to represent.
    "max_objects": 4096, "max_operations": 100000,
    "max_composition_operations": 100000, "max_items": 65536,
    "max_nodes": 4096, "max_edges": 16384,
    "max_evidence_bytes": 4 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class GraphStaticsError(ValueError):
    """Malformed selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE,
        "subject_kind": "GRAPH",
        "scope": SCOPE,
        "proposition": (
            "The externally selected exact GRAPH namespace record occurs in "
            "the selected finite typed collection; the externally selected "
            "retained node and directed-edge arrays rehash exactly; nodes "
            "are exactly the GRAPH direct members; every edge endpoint "
            "resolves to those nodes; no edge repeats; and the selected "
            "finite directed graph is acyclic."
        ),
        "prerequisites": [
            "independently selected exact GRAPH record, collection, retained "
            "node and directed-edge bytes, installed policy and finite "
            "checker limits"
        ],
        "exclusions": [
            "legacy GRAPH-3.1 substrate-rating re-execution or legacy Graph-profile conformance",
            "causal, provenance, or semantic truth of declared edges",
            "undeclared edges, transitive closure or distributed network behavior",
            "whole GRAPH statics tier or object-profile conformance",
            "privacy, consent, governance and security admission",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class GraphStaticsDescriptor:
    """Native public route metadata for one retained statics proposition."""

    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if (type(value) is not dict or any(type(key) is not str for key in value)
            or set(value) != fields):
        raise GraphStaticsError(label + " fields differ")
    return dict(value)


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise GraphStaticsError("canonical SHA-256 commitment required")
    return value


def mechanism_digest() -> str:
    modules = (
        certificate_module, evidence_module, namespace_module, receipt_module,
        common_module,
    )
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_GRAPH_STATICS.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())
    })


def _policy(value: Any) -> dict[str, Any]:
    policy = _record(value, {
        "schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "max_certificate_bytes",
    }, "policy")
    if (type(policy["schema_version"]) is not str
            or type(policy["mechanism_id"]) is not str
            or policy["schema_version"] != POLICY_VERSION
            or policy["mechanism_id"] != MECHANISM_ID):
        raise GraphStaticsError("policy mechanism differs")
    if _hash(policy["mechanism_digest"]) != mechanism_digest():
        raise GraphStaticsError("policy differs from installed mechanism")
    roots = policy["trust_roots"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise GraphStaticsError("bounded sorted unique trust-root labels required")
    size = policy["max_certificate_bytes"]
    if type(size) is not int or not 1 <= size <= _MAX_CERTIFICATE_BYTES:
        raise GraphStaticsError("certificate byte bound is unsupported")
    # Own the selected list before later binding or certificate construction.
    policy["trust_roots"] = list(roots)
    return policy


def graph_statics_policy(*, trust_roots: list[str],
                              max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({
        "schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes,
    })


def _limits(value: Any) -> dict[str, int]:
    limits = _record(value, set(_CEILINGS), "limits")
    if any(type(limits[key]) is not int or not 1 <= limits[key] <= ceiling
           for key, ceiling in _CEILINGS.items()):
        raise GraphStaticsError("finite checker limit is unsupported")
    return limits


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "nodes_digest", "edges_digest", "evidence_ref", "policy_digest", "limits",
    }, "request")
    for field, expected in (
        ("schema_version", REQUEST_VERSION), ("semantic_version", SEMANTIC_VERSION),
        ("coordinate", COORDINATE), ("object_kind", "GRAPH"),
        ("proposition_digest", PROPOSITION_DIGEST),
    ):
        if type(request[field]) is not str or request[field] != expected:
            raise GraphStaticsError("selected retained statics objective differs")
    for field in ("object_digest", "collection_digest", "nodes_digest", "edges_digest", "evidence_ref", "policy_digest"):
        _hash(request[field])
    if type(request["subject_id"]) is not str or not request["subject_id"].strip() or len(request["subject_id"]) > 256:
        raise GraphStaticsError("bounded subject identifier required")
    request["limits"] = _limits(request["limits"])
    return request


def graph_statics_request(*, subject_id: str, object_digest: str,
                          collection_digest: str, nodes_digest: str,
                          edges_digest: str, evidence_ref: str,
                          policy: dict[str, Any], limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS)):
        raise GraphStaticsError("unsupported limit override")
    return _request({
        "schema_version": REQUEST_VERSION, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "proposition_digest": PROPOSITION_DIGEST,
        "object_kind": "GRAPH", "subject_id": subject_id,
        "object_digest": object_digest, "collection_digest": collection_digest,
        "nodes_digest": nodes_digest, "edges_digest": edges_digest,
        "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})},
    })


def _retained_graph(inputs: Any, selected: NamespaceObject,
                    request: dict[str, Any], budget: common_module.Budget) -> dict[str, Any]:
    retained = _record(inputs, {"nodes", "edges"}, "graph inputs")
    nodes, edges = retained["nodes"], retained["edges"]
    if type(nodes) is not list or type(edges) is not list:
        raise Refuted("retained nodes and edges must be arrays")
    if len(nodes) > request["limits"]["max_nodes"] or len(edges) > request["limits"]["max_edges"]:
        raise Unavailable("selected graph node or edge bound exhausted")
    if not nodes:
        raise Refuted("selected GRAPH has no retained nodes")
    if any(type(node) is not str or not node.strip() or len(node) > 256 for node in nodes):
        raise Refuted("bounded exact node identifiers required")
    if nodes != sorted(set(nodes)):
        raise Refuted("retained node identifiers must be sorted and unique")
    budget.tick(len(nodes))
    members = dict(selected.operands).get("members")
    if members is None or nodes != sorted(members):
        raise Refuted("retained nodes differ from selected GRAPH direct members")
    node_digest = "sha256:" + canonical_digest(nodes)
    edge_digest = "sha256:" + canonical_digest(edges)
    payload = _record(selected.payload, {
        "element_kind", "scope", "nodes_digest", "edges_digest",
    }, "graph payload")
    if payload["scope"] != "retained_directed_graph":
        raise Refuted("unsupported selected GRAPH statics scope")
    if (payload["nodes_digest"] != node_digest or request["nodes_digest"] != node_digest
            or payload["edges_digest"] != edge_digest or request["edges_digest"] != edge_digest):
        raise Refuted("retained graph arrays differ from external selection or GRAPH commitments")
    adjacency: dict[str, list[str]] = {node: [] for node in nodes}
    indegree: dict[str, int] = {node: 0 for node in nodes}
    previous: tuple[str, str] | None = None
    for row in edges:
        edge = _record(row, {"source", "target"}, "directed edge")
        source, target = edge["source"], edge["target"]
        if type(source) is not str or type(target) is not str or source not in adjacency or target not in adjacency:
            raise Refuted("directed edge has dangling or invalid endpoint")
        pair = (source, target)
        if previous is not None and pair <= previous:
            raise Refuted("directed edges must be sorted and unique")
        previous = pair
        adjacency[source].append(target)
        indegree[target] += 1
        budget.tick()
    ready = deque(node for node in nodes if indegree[node] == 0)
    visited = 0
    while ready:
        node = ready.popleft()
        visited += 1
        budget.tick()
        for target in adjacency[node]:
            indegree[target] -= 1
            budget.tick()
            if indegree[target] == 0:
                ready.append(target)
    if visited != len(nodes):
        raise Refuted("retained directed graph contains a cycle")
    return {
        "nodes_digest": node_digest, "edges_digest": edge_digest,
        "node_count": len(nodes), "edge_count": len(edges),
    }


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        raw = strict_json_loads(data.decode("utf-8"))
        if type(raw) is dict and set(raw) == {"schema_version", "objects"}:
            if raw["schema_version"] != EVIDENCE_VERSION or canonical_bytes(raw) != data:
                raise Refuted("retained evidence version or canonical bytes differ")
            raise Unavailable("retained graph inputs absent")
        value = _record(raw, {"schema_version", "objects", "inputs"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained evidence version or canonical bytes differ")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        rows = value["objects"]
        if type(rows) is not list:
            raise Refuted("retained collection requires records")
        if len(rows) > limits["max_objects"]:
            raise Unavailable("selected object bound exhausted")
        objects = []
        for row in rows:
            selected = _record(row, {"object_id", "kind", "payload", "operands"}, "namespace record")
            item = NamespaceObject.create(**selected)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        matches = [obj for obj in objects if obj.object_id == request["subject_id"]]
        if len(matches) != 1 or matches[0].kind.value != "GRAPH" or matches[0].digest != request["object_digest"]:
            raise Refuted("retained graph subject differs from external selection")
        composition = namespace_module.assess_composition(
            objects, expected_digest=request["collection_digest"],
            max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"],
        )
        if composition.verdict.value != "PASS":
            return MechanismDecision(MechanismOutcome(composition.verdict.value), composition.reason)
        if value["inputs"] is None:
            raise Unavailable("retained node or edge evidence absent")
        if (type(value["inputs"]) is dict
                and set(value["inputs"]) < {"nodes", "edges"}):
            raise Unavailable("retained node or edge evidence absent")
        result = _retained_graph(value["inputs"], matches[0], request, budget)
        return MechanismDecision(
            MechanismOutcome.PASS, "selected retained GRAPH directed-edge statics reproduced",
            {"graph": result, "operations": budget.used},
        )
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {
        **{key: request[key] for key in (
            "semantic_version", "proposition_digest", "object_kind",
            "object_digest", "collection_digest", "nodes_digest", "edges_digest",
            "policy_digest",
        )},
        "limits_digest": "sha256:" + canonical_digest(request["limits"]),
    }


class _GraphStaticsMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition, evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL, "bound graph proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained graph evidence bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise GraphStaticsError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request),
    )
    session = VerificationSession(store)
    session.register(_GraphStaticsMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {
        "status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "GRAPH", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "graph_statics_tier_conformance": "NOT_ESTABLISHED",
        "legacy_graph_profile_conformance": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict(),
    }
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {
        "schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs),
        "result": result,
    }
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise GraphStaticsError("certificate byte bound exhausted")
    return encoded


def build_graph_statics_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                         *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise GraphStaticsError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise GraphStaticsError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_graph_statics_certificate(certificate_bytes: bytes, *,
                                           expected_request: dict[str, Any],
                                           policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise GraphStaticsError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads",
            "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise GraphStaticsError("canonical certificate version differs")
        if value["request"] != selected:
            raise GraphStaticsError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise GraphStaticsError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise GraphStaticsError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
        if isinstance(exc, GraphStaticsError):
            raise
        raise GraphStaticsError("invalid retained graph certificate") from exc


__all__ = [
    "SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
    "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "GraphStaticsDescriptor",
    "GraphStaticsError", "registration", "graph_statics_policy",
    "graph_statics_request", "build_graph_statics_certificate",
    "recheck_graph_statics_certificate",
]
