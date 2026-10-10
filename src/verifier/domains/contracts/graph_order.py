"""Current GRAPH-2.1: least topological order of one retained directed graph.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Node and edge counts and checking budgets are
dimensionless; byte ceilings count encoded bytes. This check concerns declared
edges only, not temporal, causal or lineage truth or the legacy Graph axis.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import heapq
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (BoundProposition, EvidenceBounds,
    EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import graph_statics, retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "GRAPH-2.1"
REQUEST_VERSION = "verifier-current-graph-order-request-1"
POLICY_VERSION = "verifier-current-graph-order-policy-1"
CERTIFICATE_VERSION = "verifier-current-graph-order-certificate-1"
EVIDENCE_VERSION = "verifier-current-graph-order-evidence-1"
MECHANISM_ID = "verifier.current-graph.least-topological-order.1"
SCOPE = "finite_retained_directed_graph_least_topological_order"
_CEILINGS = {"max_operations": 2_000_000, "max_items": 4096,
             "max_nodes": 256, "max_edges": 4096,
             "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024


class GraphOrderError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "GRAPH", "scope": SCOPE,
        "proposition": (
            "The independently selected exact GRAPH-3.1 child replays PASS "
            "for the same GRAPH subject and collection; the retained declared "
            "order rehashes to the externally selected order digest; it names "
            "every retained node exactly once; it places every retained edge "
            "source before its target; and it equals the lexicographically "
            "least such order under Unicode code point comparison of node "
            "identifiers, which the verifier computes itself."),
        "prerequisites": [
            "exact separately selected GRAPH-3.1 request, policy and retained "
            "certificate; child replay PASS; externally selected order "
            "digest; finite checker limits"],
        "exclusions": [
            "legacy Graph-axis GRAPH-2.1 member rating re-execution or legacy Graph-profile conformance",
            "undeclared edges, or temporal, causal, provenance or lineage truth of declared edges",
            "any other topological order, schedule optimality or actual execution of the order",
            "whole GRAPH dynamics tier or object-profile conformance",
            "privacy, consent, governance, security, spending or publication"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class GraphOrderDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, GraphOrderError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, GraphOrderError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, retained_selection, graph_statics)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_GRAPH_STATICS.md",
                 "CURRENT_GRAPH_ORDER.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=GraphOrderError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def graph_order_policy(*, trust_roots: list[str],
        max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION,
        "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(),
        "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _request(value: Any) -> dict[str, Any]:
    selected = _record(value, {"schema_version", "semantic_version",
        "coordinate", "proposition_digest", "object_kind", "subject_id",
        "object_digest", "collection_digest",
        "child_request_digest", "child_policy_digest",
        "child_certificate_digest", "order_digest", "evidence_ref",
        "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST),
                            ("object_kind", "GRAPH")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise GraphOrderError("selected GRAPH order objective differs")
    if (type(selected["subject_id"]) is not str
            or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise GraphOrderError("bounded GRAPH subject required")
    for field in ("object_digest", "collection_digest",
                  "child_request_digest", "child_policy_digest",
                  "child_certificate_digest", "order_digest",
                  "evidence_ref", "policy_digest"):
        _digest(selected[field])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, GraphOrderError)
    return selected


def graph_order_request(*, subject_id: str, object_digest: str,
        collection_digest: str, child_request_digest: str,
        child_policy_digest: str, child_certificate_digest: str,
        order_digest: str, evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise GraphOrderError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "GRAPH",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "child_request_digest": child_request_digest,
        "child_policy_digest": child_policy_digest,
        "child_certificate_digest": child_certificate_digest,
        "order_digest": order_digest, "evidence_ref": evidence_ref,
        "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}})


def _decode_b64(value: Any, label: str) -> bytes:
    if type(value) is not str:
        raise Refuted(label + " must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise Refuted(label + " is invalid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise Refuted(label + " is noncanonical base64")
    return decoded


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


def _child_graph(value: dict[str, Any], request: dict[str, Any]) -> tuple[list[str], list[dict[str, str]]]:
    """Replay the selected GRAPH-3.1 child and return its checked arrays."""
    child_request, child_policy = value["child_request"], value["child_policy"]
    if ("sha256:" + canonical_digest(child_request) != request["child_request_digest"]
            or "sha256:" + canonical_digest(child_policy) != request["child_policy_digest"]):
        raise Refuted("selected child request or policy differs")
    if (type(child_request) is not dict
            or child_request.get("subject_id") != request["subject_id"]
            or child_request.get("object_digest") != request["object_digest"]
            or child_request.get("collection_digest") != request["collection_digest"]
            or child_request.get("semantic_version") != graph_statics.SEMANTIC_VERSION
            or child_request.get("coordinate") != graph_statics.COORDINATE
            or child_request.get("object_kind") != "GRAPH"):
        raise Refuted("child is not the selected GRAPH-3.1 subject")
    child_certificate = _decode_b64(value["child_certificate"], "child certificate")
    if len(child_certificate) > graph_statics._MAX_CERTIFICATE_BYTES:
        raise Unavailable("child certificate bound exhausted")
    if ("sha256:" + hashlib.sha256(child_certificate).hexdigest()
            != request["child_certificate_digest"]):
        raise Refuted("selected child certificate differs")
    try:
        child_result = graph_statics.recheck_graph_statics_certificate(
            child_certificate, expected_request=child_request, policy=child_policy)
    except graph_statics.GraphStaticsError as exc:
        raise Refuted("selected GRAPH-3.1 child does not replay") from exc
    if child_result["status"] == "UNKNOWN":
        raise Unavailable("selected GRAPH-3.1 child remains UNKNOWN")
    if child_result["status"] != "PASS":
        raise Refuted("selected GRAPH-3.1 child did not pass")
    child = strict_json_loads(child_certificate.decode("utf-8"))
    child_data = _decode_b64(child["evidence_payloads"][child_request["evidence_ref"]],
                             "child retained evidence")
    inputs = strict_json_loads(child_data.decode("utf-8"))["inputs"]
    return inputs["nodes"], inputs["edges"]


def _declared_order(order: Any, nodes: list[str],
                    budget: common_module.Budget) -> list[str]:
    """Admit one array naming every retained node exactly once."""
    if type(order) is not list or any(type(item) is not str for item in order):
        raise Refuted("declared order must be an array of node identifiers")
    budget.tick(len(order) + 1)
    members = set(nodes)
    if any(item not in members for item in order):
        raise Refuted("declared order names a node outside the selected GRAPH members")
    if len(set(order)) != len(order):
        raise Refuted("declared order repeats a node")
    if len(order) != len(nodes):
        raise Refuted("declared order omits a retained node")
    return order


def _least_order(nodes: list[str], edges: list[dict[str, str]],
                 budget: common_module.Budget) -> list[str]:
    """Kahn's algorithm, always removing the least available identifier."""
    indegree = {node: 0 for node in nodes}
    successors: dict[str, list[str]] = {node: [] for node in nodes}
    for edge in edges:
        successors[edge["source"]].append(edge["target"])
        indegree[edge["target"]] += 1
        budget.tick()
    ready = [node for node in nodes if indegree[node] == 0]
    heapq.heapify(ready)
    budget.tick(len(nodes))
    order = []
    while ready:
        node = heapq.heappop(ready)
        budget.tick()
        order.append(node)
        for target in successors[node]:
            budget.tick()
            indegree[target] -= 1
            if indegree[target] == 0:
                heapq.heappush(ready, target)
    if len(order) != len(nodes):
        # The child already refuses cycles; keep the order check self-contained.
        raise Refuted("retained edges admit no topological order")
    return order


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "child_request", "child_policy",
                         "child_certificate", "order"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained order evidence differs")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        nodes, edges = _child_graph(value, request)
        if len(nodes) > limits["max_nodes"] or len(edges) > limits["max_edges"]:
            raise Unavailable("selected graph node or edge bound exhausted")
        if "sha256:" + canonical_digest(value["order"]) != request["order_digest"]:
            raise Refuted("retained order differs from the selected order digest")
        declared = _declared_order(value["order"], nodes, budget)
        position = {node: index for index, node in enumerate(declared)}
        for edge in edges:
            budget.tick()
            if position[edge["source"]] > position[edge["target"]]:
                raise Refuted("declared order places " + edge["target"]
                              + " before its retained predecessor " + edge["source"])
        least = _least_order(nodes, edges, budget)
        for index, (claimed, actual) in enumerate(zip(declared, least)):
            budget.tick()
            if claimed != actual:
                raise Refuted("declared topological order is not the least: position "
                              + str(index) + " names " + claimed + " where "
                              + actual + " is available")
        return MechanismDecision(MechanismOutcome.PASS,
            "selected retained GRAPH least topological order reproduced",
            {"graph": {"nodes_digest": "sha256:" + canonical_digest(nodes),
                       "edges_digest": "sha256:" + canonical_digest(edges),
                       "node_count": len(nodes), "edge_count": len(edges)},
             "order_digest": request["order_digest"],
             "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _GraphOrderMechanism:
    mechanism_id = MECHANISM_ID

    def __init__(self, request: dict[str, Any], policy: dict[str, Any]) -> None:
        self.request, self.policy = request, policy
        self.mechanism_digest = policy["mechanism_digest"]

    def evaluate(self, binding: BoundProposition,
                 evidence: Sequence[bytes]) -> MechanismDecision:
        if (binding.subject_id != self.request["subject_id"]
                or binding.predicate != COORDINATE or binding.expected is not True
                or dict(binding.parameters) != _parameters(self.request)
                or tuple(binding.trust_roots) != tuple(self.policy["trust_roots"])):
            return MechanismDecision(MechanismOutcome.FAIL,
                                     "bound GRAPH order proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected order bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise GraphOrderError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_GraphOrderMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "GRAPH", "scope": SCOPE,
        "least_topological_order": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"),
        "temporal_or_lineage_truth": "NOT_ESTABLISHED",
        "graph_dynamics_tier_conformance": "NOT_ESTABLISHED",
        "legacy_graph_profile_conformance": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"],
        "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST,
        "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs),
        "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise GraphOrderError("certificate byte bound exhausted")
    return encoded


def build_graph_order_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise GraphOrderError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise GraphOrderError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_graph_order_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise GraphOrderError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise GraphOrderError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise GraphOrderError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise GraphOrderError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, GraphOrderError):
            raise
        raise GraphOrderError("invalid retained GRAPH order certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "GraphOrderDescriptor",
           "GraphOrderError", "registration", "graph_order_policy",
           "graph_order_request", "build_graph_order_certificate",
           "recheck_graph_order_certificate"]
