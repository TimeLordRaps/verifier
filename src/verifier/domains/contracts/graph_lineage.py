"""GRAPH-9.2: selected direct operand lineage and endpoint-content binding.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Identifiers, digests and operation/item counts
are dimensionless; encoded evidence and certificate limits count bytes.
This finite retained comparison establishes neither real-world lineage nor
authority, enforcement, transitive closure or a complete security tier.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Sequence

from verifier.core import certificate as certificate_module
from verifier.core import evidence as evidence_module
from verifier.core import namespace as namespace_module
from verifier.core import receipt as receipt_module
from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (BoundProposition, EvidenceBounds, EvidenceStore,
    MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.namespace import NamespaceObject
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import graph_statics, retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "GRAPH-9.2"
REQUEST_VERSION = "verifier-current-graph-lineage-request-1"
POLICY_VERSION = "verifier-current-graph-lineage-policy-1"
CERTIFICATE_VERSION = "verifier-current-graph-lineage-certificate-1"
EVIDENCE_VERSION = "verifier-current-graph-lineage-evidence-1"
MECHANISM_ID = "verifier.current-graph.direct-operand-content-lineage.1"
SCOPE = "finite_selected_direct_operand_content_lineage"
_CEILINGS = {
    "max_operations": 2_000_000, "max_items": 4096, "max_objects": 256,
    "max_composition_operations": 100000, "max_nodes": 256, "max_edges": 4096,
    "max_evidence_bytes": 8 * 1024 * 1024,
    "max_reference_bytes": 4 * 1024 * 1024,
    "max_payload_bytes": 4 * 1024 * 1024,
    "max_child_certificate_bytes": 8 * 1024 * 1024,
}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024
_CAUGHT = (ValueError, TypeError, KeyError, IndexError, UnicodeError,
           RecursionError, OverflowError, AttributeError)


class GraphLineageError(ValueError):
    """Malformed external selection, unsupported policy or substituted certificate."""


def registration() -> dict[str, Any]:
    return {
        "schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "GRAPH", "scope": SCOPE,
        "proposition": (
            "For the exact externally selected GRAPH and complete canonical "
            "collection, the selected directed edge set equals the direct named-operand "
            "target relation induced among its declared direct member identifiers; "
            "every selected edge endpoint content commitment equals its canonical "
            "record digest; and the separately selected GRAPH-3.1 certificate replays "
            "PASS for that same subject, collection and retained node and edge arrays."
        ),
        "prerequisites": [
            "externally selected exact GRAPH record, complete collection, node and "
            "edge arrays, endpoint-content manifest, finite limits and policy",
            "separately selected exact GRAPH-3.1 request, policy and raw certificate",
        ],
        "exclusions": [
            "real-world, causal or historical lineage truth and record-maker authenticity",
            "transitive edges, recursive member expansion and references outside direct nodes",
            "generic GRAPH-9.1 receipt inclusion, actual execution, enforcement or authority",
            "whole GRAPH security tier or object profile, privacy, consent or governance",
        ],
    }


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class GraphLineageDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, GraphLineageError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, GraphLineageError)


def _identifier(value: Any) -> bool:
    return type(value) is str and bool(value.strip()) and len(value) <= 256


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, retained_selection, graph_statics)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_GRAPH_STATICS.md",
                 "CURRENT_GRAPH_LINEAGE.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=GraphLineageError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest, max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def graph_lineage_policy(*, trust_roots: list[str],
                         max_certificate_bytes: int = _MAX_CERTIFICATE_BYTES
                         ) -> dict[str, Any]:
    return _policy({"schema_version": POLICY_VERSION, "mechanism_id": MECHANISM_ID,
        "mechanism_digest": mechanism_digest(), "trust_roots": trust_roots,
        "max_certificate_bytes": max_certificate_bytes})


def _child_selection(request: Any, policy: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    # Native selection validation captures plain fields and its own limit/root lists.
    try:
        selected_policy = graph_statics._policy(policy)
        selected_request = graph_statics._request(request)
    except _CAUGHT as exc:
        raise GraphLineageError("invalid selected GRAPH-3.1 prerequisite") from exc
    if selected_request["policy_digest"] != "sha256:" + canonical_digest(selected_policy):
        raise GraphLineageError("selected child policy differs from child request")
    return selected_request, selected_policy


def _request(value: Any) -> dict[str, Any]:
    request = _record(value, {
        "schema_version", "semantic_version", "coordinate", "proposition_digest",
        "object_kind", "subject_id", "object_digest", "collection_digest",
        "nodes_digest", "edges_digest", "edge_contents_digest", "evidence_ref",
        "policy_digest", "limits", "child_request", "child_policy",
        "child_certificate_digest",
    }, "request")
    for key, expected in (("schema_version", REQUEST_VERSION),
            ("semantic_version", SEMANTIC_VERSION), ("coordinate", COORDINATE),
            ("proposition_digest", PROPOSITION_DIGEST), ("object_kind", "GRAPH")):
        if type(request[key]) is not str or request[key] != expected:
            raise GraphLineageError("selected direct lineage objective differs")
    if not _identifier(request["subject_id"]):
        raise GraphLineageError("bounded exact subject identifier required")
    for key in ("object_digest", "collection_digest", "nodes_digest", "edges_digest",
                "edge_contents_digest", "evidence_ref", "policy_digest",
                "child_certificate_digest"):
        _digest(request[key])
    request["limits"] = retained_selection.limits(request["limits"], _CEILINGS,
                                                   GraphLineageError)
    child_request, child_policy = _child_selection(request["child_request"],
                                                  request["child_policy"])
    for key in ("subject_id", "object_digest", "collection_digest", "nodes_digest",
                "edges_digest"):
        if child_request[key] != request[key]:
            raise GraphLineageError("selected child belongs to another graph or retained arrays")
    request["child_request"], request["child_policy"] = child_request, child_policy
    return request


def graph_lineage_request(*, subject_id: str, object_digest: str,
                         collection_digest: str, nodes_digest: str,
                         edges_digest: str, edge_contents_digest: str,
                         evidence_ref: str, child_request: dict[str, Any],
                         child_policy: dict[str, Any], child_certificate_digest: str,
                         policy: dict[str, Any], limits: dict[str, int] | None = None
                         ) -> dict[str, Any]:
    admitted = _policy(policy)
    if limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits) or set(limits) - set(_CEILINGS)):
        raise GraphLineageError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "GRAPH",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest, "nodes_digest": nodes_digest,
        "edges_digest": edges_digest, "edge_contents_digest": edge_contents_digest,
        "evidence_ref": evidence_ref, "policy_digest": "sha256:" + canonical_digest(admitted),
        "limits": {**_CEILINGS, **(limits or {})}, "child_request": child_request,
        "child_policy": child_policy, "child_certificate_digest": child_certificate_digest})


def _child_status(value: Any, request: dict[str, Any], failures: set[str],
                  unknowns: set[str]) -> str:
    if value is None:
        unknowns.add("selected GRAPH-3.1 certificate is absent")
        return "ABSENT"
    if type(value) is not str or not value:
        failures.add("present child certificate must be nonempty canonical base64")
        return "REJECTED"
    limit = min(request["limits"]["max_child_certificate_bytes"],
                request["child_policy"]["max_certificate_bytes"])
    if len(value) > 4 * ((limit + 2) // 3):
        unknowns.add("selected child certificate byte bound exhausted")
        return "UNKNOWN"
    try:
        certificate = base64.b64decode(value, validate=True)
        if not certificate or base64.b64encode(certificate).decode("ascii") != value:
            raise Refuted("noncanonical child certificate encoding")
        if len(certificate) > limit:
            unknowns.add("selected child certificate byte bound exhausted")
            return "UNKNOWN"
        if "sha256:" + hashlib.sha256(certificate).hexdigest() != request["child_certificate_digest"]:
            raise Refuted("child certificate differs from external selection")
        result = graph_statics.recheck_graph_statics_certificate(certificate,
            expected_request=request["child_request"], policy=request["child_policy"])
        status = result["status"]
        if status not in ("PASS", "FAIL", "UNKNOWN"):
            raise Refuted("unsupported native child status")
    except _CAUGHT as exc:
        failures.add("selected GRAPH-3.1 child does not replay: " + str(exc))
        return "REJECTED"
    if status == "FAIL":
        failures.add("selected GRAPH-3.1 child replays FAIL")
    elif status == "UNKNOWN":
        unknowns.add("selected GRAPH-3.1 child remains UNKNOWN")
    return status


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    failures: set[str] = set()
    unknowns: set[str] = set()
    observations: dict[str, Any] = {}
    budget = common_module.Budget(limits["max_operations"], limits["max_items"])
    try:
        value = _record(strict_json_loads(data.decode("utf-8")), {
            "schema_version", "objects", "inputs", "edge_contents", "child_certificate",
        }, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained lineage evidence version or canonical bytes differ")
        common_module.inspect_structure(value, budget)
        rows = value["objects"]
        if type(rows) is not list:
            raise Refuted("complete collection requires records")
        if len(rows) > limits["max_objects"]:
            raise Unavailable("selected object bound exhausted")
        objects = []
        for row in rows:
            budget.tick()
            record = _record(row, {"object_id", "kind", "payload", "operands"}, "namespace record")
            item = NamespaceObject.create(**record)
            if canonical_bytes(item.to_dict()) != canonical_bytes(row):
                raise Refuted("namespace record does not reconstruct exactly")
            objects.append(item)
        index = {item.object_id: item for item in objects}
        selected = index.get(request["subject_id"])
        if (len(index) != len(objects) or selected is None or selected.kind.value != "GRAPH"
                or selected.digest != request["object_digest"]):
            raise Refuted("selected graph or unique collection differs")
        composition = namespace_module.assess_composition(objects,
            expected_digest=request["collection_digest"], max_objects=limits["max_objects"],
            max_operations=limits["max_composition_operations"],
            max_payload_bytes=limits["max_payload_bytes"],
            max_reference_bytes=limits["max_reference_bytes"])
        if composition.verdict.value == "UNKNOWN":
            raise Unavailable(composition.reason)
        if composition.verdict.value != "PASS":
            raise Refuted(composition.reason)
        # After collection admission, replay this independently selected child
        # even when parent-specific arrays are absent or later refuted.
        observations.update({"required_child_count": 1,
            "child_coordinate": graph_statics.COORDINATE,
            "child_certificate_digest": request["child_certificate_digest"]})
        observations["child_status"] = _child_status(value["child_certificate"], request,
                                                      failures, unknowns)
        if value["inputs"] is None or value["edge_contents"] is None:
            raise Unavailable("selected node, edge or endpoint-content evidence is absent")
        inputs = _record(value["inputs"], {"nodes", "edges"}, "graph inputs")
        nodes, edges, contents = inputs["nodes"], inputs["edges"], value["edge_contents"]
        if type(nodes) is not list or type(edges) is not list or type(contents) is not list:
            raise Refuted("selected nodes, edges and endpoint contents require arrays")
        if len(nodes) > limits["max_nodes"] or max(len(edges), len(contents)) > limits["max_edges"]:
            raise Unavailable("selected node or edge bound exhausted")
        if not nodes or any(not _identifier(node) for node in nodes) or nodes != sorted(set(nodes)):
            raise Refuted("direct node identifiers must be nonempty, sorted and unique")
        if nodes != sorted(dict(selected.operands)["members"]):
            raise Refuted("nodes differ from the selected GRAPH direct members")
        if ("sha256:" + canonical_digest(nodes) != request["nodes_digest"]
                or "sha256:" + canonical_digest(edges) != request["edges_digest"]
                or "sha256:" + canonical_digest(contents) != request["edge_contents_digest"]):
            raise Refuted("retained graph or endpoint-content arrays differ from selection")
        # Typed composition is admitted. Derive only direct references between N.
        node_set = set(nodes)
        relation: set[tuple[str, str]] = set()
        for node in nodes:
            budget.tick()
            for _, targets in index[node].operands:
                budget.tick()
                for target in targets:
                    budget.tick()
                    if target in node_set:
                        relation.add((node, target))
        derived = sorted(relation)
        pairs = []
        for row in edges:
            budget.tick()
            edge = _record(row, {"source", "target"}, "directed edge")
            if not _identifier(edge["source"]) or not _identifier(edge["target"]):
                raise Refuted("bounded edge endpoints required")
            pair = (edge["source"], edge["target"])
            if pair[0] not in node_set or pair[1] not in node_set:
                failures.add("edge endpoint is outside the selected direct nodes")
            pairs.append(pair)
        if pairs != sorted(set(pairs)):
            failures.add("selected directed edges are not sorted and unique")
        if pairs != derived:
            failures.add("selected edges differ from the induced direct operand relation")
        content_pairs = []
        for row in contents:
            budget.tick()
            content = _record(row, {"source", "target", "source_digest", "target_digest"},
                              "edge endpoint content")
            if not _identifier(content["source"]) or not _identifier(content["target"]):
                raise Refuted("bounded content endpoint identifiers required")
            _digest(content["source_digest"])
            _digest(content["target_digest"])
            pair = (content["source"], content["target"])
            content_pairs.append(pair)
            if (pair[0] not in node_set or pair[1] not in node_set
                    or content["source_digest"] != index[pair[0]].digest
                    or content["target_digest"] != index[pair[1]].digest):
                failures.add("selected endpoint content differs from its canonical record")
        if content_pairs != pairs or content_pairs != sorted(set(content_pairs)):
            failures.add("endpoint-content manifest does not name each selected edge once")
        observations.update({"nodes": nodes,
            "derived_edges": [{"source": a, "target": b} for a, b in derived],
            "node_count": len(nodes), "edge_count": len(edges)})
        observations["operations"] = budget.used
        if failures:
            return MechanismDecision(MechanismOutcome.FAIL, "; ".join(sorted(failures)), observations)
        if unknowns:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "; ".join(sorted(unknowns)), observations)
        return MechanismDecision(MechanismOutcome.PASS,
            "selected direct operand relation and endpoint contents reproduced", observations)
    except Unavailable as exc:
        if failures:
            return MechanismDecision(MechanismOutcome.FAIL, "; ".join(sorted(failures)), observations)
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc), observations)
    except _CAUGHT as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc), observations)


def _parameters(request: dict[str, Any]) -> dict[str, str]:
    return {"request_digest": "sha256:" + canonical_digest(request)}


class _GraphLineageMechanism:
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
            return MechanismDecision(MechanismOutcome.FAIL, "bound direct lineage proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one retained lineage bundle is required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any], store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise GraphLineageError("request differs from selected policy")
    binding = BoundProposition(subject_id=request["subject_id"], predicate=COORDINATE,
        expected=True, mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],), trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_GraphLineageMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value, "semantic_version": SEMANTIC_VERSION,
        "coordinate": COORDINATE, "object_kind": "GRAPH", "scope": SCOPE,
        "object_profile_conformance": "NOT_ESTABLISHED",
        "graph_security_tier_conformance": "NOT_ESTABLISHED",
        "legacy_graph_profile_conformance": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED", "evaluation": evaluation.to_dict()}
    refs = [request["evidence_ref"]] if request["evidence_ref"] in store else []
    envelope = {"schema_version": CERTIFICATE_VERSION, "request": request,
        "policy_digest": request["policy_digest"], "mechanism_digest": policy["mechanism_digest"],
        "proposition_digest": PROPOSITION_DIGEST, "evidence_refs": [request["evidence_ref"]],
        "evidence_payloads": store.export_base64(refs), "result": result}
    envelope["digest"] = "sha256:" + canonical_digest(envelope)
    encoded = canonical_bytes(envelope)
    if len(encoded) > policy["max_certificate_bytes"]:
        raise GraphLineageError("certificate byte bound exhausted")
    return encoded


def build_graph_lineage_certificate(request: dict[str, Any], evidence_bytes: bytes | None,
                                    *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if type(evidence_bytes) is not bytes or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]:
            raise GraphLineageError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise GraphLineageError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_graph_lineage_certificate(certificate_bytes: bytes, *,
                                     expected_request: dict[str, Any],
                                     policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if type(certificate_bytes) is not bytes or len(certificate_bytes) > admitted["max_certificate_bytes"]:
        raise GraphLineageError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")), {
            "schema_version", "request", "policy_digest", "mechanism_digest",
            "proposition_digest", "evidence_refs", "evidence_payloads", "result", "digest",
        }, "certificate")
        if canonical_bytes(value) != certificate_bytes or value["schema_version"] != CERTIFICATE_VERSION:
            raise GraphLineageError("canonical certificate version differs")
        if value["request"] != selected:
            raise GraphLineageError("certificate differs from selected request")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise GraphLineageError("retained lineage evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise GraphLineageError("lineage certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except _CAUGHT as exc:
        if isinstance(exc, GraphLineageError):
            raise
        raise GraphLineageError("invalid retained lineage certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION", "EVIDENCE_VERSION",
    "PROPOSITION_DIGEST", "GraphLineageDescriptor", "GraphLineageError", "registration",
    "mechanism_digest", "graph_lineage_policy", "graph_lineage_request",
    "build_graph_lineage_certificate", "recheck_graph_lineage_certificate"]
