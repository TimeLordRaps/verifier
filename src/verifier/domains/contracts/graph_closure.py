"""Current GRAPH-4.1: exact reachability closure of one retained directed graph.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Node, edge and closure-pair counts and checking
budgets are dimensionless; byte ceilings count encoded bytes. This check
concerns declared edges only, not lineage truth or the legacy Graph axis.
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
from verifier.core.evidence import (BoundProposition, EvidenceBounds,
    EvidenceStore, MechanismDecision, MechanismOutcome, VerificationSession)
from verifier.core.receipt import strict_json_loads
from verifier.domains import common as common_module
from verifier.domains.common import Refuted, Unavailable
from verifier.domains.contracts import graph_statics, retained_selection


SEMANTIC_VERSION = "verifier-current-object-obligations-1"
COORDINATE = "GRAPH-4.1"
REQUEST_VERSION = "verifier-current-graph-closure-request-1"
POLICY_VERSION = "verifier-current-graph-closure-policy-1"
CERTIFICATE_VERSION = "verifier-current-graph-closure-certificate-1"
EVIDENCE_VERSION = "verifier-current-graph-closure-evidence-1"
MECHANISM_ID = "verifier.current-graph.retained-reachability-closure.1"
SCOPE = "finite_retained_directed_graph_reachability_closure"
# An acyclic graph on the child's 256-node ceiling has at most 256*255/2 pairs.
_CEILINGS = {"max_operations": 2_000_000, "max_items": 4096,
             "max_nodes": 256, "max_edges": 4096, "max_closure_pairs": 32640,
             "max_evidence_bytes": 8 * 1024 * 1024}
_MAX_CERTIFICATE_BYTES = 16 * 1024 * 1024


class GraphClosureError(ValueError):
    """Malformed selection, unsupported policy, or substituted certificate."""


def registration() -> dict[str, Any]:
    return {"schema_version": "verifier-current-object-proposition-1",
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "subject_kind": "GRAPH", "scope": SCOPE,
        "proposition": (
            "The independently selected exact GRAPH-3.1 child replays PASS "
            "for the same GRAPH subject and collection; the retained declared "
            "closure rehashes to the externally selected closure digest; it "
            "has exactly one row per retained node in node order, each "
            "naming only sorted unique selected members; and every row "
            "equals the set of nodes the verifier reaches from that node by "
            "one or more retained directed edges."),
        "prerequisites": [
            "exact separately selected GRAPH-3.1 request, policy and retained "
            "certificate; child replay PASS; externally selected closure "
            "digest; finite checker limits"],
        "exclusions": [
            "legacy Graph-axis GRAPH-4.1 member refutability entry or legacy Graph-profile conformance",
            "undeclared edges, or causal, provenance or lineage truth of declared edges",
            "submitted per-pair path witnesses; traversal is the verifier's own bounded replay",
            "whole GRAPH closure tier or object-profile conformance",
            "privacy, consent, governance, security, spending or publication"]}


PROPOSITION_DIGEST = "sha256:" + canonical_digest(registration())


@dataclass(frozen=True)
class GraphClosureDescriptor:
    CERTIFICATE_VERSION = CERTIFICATE_VERSION
    PROPOSITION_DIGEST = PROPOSITION_DIGEST


def _record(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    return retained_selection.record(value, fields, label, GraphClosureError)


def _digest(value: Any) -> str:
    return retained_selection.commitment(value, GraphClosureError)


def mechanism_digest() -> str:
    modules = (certificate_module, evidence_module, namespace_module,
               receipt_module, common_module, retained_selection, graph_statics)
    paths = {module.__name__: Path(module.__file__) for module in modules}
    paths[__name__] = Path(__file__)
    for name in ("NAMESPACE_OBJECTS.md", "CURRENT_GRAPH_STATICS.md",
                 "CURRENT_GRAPH_CLOSURE.md"):
        paths[name] = Path(__file__).parents[2] / "standard" / name
    return "sha256:" + canonical_digest({
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(paths.items())})


def _policy(value: Any) -> dict[str, Any]:
    return retained_selection.policy(value, error_type=GraphClosureError,
        version=POLICY_VERSION, mechanism_id=MECHANISM_ID,
        current_digest=mechanism_digest,
        max_certificate_bytes=_MAX_CERTIFICATE_BYTES)


def graph_closure_policy(*, trust_roots: list[str],
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
        "child_certificate_digest", "closure_digest", "evidence_ref",
        "policy_digest", "limits"}, "request")
    for field, expected in (("schema_version", REQUEST_VERSION),
                            ("semantic_version", SEMANTIC_VERSION),
                            ("coordinate", COORDINATE),
                            ("proposition_digest", PROPOSITION_DIGEST),
                            ("object_kind", "GRAPH")):
        if type(selected[field]) is not str or selected[field] != expected:
            raise GraphClosureError("selected GRAPH closure objective differs")
    if (type(selected["subject_id"]) is not str
            or not selected["subject_id"].strip()
            or len(selected["subject_id"]) > 256):
        raise GraphClosureError("bounded GRAPH subject required")
    for field in ("object_digest", "collection_digest",
                  "child_request_digest", "child_policy_digest",
                  "child_certificate_digest", "closure_digest",
                  "evidence_ref", "policy_digest"):
        _digest(selected[field])
    selected["limits"] = retained_selection.limits(
        selected["limits"], _CEILINGS, GraphClosureError)
    return selected


def graph_closure_request(*, subject_id: str, object_digest: str,
        collection_digest: str, child_request_digest: str,
        child_policy_digest: str, child_certificate_digest: str,
        closure_digest: str, evidence_ref: str, policy: dict[str, Any],
        limits: dict[str, int] | None = None) -> dict[str, Any]:
    admitted = _policy(policy)
    if (limits is not None and (type(limits) is not dict
            or any(type(key) is not str for key in limits)
            or set(limits) - set(_CEILINGS))):
        raise GraphClosureError("unsupported limit override")
    return _request({"schema_version": REQUEST_VERSION,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "proposition_digest": PROPOSITION_DIGEST, "object_kind": "GRAPH",
        "subject_id": subject_id, "object_digest": object_digest,
        "collection_digest": collection_digest,
        "child_request_digest": child_request_digest,
        "child_policy_digest": child_policy_digest,
        "child_certificate_digest": child_certificate_digest,
        "closure_digest": closure_digest, "evidence_ref": evidence_ref,
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


def _declared_rows(closure: Any, nodes: list[str], limits: dict[str, int],
                   budget: common_module.Budget) -> list[list[str]]:
    """Admit exactly one sorted in-boundary row per retained node."""
    if type(closure) is not list:
        raise Refuted("declared closure must be an array of node rows")
    if len(closure) != len(nodes):
        raise Refuted("declared closure rows differ from retained nodes")
    members = set(nodes)
    pairs = 0
    declared = []
    for node, row in zip(nodes, closure):
        selected = _record(row, {"node", "reachable"}, "closure row")
        reachable = selected["reachable"]
        if selected["node"] != node:
            raise Refuted("declared closure rows differ from retained node order")
        if type(reachable) is not list or any(type(item) is not str for item in reachable):
            raise Refuted("declared reachable nodes must be identifiers")
        pairs += len(reachable)
        if pairs > limits["max_closure_pairs"]:
            raise Unavailable("selected closure pair bound exhausted")
        if any(item not in members for item in reachable):
            raise Refuted("declared closure endpoint lies outside the selected GRAPH members")
        if reachable != sorted(set(reachable)):
            raise Refuted("declared reachable nodes must be sorted and unique")
        budget.tick(len(reachable) + 1)
        declared.append(reachable)
    return declared


def _reachable(nodes: list[str], edges: list[dict[str, str]],
               budget: common_module.Budget) -> list[list[str]]:
    """Bounded depth-first traversal from every node over retained edges."""
    successors: dict[str, list[str]] = {node: [] for node in nodes}
    for edge in edges:
        successors[edge["source"]].append(edge["target"])
        budget.tick()
    closure = []
    for origin in nodes:
        seen: set[str] = set()
        pending = list(successors[origin])
        while pending:
            node = pending.pop()
            budget.tick()
            if node in seen:
                continue
            seen.add(node)
            pending.extend(successors[node])
            budget.tick(len(successors[node]))
        closure.append(sorted(seen))
    return closure


def _evaluate(data: bytes, request: dict[str, Any]) -> MechanismDecision:
    limits = request["limits"]
    try:
        value = _record(strict_json_loads(data.decode("utf-8")),
                        {"schema_version", "child_request", "child_policy",
                         "child_certificate", "closure"}, "evidence")
        if value["schema_version"] != EVIDENCE_VERSION or canonical_bytes(value) != data:
            raise Refuted("retained closure evidence differs")
        budget = common_module.Budget(limits["max_operations"], limits["max_items"])
        common_module.inspect_structure(value, budget)
        nodes, edges = _child_graph(value, request)
        if len(nodes) > limits["max_nodes"] or len(edges) > limits["max_edges"]:
            raise Unavailable("selected graph node or edge bound exhausted")
        if "sha256:" + canonical_digest(value["closure"]) != request["closure_digest"]:
            raise Refuted("retained closure differs from the selected closure digest")
        declared = _declared_rows(value["closure"], nodes, limits, budget)
        computed = _reachable(nodes, edges, budget)
        for node, claimed, actual in zip(nodes, declared, computed):
            budget.tick(len(claimed) + len(actual))
            if set(claimed) - set(actual):
                raise Refuted("declared closure names a pair unreachable from " + node)
            if set(actual) - set(claimed):
                raise Refuted("declared closure omits a pair reachable from " + node)
        return MechanismDecision(MechanismOutcome.PASS,
            "selected retained GRAPH reachability closure reproduced",
            {"graph": {"nodes_digest": "sha256:" + canonical_digest(nodes),
                       "edges_digest": "sha256:" + canonical_digest(edges),
                       "node_count": len(nodes), "edge_count": len(edges)},
             "closure_digest": request["closure_digest"],
             "closure_pairs": sum(len(row) for row in computed),
             "operations": budget.used})
    except Unavailable as exc:
        return MechanismDecision(MechanismOutcome.UNKNOWN, str(exc))
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError,
            RecursionError, OverflowError, AttributeError) as exc:
        return MechanismDecision(MechanismOutcome.FAIL, str(exc))


class _GraphClosureMechanism:
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
                                     "bound GRAPH closure proposition differs")
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN,
                                     "one selected closure bundle required")
        return _evaluate(evidence[0], self.request)


def _build(request: dict[str, Any], policy: dict[str, Any],
           store: EvidenceStore) -> bytes:
    if request["policy_digest"] != "sha256:" + canonical_digest(policy):
        raise GraphClosureError("request differs from selected policy")
    binding = BoundProposition(
        subject_id=request["subject_id"], predicate=COORDINATE, expected=True,
        mechanism_id=MECHANISM_ID, mechanism_digest=policy["mechanism_digest"],
        evidence_refs=(request["evidence_ref"],),
        trust_roots=tuple(policy["trust_roots"]),
        bounds=EvidenceBounds(1, request["limits"]["max_evidence_bytes"]),
        parameters=_parameters(request))
    session = VerificationSession(store)
    session.register(_GraphClosureMechanism(request, policy))
    evaluation = session.evaluate(binding)
    result = {"status": evaluation.outcome.value,
        "semantic_version": SEMANTIC_VERSION, "coordinate": COORDINATE,
        "object_kind": "GRAPH", "scope": SCOPE,
        "reachability_closure": (
            "PASS" if evaluation.outcome == MechanismOutcome.PASS
            else "NOT_ESTABLISHED"),
        "lineage_truth": "NOT_ESTABLISHED",
        "graph_closure_tier_conformance": "NOT_ESTABLISHED",
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
        raise GraphClosureError("certificate byte bound exhausted")
    return encoded


def build_graph_closure_certificate(request: dict[str, Any],
        evidence_bytes: bytes | None, *, policy: dict[str, Any]) -> bytes:
    selected, admitted = _request(request), _policy(policy)
    store = EvidenceStore()
    if evidence_bytes is not None:
        if (type(evidence_bytes) is not bytes
                or len(evidence_bytes) > _CEILINGS["max_evidence_bytes"]):
            raise GraphClosureError("immutable bounded evidence bytes required")
        if store.add(evidence_bytes) != selected["evidence_ref"]:
            raise GraphClosureError("evidence differs from selected byte reference")
    return _build(selected, admitted, store)


def recheck_graph_closure_certificate(certificate_bytes: bytes, *,
        expected_request: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    selected, admitted = _request(expected_request), _policy(policy)
    if (type(certificate_bytes) is not bytes
            or len(certificate_bytes) > admitted["max_certificate_bytes"]):
        raise GraphClosureError("bounded immutable certificate bytes required")
    try:
        value = _record(strict_json_loads(certificate_bytes.decode("utf-8")),
            {"schema_version", "request", "policy_digest", "mechanism_digest",
             "proposition_digest", "evidence_refs", "evidence_payloads",
             "result", "digest"}, "certificate")
        if (canonical_bytes(value) != certificate_bytes
                or value["schema_version"] != CERTIFICATE_VERSION
                or value["request"] != selected):
            raise GraphClosureError("selected canonical certificate differs")
        payloads = value["evidence_payloads"]
        if (type(payloads) is not dict or len(payloads) > 1
                or set(payloads) - {selected["evidence_ref"]}
                or any(type(data) is not str for data in payloads.values())):
            raise GraphClosureError("retained evidence differs")
        store = EvidenceStore()
        store.import_base64(payloads)
        rebuilt = _build(selected, admitted, store)
        if rebuilt != certificate_bytes:
            raise GraphClosureError("certificate does not reproduce exactly")
        return strict_json_loads(rebuilt.decode("utf-8"))["result"]
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError) as exc:
        if isinstance(exc, GraphClosureError):
            raise
        raise GraphClosureError("invalid retained GRAPH closure certificate") from exc


__all__ = ["SEMANTIC_VERSION", "COORDINATE", "CERTIFICATE_VERSION",
           "EVIDENCE_VERSION", "PROPOSITION_DIGEST", "GraphClosureDescriptor",
           "GraphClosureError", "registration", "graph_closure_policy",
           "graph_closure_request", "build_graph_closure_certificate",
           "recheck_graph_closure_certificate"]
