"""Independent finite direct-relation oracle for current GRAPH-9.2.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Enumerate all64 directed edge sets without
self-edges over three selected nodes. This finite check is not a theorem
about arbitrary graphs, causation between records, authority or complete security.
Counts are dimensionless; encoded commitments bind bytes.
"""
from __future__ import annotations

import base64
import hashlib
import json

import pytest

from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes, graph_lineage, graph_statics


def _raw(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_raw(value)).hexdigest()


@pytest.mark.parametrize("mask", range(64), ids=lambda value: f"mask-{value:02d}")
def test_all_three_node_edge_sets_obey_the_independent_declared_relation(mask: int) -> None:
    nodes = ["a", "b", "c"]
    possible = [(a, b) for a in nodes for b in nodes if a != b]
    chosen = [pair for bit, pair in enumerate(possible) if mask & (1 << bit)]
    # Literal oracle comes from these two fixture declarations, not a native
    # checker, route catalogue, exported result or producer test helper.
    required = {("a", "b"), ("b", "c")}
    expected = "PASS" if set(chosen) == required else "FAIL"
    objects = [NamespaceObject.create("a", "HYPER", {}, {"next": ["b"]}),
               NamespaceObject.create("b", "HYPER", {}, {"next": ["c"]}),
               NamespaceObject.create("c", "OBJECT", {})]
    edges = [{"source": a, "target": b} for a, b in chosen]
    graph = NamespaceObject.create("g", "GRAPH", {
        "element_kind": "OBJECT", "scope": "retained_directed_graph",
        "nodes_digest": _digest(nodes), "edges_digest": _digest(edges)}, {"members": nodes})
    objects.append(graph)
    records = {item.object_id: item.to_dict() for item in objects}
    for item in objects:
        assert item.digest == _digest(records[item.object_id])
    child_evidence = _raw({"schema_version": graph_statics.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects], "inputs": {"nodes": nodes, "edges": edges}})
    child_policy = graph_statics.graph_statics_policy(trust_roots=["synthetic-finite-child"])
    child_request = graph_statics.graph_statics_request(subject_id="g", object_digest=graph.digest,
        collection_digest=composition_digest(objects), nodes_digest=_digest(nodes), edges_digest=_digest(edges),
        evidence_ref="sha256:" + hashlib.sha256(child_evidence).hexdigest(), policy=child_policy)
    child = graph_statics.build_graph_statics_certificate(child_request, child_evidence, policy=child_policy)
    contents = [{"source": a, "target": b, "source_digest": _digest(records[a]),
                 "target_digest": _digest(records[b])} for a, b in chosen]
    value = {"schema_version": graph_lineage.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects], "inputs": {"nodes": nodes, "edges": edges},
        "edge_contents": contents, "child_certificate": base64.b64encode(child).decode("ascii")}
    evidence = _raw(value)
    policy = graph_lineage.graph_lineage_policy(trust_roots=["synthetic-finite-parent"])
    request = graph_lineage.graph_lineage_request(subject_id="g", object_digest=graph.digest,
        collection_digest=composition_digest(objects), nodes_digest=_digest(nodes), edges_digest=_digest(edges),
        edge_contents_digest=_digest(contents), evidence_ref=_digest(value), child_request=child_request,
        child_policy=child_policy, child_certificate_digest="sha256:" + hashlib.sha256(child).hexdigest(), policy=policy)
    certificate = graph_lineage.build_graph_lineage_certificate(request, evidence, policy=policy)
    result = current_object_routes.replay_current_object_certificate(certificate,
        semantic_version=graph_lineage.SEMANTIC_VERSION, objective="GRAPH-9.2", represented_kind="GRAPH",
        expected_request=request, policy=policy)
    assert result["computational_status"] == expected
    assert result["replay_status"] == "REPRODUCED"
    assert result["native_result"]["authority"] == "NOT_ESTABLISHED"
    assert result["native_result"]["graph_security_tier_conformance"] == "NOT_ESTABLISHED"
