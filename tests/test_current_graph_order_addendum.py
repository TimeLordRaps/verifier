"""Order controls an acceptor's mutants showed the first GRAPH-2.1 tests could not see.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Node and edge counts and order positions are
dimensionless. Each test names the surviving mutant from claude-desktop's
interim acceptance (packet 20260930-182736) that it is written to kill.
"""
from __future__ import annotations

import base64
import hashlib
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import graph_order, graph_statics

DIAMOND = [{"source": "a", "target": "b"}, {"source": "a", "target": "c"},
           {"source": "b", "target": "d"}, {"source": "c", "target": "d"}]
_ABSENT = object()


def child_for(nodes: list[str], edges: list[dict[str, str]], *, retain: bool = True):
    members = [NamespaceObject.create(name, "ENV", {"fixture": name}) for name in nodes]
    graph = NamespaceObject.create("graph", "GRAPH", {
        "element_kind": "ENV", "scope": "retained_directed_graph",
        "nodes_digest": digest(nodes), "edges_digest": digest(edges),
    }, {"members": list(nodes)})
    objects = [*members, graph]
    evidence = canonical_bytes({
        "schema_version": graph_statics.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"nodes": nodes, "edges": edges},
    })
    policy = graph_statics.graph_statics_policy(trust_roots=["graph-root"])
    request = graph_statics.graph_statics_request(
        subject_id="graph", object_digest=graph.digest,
        collection_digest=composition_digest(objects),
        nodes_digest=digest(nodes), edges_digest=digest(edges),
        evidence_ref=digest(json.loads(evidence)), policy=policy)
    certificate = graph_statics.build_graph_statics_certificate(
        request, evidence if retain else None, policy=policy)
    return request, policy, certificate


def verdict(nodes: list[str], edges: list[dict[str, str]], order: list[str], *,
            embedded=None, child_field=_ABSENT, **limits: int) -> str:
    """Parent status for `order`; `embedded` swaps the certificate carried in the bundle."""
    child_request, child_policy, child_certificate = child_for(nodes, edges)
    carried = child_certificate if embedded is None else embedded
    bundle = {"schema_version": graph_order.EVIDENCE_VERSION,
              "child_request": child_request, "child_policy": child_policy,
              "child_certificate": base64.b64encode(carried).decode("ascii"),
              "order": order}
    if child_field == "omit":
        del bundle["child_certificate"]
    elif child_field is not _ABSENT:
        bundle["child_certificate"] = child_field
    evidence = canonical_bytes(bundle)
    policy = graph_order.graph_order_policy(trust_roots=["order-root"])
    request = graph_order.graph_order_request(
        subject_id="graph", object_digest=child_request["object_digest"],
        collection_digest=child_request["collection_digest"],
        child_request_digest=digest(child_request), child_policy_digest=digest(child_policy),
        child_certificate_digest="sha256:" + hashlib.sha256(child_certificate).hexdigest(),
        order_digest=digest(order), evidence_ref=digest(json.loads(evidence)),
        policy=policy, limits=limits or None)
    certificate = graph_order.build_graph_order_certificate(request, evidence, policy=policy)
    result = graph_order.recheck_graph_order_certificate(
        certificate, expected_request=request, policy=policy)
    return result["status"]


def test_edgeless_graph_still_requires_every_node():
    # Kills mutant d (omitted-node check dropped). Without edges, no precedence
    # lookup can raise, and the least-order comparison stops at the shorter list.
    nodes = ["a", "b", "c", "d"]
    assert verdict(nodes, [], ["a", "b", "c", "d"]) == "PASS"
    assert verdict(nodes, [], ["a", "b", "c"]) == "FAIL"
    assert verdict(nodes, [], ["a"]) == "FAIL"


def test_identifiers_order_by_code_point_not_by_case_fold():
    # Kills mutant b2. "A" is U+0041 and "a" is U+0061, so "A" is least.
    nodes = ["A", "a"]
    assert verdict(nodes, [], ["A", "a"]) == "PASS"
    assert verdict(nodes, [], ["a", "A"]) == "FAIL"


def test_identifiers_order_by_code_point_not_by_utf16_code_unit():
    # Kills mutant b3. U+FFFD precedes U+1F600 by code point; in UTF-16 the
    # astral character's leading surrogate D83D sorts before FFFD.
    replacement, astral = "�", "\U0001f600"
    assert replacement.encode("utf-16-be") > astral.encode("utf-16-be")
    nodes = [replacement, astral]  # the GRAPH-3.1 child retains nodes in code-point order
    assert verdict(nodes, [], [replacement, astral]) == "PASS"
    assert verdict(nodes, [], [astral, replacement]) == "FAIL"


@pytest.mark.parametrize("bound,at,over", [("max_nodes", 4, 3), ("max_edges", 4, 3)])
def test_a_graph_exactly_at_its_bound_passes(bound, at, over):
    # Kills mutants k and k3 (">=" at the node and edge bound): a limit admits its value.
    nodes, order = ["a", "b", "c", "d"], ["a", "b", "c", "d"]
    assert verdict(nodes, DIAMOND, order, **{bound: at}) == "PASS"
    assert verdict(nodes, DIAMOND, order, **{bound: over}) == "UNKNOWN"


def test_another_certificate_for_the_same_child_request_is_a_substitution():
    # Kills mutant o (child-certificate digest check dropped). The carried
    # certificate shares the child request but retains no evidence, so it would
    # replay UNKNOWN; the selection names other bytes, so the parent is FAIL.
    nodes, order = ["a", "b", "c", "d"], ["a", "b", "c", "d"]
    _, _, unretained = child_for(nodes, DIAMOND, retain=False)
    assert json.loads(unretained)["result"]["status"] == "UNKNOWN"
    assert verdict(nodes, DIAMOND, order, embedded=unretained) == "FAIL"


@pytest.mark.parametrize("child_field", [None, "", "omit"])
def test_a_present_bundle_with_an_unusable_child_field_is_malformed(child_field):
    # Pins the behaviour behind finding F1: a retained bundle whose child field
    # is null, empty or absent is malformed evidence (FAIL); only an absent
    # bundle or an UNKNOWN child is UNKNOWN. The specification sentence is
    # corrected in the next revision to say exactly this.
    nodes, order = ["a", "b", "c", "d"], ["a", "b", "c", "d"]
    assert verdict(nodes, DIAMOND, order, child_field=child_field) == "FAIL"
