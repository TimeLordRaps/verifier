"""Selected GRAPH-9.2 relation, content, native child and public replay controls.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Counts are dimensionless; bounds count bytes.
These producer controls require execution; source inspection is not a replay.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import graph_lineage as parent, graph_statics as child
from verifier.domains.inventory import get_slot

NODES = ["a", "b", "c"]
DIRECT = [{"source": "a", "target": "b"}, {"source": "b", "target": "c"}]


def selected(*, edges=None, contents=None, operands=None, child_limits=None,
             absent_child=False, parent_limits=None, absent_contents=False):
    edges = deepcopy(DIRECT if edges is None else edges)
    roles = {"a": {"link": ["b"]}, "b": {"link": ["c"]}, "c": {}}
    if operands is not None:
        roles = operands
    members = [NamespaceObject.create(name, "HYPER" if roles[name] else "OBJECT",
                                      {}, roles[name]) for name in NODES]
    graph = NamespaceObject.create("g", "GRAPH", {
        "element_kind": "OBJECT", "scope": "retained_directed_graph",
        "nodes_digest": digest(NODES), "edges_digest": digest(edges),
    }, {"members": NODES})
    objects = [*members, graph]
    child_evidence = canonical_bytes({"schema_version": child.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"nodes": NODES, "edges": edges}})
    child_policy = child.graph_statics_policy(trust_roots=["graph-root"])
    child_request = child.graph_statics_request(subject_id="g", object_digest=graph.digest,
        collection_digest=composition_digest(objects), nodes_digest=digest(NODES),
        edges_digest=digest(edges), evidence_ref=digest(json.loads(child_evidence)),
        policy=child_policy, limits=child_limits)
    child_certificate = child.build_graph_statics_certificate(
        child_request, child_evidence, policy=child_policy)
    index = {item.object_id: item for item in objects}
    if contents is None:
        contents = [{**edge, "source_digest": index[edge["source"]].digest,
                     "target_digest": index[edge["target"]].digest} for edge in edges]
    value = {"schema_version": parent.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"nodes": NODES, "edges": edges},
        "edge_contents": None if absent_contents else contents,
        "child_certificate": None if absent_child else
            base64.b64encode(child_certificate).decode("ascii")}
    evidence = canonical_bytes(value)
    policy = parent.graph_lineage_policy(trust_roots=["lineage-root"])
    request = parent.graph_lineage_request(subject_id="g", object_digest=graph.digest,
        collection_digest=composition_digest(objects), nodes_digest=digest(NODES),
        edges_digest=digest(edges), edge_contents_digest=digest(contents),
        evidence_ref=digest(value), child_request=child_request, child_policy=child_policy,
        child_certificate_digest="sha256:" + hashlib.sha256(child_certificate).hexdigest(),
        policy=policy, limits=parent_limits)
    return request, policy, evidence, child_certificate


def replay(request, policy, evidence):
    certificate = parent.build_graph_lineage_certificate(request, evidence, policy=policy)
    result = parent.recheck_graph_lineage_certificate(
        certificate, expected_request=request, policy=policy)
    assert result["coordinate"] == "GRAPH-9.2"
    assert result["graph_security_tier_conformance"] == "NOT_ESTABLISHED"
    assert result["authority"] == "NOT_ESTABLISHED"
    return certificate, result


def recommit(request, evidence, mutate):
    value = json.loads(evidence)
    mutate(value)
    request = deepcopy(request)
    request["evidence_ref"] = digest(value)
    if value["edge_contents"] is not None:
        request["edge_contents_digest"] = digest(value["edge_contents"])
    return request, canonical_bytes(value)


def test_direct_relation_content_and_separate_native_child_pass():
    request, policy, evidence, certificate = selected()
    assert child.recheck_graph_statics_certificate(certificate,
        expected_request=request["child_request"], policy=request["child_policy"])["status"] == "PASS"
    raw, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["evaluation"]["observations"]["derived_edges"] == DIRECT
    assert result["evaluation"]["observations"]["required_child_count"] == 1
    assert raw != certificate
    assert raw == parent.build_graph_lineage_certificate(request, evidence, policy=policy)


@pytest.mark.parametrize("edges", [
    [{"source": "a", "target": "b"}, {"source": "a", "target": "c"},
     {"source": "b", "target": "c"}],
    [{"source": "b", "target": "c"}],
])
def test_injected_or_omitted_direct_edge_passes_child_but_refutes_parent(edges):
    request, policy, evidence, certificate = selected(edges=edges)
    assert json.loads(certificate)["result"]["status"] == "PASS"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_wrong_content_is_refuted_after_recommitting_every_parent_digest():
    request, policy, evidence, certificate = selected()
    request, evidence = recommit(request, evidence,
        lambda value: value["edge_contents"][0].update(target_digest="sha256:" + "0" * 64))
    assert json.loads(certificate)["result"]["status"] == "PASS"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_named_roles_collapse_to_pairs_and_empty_projection_is_vacuous():
    request, policy, evidence, _ = selected(operands={
        "a": {"left": ["b"], "right": ["b"]}, "b": {"link": ["c"]}, "c": {}})
    assert replay(request, policy, evidence)[1]["status"] == "PASS"
    request, policy, evidence, _ = selected(edges=[], operands={name: {} for name in NODES})
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "PASS"
    assert result["evaluation"]["observations"]["edge_count"] == 0


@pytest.mark.parametrize("absent", [False, True])
def test_known_parent_refutation_dominates_unknown_or_absent_child(absent):
    request, policy, evidence, _ = selected(edges=DIRECT[1:], absent_child=absent,
        child_limits=None if absent else {"max_items": 1})
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert result["evaluation"]["observations"]["child_status"] == ("ABSENT" if absent else "UNKNOWN")


def test_known_child_fail_is_not_masked_by_missing_parent_manifest():
    edges = [{"source": "a", "target": "b"}, {"source": "b", "target": "a"}]
    request, policy, evidence, certificate = selected(edges=edges, absent_contents=True)
    assert json.loads(certificate)["result"]["status"] == "FAIL"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_missing_and_malformed_child_remain_distinct():
    request, policy, evidence, _ = selected(absent_child=True)
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"
    request, evidence = recommit(request, evidence,
        lambda value: value.update(child_certificate=""))
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


@pytest.mark.parametrize("transform", [
    lambda rows: rows + [deepcopy(rows[0])],
    lambda rows: rows[1:],
    lambda rows: list(reversed(rows)),
])
def test_endpoint_manifest_must_name_each_edge_once_in_selected_order(transform):
    request, policy, evidence, _ = selected()
    request, evidence = recommit(request, evidence,
        lambda value: value.update(edge_contents=transform(value["edge_contents"])))
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


@pytest.mark.parametrize("limits", [
    {"max_operations": 1}, {"max_items": 1}, {"max_objects": 3},
    {"max_nodes": 2}, {"max_edges": 1}, {"max_child_certificate_bytes": 1},
    {"max_composition_operations": 1}, {"max_payload_bytes": 1},
    {"max_reference_bytes": 1}, {"max_evidence_bytes": 1},
])
def test_admission_or_work_bounds_preserve_unknown(limits):
    request, policy, evidence, _ = selected(parent_limits=limits)
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_exact_operations_evidence_and_child_bytes_have_inclusive_bounds():
    request, policy, evidence, certificate = selected()
    operations = replay(request, policy, evidence)[1]["evaluation"]["observations"]["operations"]
    for key, amount in (("max_operations", operations), ("max_evidence_bytes", len(evidence)),
                        ("max_child_certificate_bytes", len(certificate))):
        selected_request = deepcopy(request)
        selected_request["limits"][key] = amount
        assert replay(selected_request, policy, evidence)[1]["status"] == "PASS", key
        selected_request["limits"][key] = amount - 1
        assert replay(selected_request, policy, evidence)[1]["status"] == "UNKNOWN", key


@pytest.mark.parametrize("field", ["subject_id", "object_digest", "collection_digest",
                                   "nodes_digest", "edges_digest"])
def test_wrong_selected_child_subject_or_arrays_are_external_refusals(field):
    request, policy, evidence, _ = selected()
    wrong = deepcopy(request)
    wrong["child_request"][field] = "other" if field == "subject_id" else "sha256:" + "1" * 64
    with pytest.raises(parent.GraphLineageError):
        replay(wrong, policy, evidence)


def test_child_native_replay_refuses_rehashed_false_child_result():
    request, policy, evidence, certificate = selected()
    forged = json.loads(certificate)
    forged["result"]["evaluation"]["details"] = "substituted result"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    raw = canonical_bytes(forged)
    request, evidence = recommit(request, evidence,
        lambda value: value.update(child_certificate=base64.b64encode(raw).decode("ascii")))
    request["child_certificate_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_parent_tamper_rehashed_false_result_and_wrong_policy_are_refused():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    for raw in (certificate[:-1] + b"X", canonical_bytes(forged)):
        with pytest.raises(parent.GraphLineageError):
            parent.recheck_graph_lineage_certificate(raw, expected_request=request, policy=policy)
    wrong = deepcopy(policy)
    wrong["trust_roots"] = ["another-root"]
    with pytest.raises(parent.GraphLineageError):
        parent.recheck_graph_lineage_certificate(certificate, expected_request=request, policy=wrong)


def test_public_route_inventory_and_dependency_selection():
    request, policy, evidence, certificate = selected()
    raw, _ = replay(request, policy, evidence)
    result = routes.replay_current_object_certificate(raw,
        semantic_version=parent.SEMANTIC_VERSION, objective=parent.COORDINATE,
        represented_kind="GRAPH", expected_request=request, policy=policy)
    assert result["computational_status"] == "PASS"
    slot = get_slot("GRAPH", 9).to_dict()
    assert "GRAPH-9.2" in {item["coordinate"] for item in slot["registered_objectives"]}
    assert slot["objective_inventory_closure"] == "NOT_ESTABLISHED"
    for candidate, kind in ((raw, "OBJECT"), (certificate, "GRAPH")):
        with pytest.raises(routes.CurrentObjectRouteRefusal):
            routes.replay_current_object_certificate(candidate,
                semantic_version=parent.SEMANTIC_VERSION, objective=parent.COORDINATE,
                represented_kind=kind, expected_request=request, policy=policy)


@pytest.mark.parametrize("relative", ["domains/contracts/graph_lineage.py",
    "domains/contracts/graph_statics.py", "domains/contracts/retained_selection.py",
    "standard/CURRENT_GRAPH_LINEAGE.md", "standard/CURRENT_GRAPH_STATICS.md",
    "standard/NAMESPACE_OBJECTS.md"])
def test_direct_dependency_change_invalidates_parent_policy(relative, monkeypatch):
    policy = parent.graph_lineage_policy(trust_roots=["root"])
    original = Path.read_bytes
    target = Path(parent.__file__).parents[2] / relative

    def changed(path):
        raw = original(path)
        return raw + b"\nchanged dependency\n" if path == target else raw

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(parent.GraphLineageError):
        parent._policy(policy)


@pytest.mark.parametrize("relative", ["domains/contracts/graph_lineage.py",
                                      "standard/CURRENT_GRAPH_LINEAGE.md", "domains/inventory.py"])
def test_polish_digest_includes_new_executed_dependency(relative, monkeypatch):
    from verifier.runtime import polish

    before = polish.mechanism_digest()
    original = Path.read_bytes
    target = Path(parent.__file__).parents[2] / relative

    def changed(path):
        raw = original(path)
        return raw + b"\nchanged dependency\n" if path == target else raw

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


def test_certificate_evidence_redaction_is_refused():
    from verifier.privacy import (DisclosureBound, DisclosureSurface, EmissionContext,
        EmissionEvaluator, EmissionRefusalError, ObserverParty)

    request, policy, evidence, _ = selected()
    raw, _ = replay(request, policy, evidence)
    value = json.loads(raw)
    fields = tuple(key for key in value if key != "evidence_payloads")
    surface = DisclosureSurface("GRAPH", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",)) for key in fields)
    context = EmissionContext(ObserverParty("reader", "reviewer", "inspect"), "test-time")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


@pytest.mark.parametrize("case,expected_code,expected_status", [
    ("pass", 0, "PASS"), ("fail", 1, "FAIL"), ("unknown", 2, "UNKNOWN")])
def test_public_command_has_native_outcome_exit_codes(case, expected_code, expected_status,
                                                     tmp_path, capsys):
    from verifier.runtime.public_cli import main

    request, policy, evidence, _ = selected(
        edges=DIRECT[1:] if case == "fail" else None,
        absent_child=case == "unknown")
    certificate, _ = replay(request, policy, evidence)
    for name, raw in (("request", canonical_bytes(request)), ("policy", canonical_bytes(policy)),
                      ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(raw)
    returned = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", parent.SEMANTIC_VERSION, "--objective", parent.COORDINATE,
        "--represented-kind", "GRAPH", "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert returned == expected_code
    assert json.loads(capsys.readouterr().out)["computational_status"] == expected_status
