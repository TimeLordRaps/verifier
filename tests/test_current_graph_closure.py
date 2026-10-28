"""Selected finite GRAPH reachability closure, not lineage or profile truth.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Node, edge and closure-pair counts are
dimensionless. The GRAPH-3.1 child and the declared closure are separately
selected; the current object coordinate does not inherit the legacy GRAPH-4.1.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.common import digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import graph_closure, graph_statics
from verifier.domains.inventory import get_slot

NODES = ["a", "b", "c"]
CHAIN = [{"source": "a", "target": "b"}, {"source": "b", "target": "c"}]


def reference_closure(nodes: list[str], edges: list[dict[str, str]]) -> list[dict]:
    """Warshall over a boolean matrix; shares no traversal with the checker."""
    index = {node: position for position, node in enumerate(nodes)}
    reach = [[False] * len(nodes) for _ in nodes]
    for edge in edges:
        reach[index[edge["source"]]][index[edge["target"]]] = True
    for middle in range(len(nodes)):
        for source in range(len(nodes)):
            for target in range(len(nodes)):
                reach[source][target] |= reach[source][middle] and reach[middle][target]
    return [{"node": node, "reachable": [other for other in nodes
             if reach[index[node]][index[other]]]} for node in nodes]


def selected(edges: list[dict[str, str]] | None = None, *,
             nodes: list[str] | None = None,
             evidence_edges: list[dict[str, str]] | None = None,
             closure: list[dict] | None = None,
             selected_closure: list[dict] | None = None,
             include_child: bool = True, child_limits: dict | None = None,
             **limits: int):
    edges = CHAIN if edges is None else edges
    retained_nodes = NODES if nodes is None else nodes
    retained_edges = edges if evidence_edges is None else evidence_edges
    members = [NamespaceObject.create(name, "ENV", {"fixture": name}) for name in NODES]
    graph = NamespaceObject.create("graph", "GRAPH", {
        "element_kind": "ENV", "scope": "retained_directed_graph",
        "nodes_digest": digest(retained_nodes), "edges_digest": digest(edges),
    }, {"members": list(NODES)})
    objects = [*members, graph]
    child_evidence = canonical_bytes({
        "schema_version": graph_statics.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"nodes": retained_nodes, "edges": retained_edges},
    })
    child_policy = graph_statics.graph_statics_policy(trust_roots=["graph-root"])
    child_request = graph_statics.graph_statics_request(
        subject_id="graph", object_digest=graph.digest,
        collection_digest=composition_digest(objects),
        nodes_digest=digest(retained_nodes), edges_digest=digest(edges),
        evidence_ref=digest(json.loads(child_evidence)), policy=child_policy,
        limits=child_limits)
    child_certificate = graph_statics.build_graph_statics_certificate(
        child_request, child_evidence, policy=child_policy)
    declared = reference_closure(NODES, edges) if closure is None else closure
    committed = declared if selected_closure is None else selected_closure
    evidence = canonical_bytes({
        "schema_version": graph_closure.EVIDENCE_VERSION,
        "child_request": child_request, "child_policy": child_policy,
        "child_certificate": base64.b64encode(child_certificate).decode("ascii"),
        "closure": declared,
    }) if include_child else None
    policy = graph_closure.graph_closure_policy(trust_roots=["closure-root"])
    request = graph_closure.graph_closure_request(
        subject_id="graph", object_digest=graph.digest,
        collection_digest=composition_digest(objects),
        child_request_digest=digest(child_request),
        child_policy_digest=digest(child_policy),
        child_certificate_digest="sha256:" + hashlib.sha256(child_certificate).hexdigest(),
        closure_digest=digest(committed),
        evidence_ref=digest(json.loads(evidence)) if evidence is not None
        else "sha256:" + "0" * 64,
        policy=policy, limits=limits or None)
    return request, policy, evidence, child_certificate


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = graph_closure.build_graph_closure_certificate(
        request, evidence, policy=policy)
    result = graph_closure.recheck_graph_closure_certificate(
        certificate, expected_request=request, policy=policy)
    assert result["coordinate"] == "GRAPH-4.1"
    assert result["legacy_graph_profile_conformance"] == "NOT_ESTABLISHED"
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"
    return certificate, result


def rows(**reachable: list[str]) -> list[dict]:
    return [{"node": node, "reachable": reachable.get(node, [])} for node in NODES]


def test_exact_declared_closure_passes_without_lineage_promotion():
    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["reachability_closure"] == "PASS"
    assert result["lineage_truth"] == "NOT_ESTABLISHED"
    assert result["graph_closure_tier_conformance"] == "NOT_ESTABLISHED"
    observed = result["evaluation"]["observations"]
    assert observed["closure_pairs"] == 3 and observed["graph"]["edge_count"] == 2
    assert certificate == graph_closure.build_graph_closure_certificate(
        request, evidence, policy=policy)


def test_graph_without_edges_has_an_empty_row_for_every_node():
    request, policy, evidence, _ = selected([])
    assert replay(request, policy, evidence)[1]["status"] == "PASS"


@pytest.mark.parametrize("closure", [
    rows(a=["b"], b=["c"]),                  # omitted transitive pair a->c
    rows(a=["c"], b=["c"]),                  # omitted direct pair a->b
    rows(a=["b", "c"], b=["c"], c=["a"]),    # extra unreachable pair c->a
    rows(a=["a", "b", "c"], b=["c"]),        # extra self pair in an acyclic graph
])
def test_omitted_or_extra_closure_pair_refutes(closure):
    request, policy, evidence, _ = selected(closure=closure)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


@pytest.mark.parametrize("closure", [
    [{"node": "a", "reachable": ["b", "c"]}, {"node": "b", "reachable": ["c"]}],
    rows(a=["b", "c"], b=["c"]) + [{"node": "d", "reachable": []}],
    list(reversed(rows(a=["b", "c"], b=["c"]))),
    rows(a=["c", "b"], b=["c"]),
    rows(a=["b", "b", "c"], b=["c"]),
    [{"node": "a", "reachable": ["b", "c"], "path": []}, *rows(b=["c"])[1:]],
    {"a": ["b", "c"], "b": ["c"], "c": []},
])
def test_closure_rows_must_cover_exactly_the_selected_nodes(closure):
    request, policy, evidence, _ = selected(closure=closure)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_closure_endpoint_outside_selected_members_refutes_boundary():
    request, policy, evidence, _ = selected(closure=rows(a=["b", "c", "z"], b=["c"]))
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert "outside" in result["evaluation"]["details"]


@pytest.mark.parametrize("edges", [
    [{"source": "a", "target": "b"}, {"source": "b", "target": "a"}],
    [{"source": "a", "target": "a"}],
    [{"source": "a", "target": "z"}],
    [{"source": "b", "target": "c"}, {"source": "a", "target": "b"}],
])
def test_failed_child_statics_cannot_be_reinterpreted_as_closure(edges):
    request, policy, evidence, child = selected(edges, closure=rows())
    assert json.loads(child)["result"]["status"] == "FAIL"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_tampered_retained_edge_cannot_select_a_smaller_closure():
    request, policy, evidence, child = selected(
        evidence_edges=[{"source": "a", "target": "b"}], closure=rows(a=["b"]))
    assert json.loads(child)["result"]["status"] == "FAIL"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_selected_closure_digest_must_name_the_retained_closure():
    request, policy, evidence, _ = selected(selected_closure=rows(a=["b"], b=["c"]))
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_missing_child_and_exhausted_bounds_remain_unknown():
    request, policy, _, _ = selected(include_child=False)
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"
    for bound in ({"max_operations": 1}, {"max_closure_pairs": 2},
                  {"max_nodes": 2}, {"max_edges": 1}):
        request, policy, evidence, _ = selected(**bound)
        assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN", bound
    request, policy, evidence, child = selected(child_limits={"max_items": 1})
    assert json.loads(child)["result"]["status"] == "UNKNOWN"
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("field", ["subject_id", "object_digest", "collection_digest"])
def test_parent_cannot_substitute_the_child_subject_or_collection(field):
    request, policy, evidence, _ = selected()
    other = deepcopy(request)
    other[field] = "other-graph" if field == "subject_id" else "sha256:" + "1" * 64
    assert replay(other, policy, evidence)[1]["status"] == "FAIL"


def test_limit_above_ceiling_and_unknown_limit_are_rejected():
    _, policy, _, _ = selected()
    base = {"subject_id": "graph", "object_digest": "sha256:" + "1" * 64,
            "collection_digest": "sha256:" + "2" * 64,
            "child_request_digest": "sha256:" + "3" * 64,
            "child_policy_digest": "sha256:" + "4" * 64,
            "child_certificate_digest": "sha256:" + "5" * 64,
            "closure_digest": "sha256:" + "6" * 64,
            "evidence_ref": "sha256:" + "7" * 64, "policy": policy}
    for limits in ({"max_nodes": 257}, {"max_closure_pairs": 10**9}, {"max_paths": 1}):
        with pytest.raises(graph_closure.GraphClosureError):
            graph_closure.graph_closure_request(**base, limits=limits)


def test_rehashed_verdict_substituted_request_and_other_policy_are_refused():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(ValueError):
        graph_closure.recheck_graph_closure_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    wrong = {**request, "closure_digest": "sha256:" + "0" * 64}
    with pytest.raises(graph_closure.GraphClosureError):
        graph_closure.recheck_graph_closure_certificate(
            certificate, expected_request=wrong, policy=policy)
    other = deepcopy(policy)
    other["trust_roots"] = ["other-root"]
    with pytest.raises(ValueError):
        graph_closure.recheck_graph_closure_certificate(
            certificate, expected_request=request, policy=other)


def test_rehashed_child_verdict_cannot_be_selected_as_closure():
    request, policy, evidence, child = selected()
    altered = json.loads(child)
    altered["result"]["status"] = "PASS"
    altered["result"]["evaluation"]["details"] = "forged"
    altered.pop("digest")
    altered["digest"] = digest(altered)
    altered_bytes = canonical_bytes(altered)
    altered_evidence = json.loads(evidence)
    altered_evidence["child_certificate"] = base64.b64encode(altered_bytes).decode("ascii")
    altered_request = deepcopy(request)
    altered_request["child_certificate_digest"] = (
        "sha256:" + hashlib.sha256(altered_bytes).hexdigest())
    altered_request["evidence_ref"] = digest(altered_evidence)
    assert replay(altered_request, policy, canonical_bytes(altered_evidence))[1]["status"] == "FAIL"


def test_public_route_and_inventory_select_only_this_closure_objective():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=graph_closure.SEMANTIC_VERSION,
        objective=graph_closure.COORDINATE, represented_kind="GRAPH",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["lineage_truth"] == "NOT_ESTABLISHED"
    route = next(row for row in routes.current_object_route_catalog()
                 if row["objective"] == "GRAPH-4.1")
    assert route["represented_kind_rule"] == "GRAPH"
    slot = get_slot("GRAPH", 4)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == "GRAPH-4.1"
    serialized = slot.to_dict()
    assert serialized["objective_inventory_closure"] == "NOT_ESTABLISHED"
    assert {item["coordinate"] for item in serialized["registered_objectives"]} == {"GRAPH-4.1"}


def test_registration_disambiguates_the_legacy_graph_axis_coordinate():
    registration = graph_closure.registration()
    assert registration["coordinate"] == "GRAPH-4.1"
    assert registration["subject_kind"] == "GRAPH"
    assert any("legacy" in item for item in registration["exclusions"])
    spec = (Path(graph_closure.__file__).parents[2] / "standard"
            / "CURRENT_GRAPH_CLOSURE.md").read_text(encoding="utf-8")
    assert "legacy Graph-axis `GRAPH-4.1`" in spec


def test_public_command_replays_selected_closure_certificate(tmp_path: Path, capsys):
    from verifier.runtime.public_cli import main

    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)),
                           ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", graph_closure.SEMANTIC_VERSION,
        "--objective", graph_closure.COORDINATE, "--represented-kind", "GRAPH",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_retained_closure_certificate_refuses_evidence_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty)

    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface("GRAPH", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


@pytest.mark.parametrize("relative", [
    "domains/contracts/graph_closure.py",
    "domains/contracts/graph_statics.py",
    "domains/contracts/retained_selection.py",
    "standard/CURRENT_GRAPH_CLOSURE.md",
    "standard/CURRENT_GRAPH_STATICS.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(graph_closure.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        graph_closure.recheck_graph_closure_certificate(
            certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("relative", [
    "domains/contracts/graph_closure.py", "standard/CURRENT_GRAPH_CLOSURE.md",
])
def test_closure_dependency_change_invalidates_polish_digest(relative, monkeypatch):
    from verifier.runtime import polish

    original = Path.read_bytes
    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()

    def altered(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged GRAPH closure dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", altered)
    assert polish.mechanism_digest() != before


def test_installed_wheel_replays_graph_closure_without_source_tree(tmp_path: Path, wheel_source: Path) -> None:
    root = wheel_source
    wheel_dir = tmp_path / "dist"
    wheel_dir.mkdir()
    subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps",
        "--no-cache-dir", "-w", str(wheel_dir), str(root)],
        check=True, timeout=60)
    wheels = list(wheel_dir.glob("*.whl"))
    assert len(wheels) == 1
    target = tmp_path / "site-packages"
    target.mkdir()
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
        assert "verifier/domains/contracts/graph_closure.py" in names
        assert "verifier/standard/CURRENT_GRAPH_CLOSURE.md" in names
        archive.extractall(target)

    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    work = tmp_path / "isolated"
    work.mkdir()
    (work / "certificate.json").write_bytes(certificate)
    (work / "request.json").write_bytes(canonical_bytes(request))
    (work / "policy.json").write_bytes(canonical_bytes(policy))
    env = {"PYTHONPATH": str(target), "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
           "PATH": os.environ.get("PATH", "")}
    command = ("import sys; from verifier.runtime.public_cli import main; "
        "sys.exit(main(['current-object', 'check', 'certificate.json', "
        "'--semantic-version', 'verifier-current-object-obligations-1', "
        "'--objective', 'GRAPH-4.1', '--represented-kind', 'GRAPH', "
        "'--request', 'request.json', '--policy', 'policy.json', '--json']))")
    run = subprocess.run([sys.executable, "-S", "-c", command], cwd=work,
        env=env, capture_output=True, text=True, timeout=30)
    # Keep the installed replay's own report when it does not pass.
    assert run.returncode == 0, (run.returncode, run.stdout[-4000:], run.stderr[-4000:])
    assert json.loads(run.stdout)["computational_status"] == "PASS"
