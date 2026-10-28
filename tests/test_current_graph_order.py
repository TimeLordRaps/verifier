"""Selected finite GRAPH least topological order, not temporal or profile truth.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Node and edge counts and order positions are
dimensionless. The GRAPH-3.1 child and the declared order are separately
selected; the current object coordinate does not inherit the legacy GRAPH-2.1.
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
from verifier.domains.contracts import graph_order, graph_statics
from verifier.domains import inventory
from verifier.domains.inventory import get_slot

NODES = ["a", "b", "c", "d"]
DIAMOND = [{"source": "a", "target": "b"}, {"source": "a", "target": "c"},
           {"source": "b", "target": "d"}, {"source": "c", "target": "d"}]
CROSSED = [{"source": "b", "target": "a"}, {"source": "d", "target": "c"}]
KEY = (graph_order.SEMANTIC_VERSION, graph_order.COORDINATE)


def is_topological(order: list[str], edges: list[dict[str, str]]) -> bool:
    """Position comparison only; shares no traversal with the checker."""
    where = {node: index for index, node in enumerate(order)}
    return all(where[edge["source"]] < where[edge["target"]] for edge in edges)


def selected(edges: list[dict[str, str]] | None = None, *,
             evidence_edges: list[dict[str, str]] | None = None,
             order: list[str] | None = None,
             selected_order: list[str] | None = None,
             include_child: bool = True, child_limits: dict | None = None,
             **limits: int):
    edges = DIAMOND if edges is None else edges
    retained_edges = edges if evidence_edges is None else evidence_edges
    members = [NamespaceObject.create(name, "ENV", {"fixture": name}) for name in NODES]
    graph = NamespaceObject.create("graph", "GRAPH", {
        "element_kind": "ENV", "scope": "retained_directed_graph",
        "nodes_digest": digest(NODES), "edges_digest": digest(edges),
    }, {"members": list(NODES)})
    objects = [*members, graph]
    child_evidence = canonical_bytes({
        "schema_version": graph_statics.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"nodes": NODES, "edges": retained_edges},
    })
    child_policy = graph_statics.graph_statics_policy(trust_roots=["graph-root"])
    child_request = graph_statics.graph_statics_request(
        subject_id="graph", object_digest=graph.digest,
        collection_digest=composition_digest(objects),
        nodes_digest=digest(NODES), edges_digest=digest(edges),
        evidence_ref=digest(json.loads(child_evidence)), policy=child_policy,
        limits=child_limits)
    child_certificate = graph_statics.build_graph_statics_certificate(
        child_request, child_evidence, policy=child_policy)
    declared = ["a", "b", "c", "d"] if order is None else order
    committed = declared if selected_order is None else selected_order
    evidence = canonical_bytes({
        "schema_version": graph_order.EVIDENCE_VERSION,
        "child_request": child_request, "child_policy": child_policy,
        "child_certificate": base64.b64encode(child_certificate).decode("ascii"),
        "order": declared,
    }) if include_child else None
    policy = graph_order.graph_order_policy(trust_roots=["order-root"])
    request = graph_order.graph_order_request(
        subject_id="graph", object_digest=graph.digest,
        collection_digest=composition_digest(objects),
        child_request_digest=digest(child_request),
        child_policy_digest=digest(child_policy),
        child_certificate_digest="sha256:" + hashlib.sha256(child_certificate).hexdigest(),
        order_digest=digest(committed),
        evidence_ref=digest(json.loads(evidence)) if evidence is not None
        else "sha256:" + "0" * 64,
        policy=policy, limits=limits or None)
    return request, policy, evidence, child_certificate


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = graph_order.build_graph_order_certificate(
        request, evidence, policy=policy)
    result = graph_order.recheck_graph_order_certificate(
        certificate, expected_request=request, policy=policy)
    assert result["coordinate"] == "GRAPH-2.1"
    assert result["legacy_graph_profile_conformance"] == "NOT_ESTABLISHED"
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"
    return certificate, result


def child_status(child: bytes) -> str:
    return json.loads(child)["result"]["status"]


# Unit layer: the proposition, its bounded meaning and every refusal class.

def test_least_order_passes_without_temporal_or_tier_promotion():
    request, policy, evidence, child = selected()
    certificate, result = replay(request, policy, evidence)
    assert child_status(child) == "PASS"
    assert result["status"] == "PASS"
    assert result["least_topological_order"] == "PASS"
    assert result["temporal_or_lineage_truth"] == "NOT_ESTABLISHED"
    assert result["graph_dynamics_tier_conformance"] == "NOT_ESTABLISHED"
    observed = result["evaluation"]["observations"]
    assert observed["graph"]["node_count"] == 4 and observed["graph"]["edge_count"] == 4
    assert certificate == graph_order.build_graph_order_certificate(
        request, evidence, policy=policy)


def test_valid_non_least_topological_order_passes_child_but_fails_parent():
    # Codex 163000 control: a, c, b, d respects every diamond edge.
    order = ["a", "c", "b", "d"]
    assert is_topological(order, DIAMOND) and order != sorted(order)
    request, policy, evidence, child = selected(order=order)
    assert child_status(child) == "PASS"
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert result["least_topological_order"] == "NOT_ESTABLISHED"
    assert "not the least" in result["evaluation"]["details"]


def test_least_order_differs_from_sorted_members_and_from_the_childs_queue():
    # Least is b, a, d, c. Sorted members break b->a; the child's own
    # first-in first-out order b, d, a, c is topological but not least.
    assert is_topological(["b", "d", "a", "c"], CROSSED)
    for order, expected in ((["b", "a", "d", "c"], "PASS"),
                            (["b", "d", "a", "c"], "FAIL"),
                            (["d", "c", "b", "a"], "FAIL"),
                            (["a", "b", "c", "d"], "FAIL")):
        request, policy, evidence, child = selected(CROSSED, order=order)
        assert child_status(child) == "PASS"
        assert replay(request, policy, evidence)[1]["status"] == expected, order


def test_edgeless_graph_least_order_is_the_sorted_members():
    request, policy, evidence, _ = selected([])
    assert replay(request, policy, evidence)[1]["status"] == "PASS"
    request, policy, evidence, _ = selected([], order=["d", "c", "b", "a"])
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_order_violating_a_retained_edge_refutes():
    request, policy, evidence, _ = selected(order=["a", "b", "d", "c"])
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert "before its retained predecessor" in result["evaluation"]["details"]


@pytest.mark.parametrize("order", [
    ["a", "b", "c"],                  # omitted node
    ["a", "b", "c", "d", "d"],        # repeated final node
    ["a", "b", "b", "d"],             # repeated node replacing c
    [],                               # empty order for a nonempty graph
    {"a": 0, "b": 1, "c": 2, "d": 3}, # positions instead of an array
    [0, 1, 2, 3],                     # positions instead of identifiers
    [["a"], ["b"], ["c"], ["d"]],     # layered rows instead of identifiers
])
def test_order_must_name_each_selected_node_exactly_once(order):
    request, policy, evidence, _ = selected(order=order)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_order_entry_outside_selected_members_refutes_boundary():
    request, policy, evidence, _ = selected(order=["a", "b", "c", "d", "z"])
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert "outside" in result["evaluation"]["details"]


@pytest.mark.parametrize("edges", [
    [{"source": "a", "target": "b"}, {"source": "b", "target": "a"}],
    [{"source": "a", "target": "a"}],
    [{"source": "a", "target": "z"}],
    [{"source": "b", "target": "c"}, {"source": "a", "target": "b"}],
])
def test_failed_child_statics_cannot_be_reinterpreted_as_order(edges):
    request, policy, evidence, child = selected(edges)
    assert child_status(child) == "FAIL"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_tampered_retained_edge_cannot_select_another_least_order():
    # Without b->a the least order would be a, b, c, d; the child refuses it.
    request, policy, evidence, child = selected(
        CROSSED, evidence_edges=[{"source": "d", "target": "c"}],
        order=["a", "b", "d", "c"])
    assert child_status(child) == "FAIL"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_selected_order_digest_must_name_the_retained_order():
    request, policy, evidence, _ = selected(selected_order=["a", "c", "b", "d"])
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_missing_child_and_exhausted_bounds_remain_unknown():
    request, policy, _, _ = selected(include_child=False)
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"
    for bound in ({"max_operations": 1}, {"max_nodes": 3}, {"max_edges": 3}):
        request, policy, evidence, _ = selected(**bound)
        assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN", bound
    request, policy, evidence, child = selected(child_limits={"max_items": 1})
    assert child_status(child) == "UNKNOWN"
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_operation_bound_is_exact_at_the_last_checked_position():
    request, policy, evidence, _ = selected()
    used = replay(request, policy, evidence)[1]["evaluation"]["observations"]["operations"]
    request, policy, evidence, _ = selected(max_operations=used)
    assert replay(request, policy, evidence)[1]["status"] == "PASS"
    request, policy, evidence, _ = selected(max_operations=used - 1)
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
            "order_digest": "sha256:" + "6" * 64,
            "evidence_ref": "sha256:" + "7" * 64, "policy": policy}
    for limits in ({"max_nodes": 257}, {"max_operations": 2_000_001},
                   {"max_closure_pairs": 1}):
        with pytest.raises(graph_order.GraphOrderError):
            graph_order.graph_order_request(**base, limits=limits)


def test_rehashed_verdict_substituted_request_and_other_policy_are_refused():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(ValueError):
        graph_order.recheck_graph_order_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    wrong = {**request, "order_digest": "sha256:" + "0" * 64}
    with pytest.raises(graph_order.GraphOrderError):
        graph_order.recheck_graph_order_certificate(
            certificate, expected_request=wrong, policy=policy)
    other = deepcopy(policy)
    other["trust_roots"] = ["other-root"]
    with pytest.raises(ValueError):
        graph_order.recheck_graph_order_certificate(
            certificate, expected_request=request, policy=other)


def test_rehashed_child_verdict_cannot_be_selected_as_order():
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


def test_registration_disambiguates_the_legacy_graph_axis_coordinate():
    registration = graph_order.registration()
    assert registration["coordinate"] == "GRAPH-2.1"
    assert registration["subject_kind"] == "GRAPH"
    assert any("legacy" in item and "rating" in item
               for item in registration["exclusions"])
    spec = (Path(graph_order.__file__).parents[2] / "standard"
            / "CURRENT_GRAPH_ORDER.md").read_text(encoding="utf-8")
    assert "legacy Graph-axis `GRAPH-2.1`" in spec
    legacy = (Path(graph_order.__file__).parents[2] / "standard"
              / "GRAPH_GROUNDING.md").read_text(encoding="utf-8")
    assert "| GRAPH-2.1 | Member rating re-execution |" in legacy


# Integration layer: public route, inventory, command line and privacy.

def test_public_route_and_inventory_select_only_this_order_objective():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=graph_order.SEMANTIC_VERSION,
        objective=graph_order.COORDINATE, represented_kind="GRAPH",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["temporal_or_lineage_truth"] == "NOT_ESTABLISHED"
    route = next(row for row in routes.current_object_route_catalog()
                 if row["objective"] == "GRAPH-2.1")
    assert route["represented_kind_rule"] == "GRAPH"
    assert route["certificate_schema_version"] == graph_order.CERTIFICATE_VERSION
    slot = get_slot("GRAPH", 2)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == "GRAPH-2.1"
    serialized = slot.to_dict()
    assert serialized["objective_inventory_closure"] == "NOT_ESTABLISHED"
    assert {item["coordinate"] for item in serialized["registered_objectives"]} == {"GRAPH-2.1"}
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version=graph_order.SEMANTIC_VERSION,
            objective=graph_order.COORDINATE, represented_kind="TIME",
            expected_request=request, policy=policy)


def test_public_command_replays_selected_order_certificate(tmp_path: Path, capsys):
    from verifier.runtime.public_cli import main

    for name, order, code in (("pass", None, 0), ("fail", ["a", "c", "b", "d"], 1),
                              ("unknown", None, 2)):
        limits = {"max_operations": 1} if name == "unknown" else {}
        request, policy, evidence, _ = selected(order=order, **limits)
        certificate, _ = replay(request, policy, evidence)
        folder = tmp_path / name
        folder.mkdir()
        for label, contents in (("request", canonical_bytes(request)),
                                ("policy", canonical_bytes(policy)),
                                ("certificate", certificate)):
            (folder / (label + ".json")).write_bytes(contents)
        returned = main(["current-object", "check", str(folder / "certificate.json"),
            "--semantic-version", graph_order.SEMANTIC_VERSION,
            "--objective", graph_order.COORDINATE, "--represented-kind", "GRAPH",
            "--request", str(folder / "request.json"),
            "--policy", str(folder / "policy.json"), "--json"])
        assert returned == code, name
        assert json.loads(capsys.readouterr().out)["computational_status"] == name.upper()


def test_retained_order_certificate_refuses_evidence_redaction():
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


# Regression layer: dependency pins, polish digest and the installed wheel.

@pytest.mark.parametrize("relative", [
    "domains/contracts/graph_order.py",
    "domains/contracts/graph_statics.py",
    "domains/contracts/retained_selection.py",
    "standard/CURRENT_GRAPH_ORDER.md",
    "standard/CURRENT_GRAPH_STATICS.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(graph_order.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        graph_order.recheck_graph_order_certificate(
            certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("relative", [
    "domains/contracts/graph_order.py", "standard/CURRENT_GRAPH_ORDER.md",
])
def test_order_dependency_change_invalidates_polish_digest(relative, monkeypatch):
    from verifier.runtime import polish

    original = Path.read_bytes
    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()

    def altered(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged GRAPH order dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", altered)
    assert polish.mechanism_digest() != before


def test_installed_wheel_replays_graph_order_without_source_tree(tmp_path: Path, wheel_source: Path) -> None:
    root = wheel_source
    wheel_dir = tmp_path / "dist"
    wheel_dir.mkdir()
    build = subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps",
        "--no-cache-dir", "-w", str(wheel_dir), str(root)],
        capture_output=True, text=True, timeout=60)
    assert build.returncode == 0, (build.returncode, build.stdout[-4000:], build.stderr[-4000:])
    wheels = list(wheel_dir.glob("*.whl"))
    assert len(wheels) == 1
    target = tmp_path / "site-packages"
    target.mkdir()
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
        assert "verifier/domains/contracts/graph_order.py" in names
        assert "verifier/standard/CURRENT_GRAPH_ORDER.md" in names
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
        "'--objective', 'GRAPH-2.1', '--represented-kind', 'GRAPH', "
        "'--request', 'request.json', '--policy', 'policy.json', '--json']))")
    run = subprocess.run([sys.executable, "-S", "-c", command], cwd=work,
        env=env, capture_output=True, text=True, timeout=30)
    # Keep the installed replay's own report when it does not pass.
    assert run.returncode == 0, (run.returncode, run.stdout[-4000:], run.stderr[-4000:])
    assert json.loads(run.stdout)["computational_status"] == "PASS"


# Proactive preventative regression layer: the registration itself is load-
# bearing. Each control below breaks one registration fact in the running
# system and shows the real route, inventory or privacy engine refusing. None
# of them reads a count literal; the census stays with the integrator.

def test_additive_registration_changes_exactly_one_route_and_one_slot(monkeypatch):
    with_route = routes.current_object_route_catalog()
    with_slots = inventory.slot_inventory()
    monkeypatch.delitem(routes._ROUTES, KEY)
    monkeypatch.delitem(inventory.MECHANIZED_12_POINT_BINDINGS, graph_order.COORDINATE)
    without_route = routes.current_object_route_catalog()
    without_slots = inventory.slot_inventory()
    added = [row for row in with_route if row not in without_route]
    assert [row["objective"] for row in added] == ["GRAPH-2.1"]
    assert [row for row in with_route if row["objective"] != "GRAPH-2.1"] == without_route
    changed = [(old["coordinate"], new["coordinate"])
               for old, new in zip(without_slots, with_slots) if old != new]
    assert changed == [("GRAPH-2.1", "GRAPH-2.1")]
    before = next(row for row in without_slots if row["object_kind"] == "GRAPH" and row["tier"] == 2)
    after = next(row for row in with_slots if row["object_kind"] == "GRAPH" and row["tier"] == 2)
    assert (before["status"], after["status"]) == ("UNKNOWN", "REPLAYABLE")


def test_missing_route_refuses_public_replay_and_command(monkeypatch, tmp_path: Path, capsys):
    from verifier.runtime.public_cli import main

    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    monkeypatch.delitem(routes._ROUTES, KEY)
    with pytest.raises(routes.CurrentObjectRouteRefusal, match="unsupported"):
        routes.replay_current_object_certificate(
            certificate, semantic_version=graph_order.SEMANTIC_VERSION,
            objective=graph_order.COORDINATE, represented_kind="GRAPH",
            expected_request=request, policy=policy)
    for label, contents in (("request", canonical_bytes(request)),
                            ("policy", canonical_bytes(policy)),
                            ("certificate", certificate)):
        (tmp_path / (label + ".json")).write_bytes(contents)
    returned = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", graph_order.SEMANTIC_VERSION,
        "--objective", graph_order.COORDINATE, "--represented-kind", "GRAPH",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    report = json.loads(capsys.readouterr().out)
    assert returned == 1
    assert (report["replay_status"], report["computational_status"]) == ("REJECTED", "NOT_CHECKED")


def test_duplicate_route_under_another_objective_cannot_launder_the_certificate(monkeypatch):
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    monkeypatch.setitem(routes._ROUTES, (graph_order.SEMANTIC_VERSION, "GRAPH-2.2"),
                        routes._ROUTES[KEY])
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version=graph_order.SEMANTIC_VERSION,
            objective="GRAPH-2.2", represented_kind="GRAPH",
            expected_request=request, policy=policy)
    relabelled = {**request, "coordinate": "GRAPH-2.2"}
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version=graph_order.SEMANTIC_VERSION,
            objective="GRAPH-2.2", represented_kind="GRAPH",
            expected_request=relabelled, policy=policy)


@pytest.mark.parametrize("misbinding", ["checker", "kind"])
def test_misbound_route_refuses_replay(misbinding, monkeypatch):
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    bound = routes._ROUTES[KEY]
    wrong = (routes._Route(bound.module, graph_statics.recheck_graph_statics_certificate,
                           bound.fixed_kind, bound.scope)
             if misbinding == "checker" else
             routes._Route(bound.module, bound.replay, "TIME", bound.scope))
    monkeypatch.setitem(routes._ROUTES, KEY, wrong)
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version=graph_order.SEMANTIC_VERSION,
            objective=graph_order.COORDINATE, represented_kind="GRAPH",
            expected_request=request, policy=policy)


def test_route_and_inventory_name_the_same_installed_checker():
    binding = inventory.MECHANIZED_12_POINT_BINDINGS[graph_order.COORDINATE]
    module_name, _, function = binding["checking_mechanism"].rpartition(".")
    assert module_name == graph_order.__name__
    assert function == "recheck_graph_order_certificate"
    assert graph_order.recheck_graph_order_certificate is routes._ROUTES[KEY].replay
    assert binding["artifact_coordinate"] == graph_order.COORDINATE
    assert binding["exact_claim"] == graph_order.registration()["proposition"]
    assert binding["resulting_evidence"] == graph_order.CERTIFICATE_VERSION
    assert {key: binding["resource_limits"][key] for key in graph_order._CEILINGS} == graph_order._CEILINGS
    assert binding["public_route_and_tests"].split("::")[1] == (
        test_public_route_and_inventory_select_only_this_order_objective.__name__
    )


def test_unreachable_route_leaves_the_slot_unknown(monkeypatch):
    monkeypatch.delitem(inventory.MECHANIZED_12_POINT_BINDINGS, graph_order.COORDINATE)
    slot = get_slot("GRAPH", 2)
    assert not slot.mechanized and slot.status == "UNKNOWN"
    assert slot.mechanized_route is None
    assert KEY in routes._ROUTES


def test_omitted_privacy_schema_would_let_redaction_through(monkeypatch):
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        EmissionContext, EmissionEvaluator, ObserverParty)
    from verifier.privacy import engine

    assert graph_order.CERTIFICATE_VERSION in engine._CANONICAL_CERTIFICATE_SCHEMAS
    monkeypatch.setattr(engine, "_CANONICAL_CERTIFICATE_SCHEMAS", tuple(
        schema for schema in engine._CANONICAL_CERTIFICATE_SCHEMAS
        if schema != graph_order.CERTIFICATE_VERSION))
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface("GRAPH", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    # Without the schema the engine does not refuse; the registration is what refuses.
    EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)
