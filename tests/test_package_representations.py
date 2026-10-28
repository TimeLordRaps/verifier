"""Versioned current representations preserve historical Verifier Standard (VSTD) records."""
# The imported fixture must retain its public name for pytest discovery; test
# arguments intentionally reuse that name.
# ruff: noqa: F401, F811
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any
from collections.abc import Callable

import pytest

from test_package_namespace_migration import envelope, select
from test_manifest_gate import selected_root
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import graph_statics
from verifier.runtime import package_manifest, tier_zero_manifest
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


def graph_representation(document: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Derive exact finite dependency arrays from the selected declaration."""
    document = deepcopy(document)
    rows = document["namespace"]["objects"]
    graph = next(row for row in rows if row["kind"] == "GRAPH")
    prior = next(row for row in tier_zero_manifest._namespace_objects(document["objects"])
                 if row.object_id == graph["object_id"])
    nodes = sorted(graph["operands"]["members"])
    edges = [{"source": source, "target": target} for source, target in sorted({
        (row["object_id"], target) for row in rows if row["object_id"] in nodes
        for targets in row["operands"].values() for target in targets if target in nodes})]
    graph["payload"] = {"element_kind": "OBJECT", "scope": "retained_directed_graph",
                        "nodes_digest": value_digest(nodes), "edges_digest": value_digest(edges)}
    graph["surfaces"] = ["file:graph.py", "python:graph.py:<module>"]
    current = NamespaceObject.create(graph["object_id"], graph["kind"], graph["payload"], graph["operands"])
    document["schema_version"] = "verifier-objects-manifest-4"
    document["representation_updates"] = [{"object_id": graph["object_id"],
        "retained_object_digest": prior.digest, "current_object_digest": current.digest,
        "reason": "The current package dependency graph requires committed node and edge arrays, not a role template.",
        "evidence": [{"path": "graph.py", "sha256": value_digest("source-placeholder")}]}]
    return document, {"nodes": nodes, "edges": edges}


def bind_current_package_graph_source_fields(document: dict[str, Any]) -> None:
    """Add the two current source bindings without refreshing old route files."""

    body = {
        "schema_version": "verifier-source-semantic-review-profile-1",
        "reason": "Bounded fixture source semantics for the current package graph.",
        "binding_sets": [],
        "records": [],
    }
    graph = next(
        row for row in document["namespace"]["objects"]
        if row["object_id"] == "vstd-package-graph"
    )
    graph["payload"].update(
        source_refresh_coordinate="sha256:" + "1" * 64,
        source_semantic_profile={**body, "digest": value_digest(body)},
    )
    update = next(
        row for row in document["representation_updates"]
        if row["object_id"] == graph["object_id"]
    )
    update["current_object_digest"] = NamespaceObject.create(
        graph["object_id"], graph["kind"], graph["payload"], graph["operands"]
    ).digest


def test_current_graph_representation_replays_without_changing_retained_records() -> None:
    original = envelope()
    document, inputs = graph_representation(original)
    retained, validation, objects = select(document)
    assert retained == package_manifest.retained_contract(original)
    assert document["objects"] == original["objects"]
    assert validation["route_count"] == 408 and validation["slot_count"] == 234
    graph = next(row for row in objects if row.kind.value == "GRAPH")
    policy = graph_statics.graph_statics_policy(trust_roots=["local-test-not-external-authority"])
    evidence = canonical_bytes({"schema_version": graph_statics.EVIDENCE_VERSION,
        "objects": [row.to_dict() for row in objects], "inputs": inputs})
    from verifier.runtime.self_polish_estate import bytes_digest
    request = graph_statics.graph_statics_request(subject_id=graph.object_id, object_digest=graph.digest,
        collection_digest=composition_digest(objects), nodes_digest=value_digest(inputs["nodes"]),
        edges_digest=value_digest(inputs["edges"]), evidence_ref=bytes_digest(evidence), policy=policy)
    certificate = graph_statics.build_graph_statics_certificate(request, evidence, policy=policy)
    assert graph_statics.recheck_graph_statics_certificate(certificate,
        expected_request=request, policy=policy)["status"] == "PASS"


def test_version_three_still_rejects_reinterpreting_its_payload() -> None:
    document, _ = graph_representation(envelope())
    document["schema_version"] = "verifier-objects-manifest-3"
    document.pop("representation_updates")
    with pytest.raises(ValueError, match="PACKAGE_NAMESPACE_PAYLOAD_CHANGED"):
        select(document)


def test_version_five_preserves_version_four_representation_semantics() -> None:
    document, _ = graph_representation(envelope())
    document["schema_version"] = package_manifest.PACKAGE_REPRESENTATION_SCHEMA
    retained, validation, objects = select(document)
    assert retained["schema_version"] == tier_zero_manifest.MANIFEST_SCHEMA
    assert validation["status"] == "PASS"
    assert len(objects) == len(document["namespace"]["objects"])


@pytest.mark.parametrize("mutation,code", [
    (lambda d: d["representation_updates"].clear(), "DENOMINATOR_DIFFERS"),
    (lambda d: d["representation_updates"].append(deepcopy(d["representation_updates"][0])), "OBJECT_INVALID"),
    (lambda d: d["representation_updates"][0].update(retained_object_digest="sha256:" + "0" * 64), "DIGEST_DIFFERS"),
    (lambda d: d["representation_updates"][0].update(current_object_digest="sha256:" + "0" * 64), "DIGEST_DIFFERS"),
    (lambda d: d["representation_updates"][0].update(reason=" "), "REASON_REQUIRED"),
    (lambda d: d["representation_updates"][0].update(object_id="not-declared"), "OBJECT_INVALID"),
    (lambda d: d["representation_updates"][0]["evidence"][0].update(path="../outside.py"), "PATH_INVALID"),
    (lambda d: d["representation_updates"][0].update(status="PASS"), "FIELDS"),
    (lambda d: d["obligation_denominator"].update(route_count=407), "DENOMINATOR"),
    (lambda d: next(r for r in d["namespace"]["objects"] if r["kind"] == "SIM")["operands"].update(verifier=["vstd-package-object"]), "EDGES_CHANGED"),
])
@pytest.mark.parametrize(
    "schema_version",
    ["verifier-objects-manifest-4", package_manifest.PACKAGE_REPRESENTATION_SCHEMA],
)
def test_current_payload_selection_cannot_drop_obligations_or_forge_history(
        mutation: Callable[[dict[str, Any]], None], code: str,
        schema_version: str) -> None:
    document, _ = graph_representation(envelope())
    document["schema_version"] = schema_version
    mutation(document)
    with pytest.raises(ValueError, match=code):
        select(document)


def test_new_manifest_schema_is_exact_and_does_not_change_old_schema() -> None:
    import json
    import jsonschema
    from referencing import Registry, Resource
    root = Path(__file__).parents[1] / "src/verifier/schemas"
    schemas = [json.loads((root / f"verifier-objects-manifest-{index}.schema.json").read_bytes()) for index in (2, 3, 4, 5)]
    registry = Registry().with_resources((schema["$id"], Resource.from_contents(schema)) for schema in schemas)
    document, _ = graph_representation(envelope())
    jsonschema.Draft202012Validator(schemas[2], registry=registry).validate(document)
    package_document = deepcopy(document)
    package_document["schema_version"] = package_manifest.PACKAGE_REPRESENTATION_SCHEMA
    jsonschema.Draft202012Validator(schemas[3], registry=registry).validate(package_document)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schemas[1], registry=registry).validate(document)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schemas[2], registry=registry).validate(package_document)


def prepare_selected_graph(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    import json
    import subprocess
    from verifier.runtime.self_polish_estate import bytes_digest
    from verifier.runtime.namespace_contracts import namespace_registry, registry_document
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    retained = json.loads((root / "objects.vstd").read_bytes())
    rows = [{**item.to_dict(), "specializations": [], "surfaces": [], "reason": "Retained test representation.",
             "classification": {}, "obligations": {}} for item in tier_zero_manifest._namespace_objects(retained["objects"])]
    document, inputs = graph_representation({**retained, "schema_version": package_manifest.SCHEMA, "namespace": {
        "schema_version": "verifier-objects-manifest-2", "extensions": [], "objects": rows,
        "registry_digest": registry_document(namespace_registry())["digest"]}})
    (root / "graph.py").write_text("raise RuntimeError('do not execute subject')\n", encoding="utf-8")
    reference = {"path": "graph.py", "sha256": bytes_digest((root / "graph.py").read_bytes())}
    document["representation_updates"][0]["evidence"] = [reference]
    return document, inputs, reference


def select_graph_evidence(root: Path, document: dict[str, Any], inputs: dict[str, Any], ref: dict[str, Any]) -> None:
    from verifier.runtime.self_polish_estate import bytes_digest
    objects = package_manifest.validate_bridge(document)
    graph = next(row for row in objects if row.object_id == "vstd-package-graph")
    policy = graph_statics.graph_statics_policy(trust_roots=["local-test-not-external-authority"])
    evidence = canonical_bytes({"schema_version": graph_statics.EVIDENCE_VERSION,
        "objects": [row.to_dict() for row in objects], "inputs": inputs})
    request = graph_statics.graph_statics_request(subject_id=graph.object_id, object_digest=graph.digest,
        collection_digest=composition_digest(objects), nodes_digest=value_digest(inputs["nodes"]),
        edges_digest=value_digest(inputs["edges"]), evidence_ref=bytes_digest(evidence), policy=policy)
    certificate = graph_statics.build_graph_statics_certificate(request, evidence, policy=policy)
    assert graph_statics.recheck_graph_statics_certificate(certificate, expected_request=request, policy=policy)["status"] == "PASS"
    check = {"object_id": graph.object_id, "coordinate": request["coordinate"],
        "semantic_version": request["semantic_version"], "proposition_digest": request["proposition_digest"],
        "reason": "The root claims complete declared operand dependencies, requiring exact retained edge statics.", "evidence": [ref]}
    for name, raw in (("request", canonical_bytes(request)), ("policy", canonical_bytes(policy)), ("certificate", certificate)):
        path = name + ".json"
        (root / path).write_bytes(raw)
        check[name] = {"path": path, "sha256": bytes_digest(raw)}
    document["namespace"]["instance_checks"] = [check]
    (root / "objects.vstd").write_bytes(canonical_bytes(document) + b"\n")


def test_exact_root_dependency_graph_has_real_focused_gate_evidence(selected_root: Path) -> None:
    from verifier.runtime.manifest_gate import assess_object_gate, obligation_catalog
    from verifier.runtime.package_graph_representation import dependency_inputs
    document, inputs, ref = prepare_selected_graph(selected_root)
    assert dependency_inputs(package_manifest.validate_bridge(document), "vstd-package-graph") == inputs
    select_graph_evidence(selected_root, document, inputs, ref)
    # Remigration enriches the package GRAPH and thereby makes the retained
    # request/certificate stale.  The focused adapter must use the exact current
    # graph without opening those historical route artifacts.
    bind_current_package_graph_source_fields(document)
    for name in ("request.json", "policy.json", "certificate.json"):
        (selected_root / name).write_bytes(b"stale route artifact must not be read")
    (selected_root / "objects.vstd").write_bytes(canonical_bytes(document) + b"\n")
    identifier = next(row["obligation_id"] for row in obligation_catalog() if row["coordinate"] == "GRAPH-3.1")
    result = assess_object_gate("vstd-package-graph", identifier, selected_root)
    assert result["status"] == "PASS", result["findings"]
    assert "every selected member and operand reference" in result["instance"]["applicability"]["reason"]
    selected = result["instance"]["selected_package_check"]
    assert selected["adapter_id"] == "verifier-fresh-package-graph-statics-projection-1"
    assert selected["evidence_origin"] == "PACKAGE_GRAPH_BOUND_FRESH_REPLAY"
    assert result["instance"]["package_graph_replay_is_instance_evidence"] is True
    assert selected["selection_digest"] == value_digest(selected["selection"])
    result_binding = deepcopy(selected)
    assert result_binding.pop("result_digest") == value_digest(result_binding)
    assert selected["selection"]["original_object_digest"] != selected["selection"]["projected_object_digest"]
    assert selected["selection"]["original_collection_digest"] != selected["selection"]["projected_collection_digest"]
    assert selected["selection"]["nodes_digest"] == value_digest(inputs["nodes"])
    assert selected["selection"]["edges_digest"] == value_digest(inputs["edges"])
    assert not result["polished"] and not result["release_authorized"]


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("nodes_digest", "PACKAGE_GRAPH_DEPENDENCY_COMMITMENT_DIFFERS"),
        ("edges_digest", "PACKAGE_GRAPH_DEPENDENCY_COMMITMENT_DIFFERS"),
        ("unexpected", "PACKAGE_GRAPH_PAYLOAD_FIELDS_DIFFER"),
    ],
)
def test_fresh_package_graph_projection_rejects_forged_or_extra_payload(
    selected_root: Path, mutation: str, reason: str
) -> None:
    from verifier.runtime.manifest_gate import assess_object_gate, obligation_catalog

    document, inputs, ref = prepare_selected_graph(selected_root)
    select_graph_evidence(selected_root, document, inputs, ref)
    bind_current_package_graph_source_fields(document)
    graph = next(
        row for row in document["namespace"]["objects"]
        if row["object_id"] == "vstd-package-graph"
    )
    graph["payload"][mutation] = (
        "unexpected" if mutation == "unexpected" else "sha256:" + "0" * 64
    )
    update = next(
        row for row in document["representation_updates"]
        if row["object_id"] == graph["object_id"]
    )
    update["current_object_digest"] = NamespaceObject.create(
        graph["object_id"], graph["kind"], graph["payload"], graph["operands"]
    ).digest
    (selected_root / "objects.vstd").write_bytes(canonical_bytes(document) + b"\n")
    identifier = next(
        row["obligation_id"] for row in obligation_catalog()
        if row["coordinate"] == "GRAPH-3.1"
    )

    report = assess_object_gate("vstd-package-graph", identifier, selected_root)

    assert report["status"] == "FAIL"
    selected = report["instance"]["selected_package_check"]
    assert selected["evidence_origin"] == "PACKAGE_GRAPH_BOUND_FRESH_REPLAY"
    assert selected["reason"] == reason


def test_non_package_graph_keeps_manifest_selected_evidence_path(
    selected_root: Path,
) -> None:
    from verifier.runtime.manifest_gate import obligation_catalog
    from verifier.runtime.package_instance_evidence import InstanceEvidence

    document, inputs, ref = prepare_selected_graph(selected_root)
    select_graph_evidence(selected_root, document, inputs, ref)
    objects = package_manifest.validate_bridge(document)
    graph = next(row for row in objects if row.object_id == "vstd-package-graph")
    route = next(
        row for row in obligation_catalog() if row["coordinate"] == "GRAPH-3.1"
    )
    evidence = InstanceEvidence(
        selected_root,
        objects,
        document["namespace"],
        package_graph_id="a-different-package-root",
        representation_updates=document["representation_updates"],
    )

    selected = evidence.evaluate(graph, route)

    assert selected is not None and selected["status"] == "PASS"
    assert selected["evidence_origin"] == "MANIFEST_SELECTED_INSTANCE"
    assert {"request.json", "policy.json", "certificate.json"} <= set(
        evidence.captured
    )


def test_legacy_package_graph_without_source_bindings_does_not_invent_selection(
    selected_root: Path,
) -> None:
    from verifier.runtime.manifest_gate import obligation_catalog
    from verifier.runtime.package_instance_evidence import InstanceEvidence

    document, _, _ = prepare_selected_graph(selected_root)
    document["namespace"]["instance_checks"] = []
    objects = package_manifest.validate_bridge(document)
    graph = next(row for row in objects if row.object_id == "vstd-package-graph")
    route = next(
        row for row in obligation_catalog() if row["coordinate"] == "GRAPH-3.1"
    )
    evidence = InstanceEvidence(
        selected_root,
        objects,
        document["namespace"],
        package_graph_id=graph.object_id,
        representation_updates=document["representation_updates"],
    )

    assert evidence.evaluate(graph, route) is None
    assert evidence.captured == {}


def test_consistent_native_certificate_with_omitted_dependency_is_refuted(selected_root: Path) -> None:
    from verifier.runtime.manifest_gate import assess_object_gate, obligation_catalog
    document, inputs, ref = prepare_selected_graph(selected_root)
    inputs["edges"].pop()
    graph = next(row for row in document["namespace"]["objects"] if row["kind"] == "GRAPH")
    graph["payload"]["edges_digest"] = value_digest(inputs["edges"])
    document["representation_updates"][0]["current_object_digest"] = NamespaceObject.create(
        graph["object_id"], graph["kind"], graph["payload"], graph["operands"]).digest
    select_graph_evidence(selected_root, document, inputs, ref)  # A real native PASS, but incomplete for this package claim.
    bind_current_package_graph_source_fields(document)
    (selected_root / "objects.vstd").write_bytes(canonical_bytes(document) + b"\n")
    identifier = next(row["obligation_id"] for row in obligation_catalog() if row["coordinate"] == "GRAPH-3.1")
    report = assess_object_gate("vstd-package-graph", identifier, selected_root)
    assert report["status"] == "FAIL"
    assert report["instance"]["selected_package_check"]["reason"] == "PACKAGE_GRAPH_DEPENDENCY_COMMITMENT_DIFFERS"


@pytest.mark.parametrize("stale", [False, True])
def test_representation_source_binding_is_checked_without_claiming_payload_truth(selected_root: Path, stale: bool) -> None:
    from verifier.runtime.namespace_admission import assess
    document, _, ref = prepare_selected_graph(selected_root)
    if stale:
        ref["sha256"] = "sha256:" + "0" * 64
    (selected_root / "objects.vstd").write_bytes(canonical_bytes(document) + b"\n")
    report = assess(selected_root)
    binding = report["representation_bindings"][0]
    assert binding["status"] == ("FAIL" if stale else "PASS")
    assert binding["semantic_fulfillment"] == "NOT_ESTABLISHED"
    assert report["independent_reconciliation"]["status"] == "PASS"
    if stale:
        assert any(row["code"] == "PACKAGE_REPRESENTATION_EVIDENCE_UNRESOLVED"
                   and row["object_id"] == "vstd-package-graph" for row in report["findings"])


def test_representation_without_owned_source_cannot_gain_a_focused_pass(selected_root: Path) -> None:
    from verifier.runtime.manifest_gate import assess_object_gate, obligation_catalog
    document, inputs, ref = prepare_selected_graph(selected_root)
    document["representation_updates"][0]["evidence"] = []
    select_graph_evidence(selected_root, document, inputs, ref)
    bind_current_package_graph_source_fields(document)
    (selected_root / "objects.vstd").write_bytes(canonical_bytes(document) + b"\n")
    identifier = next(row["obligation_id"] for row in obligation_catalog() if row["coordinate"] == "GRAPH-3.1")
    report = assess_object_gate("vstd-package-graph", identifier, selected_root)
    assert report["status"] == "UNKNOWN"
    assert report["instance"]["selected_package_check"]["reason"] == "PACKAGE_REPRESENTATION_OWNED_SOURCE_UNAVAILABLE"


def test_old_collection_certificate_cannot_transfer_to_current_graph(selected_root: Path) -> None:
    from test_package_instance_evidence import prepare
    from verifier.runtime.manifest_gate import assess_object_gate
    from verifier.runtime.self_polish_estate import bytes_digest
    old, _ = prepare(selected_root, typed=True)
    current, _ = graph_representation(old)
    (selected_root / "graph.py").write_text("pass\n", encoding="utf-8")
    current["representation_updates"][0]["evidence"][0]["sha256"] = bytes_digest((selected_root / "graph.py").read_bytes())
    (selected_root / "objects.vstd").write_bytes(canonical_bytes(current) + b"\n")
    report = assess_object_gate("vstd-package-object", "OBJECT-1.2-declared-operand-facets", selected_root)
    assert report["status"] == "FAIL"
    assert report["instance"]["selected_package_check"]["reason"] == "PACKAGE_INSTANCE_SUBJECT_OR_GRAPH_DIFFERS"


def test_coverage_refresh_keeps_current_payload_and_its_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from test_package_namespace_migration import _add_discovered_files, _migration_fixture
    module, retained = _migration_fixture(tmp_path, monkeypatch)
    observed = _add_discovered_files(tmp_path, monkeypatch, ("graph.py",))
    document, _ = graph_representation(module.migrate(tmp_path, retained))
    reference = next(row for row in observed["census"]["files"] if row["path"] == "graph.py")
    document["representation_updates"][0]["evidence"] = [deepcopy(reference)]
    result = module.migrate(tmp_path, document, refresh_unresolved=True)
    assert result["schema_version"] == "verifier-objects-manifest-4"
    assert result["representation_updates"] == document["representation_updates"]
    assert [row["payload"] for row in result["namespace"]["objects"]] == [row["payload"] for row in document["namespace"]["objects"]]


def test_independent_reconciler_refutes_forged_representation_ancestry(selected_root: Path) -> None:
    from verifier.runtime import namespace_admission, namespace_classification, namespace_discovery
    from verifier.runtime.namespace_contracts import namespace_registry
    document, _, _ = prepare_selected_graph(selected_root)
    observed = namespace_discovery.discover(selected_root)
    registry = namespace_registry()
    namespace = document["namespace"]
    classified = namespace_classification.assess_classification(namespace["objects"], registry, observed)
    raw = canonical_bytes(namespace) + b"\n"
    representations = {"updates": document["representation_updates"], "retained_objects": [
        row.to_dict() for row in tier_zero_manifest._namespace_objects(document["objects"])]}
    assert namespace_admission._reconcile(raw, registry, observed, classified, representations=representations)["status"] == "PASS"
    representations["updates"][0]["retained_object_digest"] = "sha256:" + "0" * 64
    assert namespace_admission._reconcile(raw, registry, observed, classified, representations=representations)["status"] == "FAIL"
