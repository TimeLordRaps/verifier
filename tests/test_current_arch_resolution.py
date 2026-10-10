"""Adversarial declared architecture operator-reference closure tests.

Terminology: JavaScript Object Notation (JSON).
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import arch_resolution as resolution


def _digest(value: Any) -> str:
    return "sha256:" + canonical_digest(value)


def _definition(name: str, arity: int, dependencies: list[dict[str, str]] | None = None
                ) -> dict[str, Any]:
    return {"operator_name": name, "input_count": arity,
            "dependencies": dependencies or [], "body": {"retained_declaration": name}}


def _specimen() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    libraries = [
        {"schema_version": resolution.LIBRARY_VERSION, "library_id": "blas",
         "definitions": [_definition("DOT", 2)]},
        {"schema_version": resolution.LIBRARY_VERSION, "library_id": "core",
         "definitions": [_definition("INPUT", 0),
            _definition("MATMUL", 2, [{"library_id": "blas", "operator_name": "DOT"}]),
            _definition("MAX", 2),
            _definition("RELU", 1, [{"library_id": "core", "operator_name": "MAX"}])]},
    ]
    graph = {"nodes": [
        {"name": "x", "op": "INPUT", "inputs": [], "shape": [2, 3]},
        {"name": "w", "op": "INPUT", "inputs": [], "shape": [3, 4]},
        {"name": "product", "op": "MATMUL", "inputs": ["x", "w"], "shape": [2, 4]},
        {"name": "output", "op": "RELU", "inputs": ["product"], "shape": [2, 4]},
    ], "outputs": ["output"]}
    arch = NamespaceObject.create("selected-arch", "ARCH", {
        "scope": "retained-static-tensor-graph", "graph_digest": _digest(graph)})
    holder = NamespaceObject.create("retained-holder", "HYPER", {}, {"architecture": [arch.object_id]})
    value = {"schema_version": resolution.EVIDENCE_VERSION,
        "objects": [arch.to_dict(), holder.to_dict()], "graph": graph,
        "bindings": [{"op": name, "library_id": "core", "operator_name": name,
                      "definition_digest": "sha256:" + "0" * 64}
                     for name in ("INPUT", "MATMUL", "RELU")],
        "library_manifest": [], "libraries": [],
        "closure": [{"library_id": library["library_id"], "operator_name": definition["operator_name"],
                     "definition_digest": "sha256:" + "0" * 64, "library_digest": "sha256:" + "0" * 64}
                    for library in libraries for definition in library["definitions"]]}
    _seal(value, libraries)
    return value, libraries


def _seal(value: dict[str, Any], libraries: list[dict[str, Any]]) -> None:
    """Reselect all enclosing commitments without repairing membership or reference errors."""
    retained = []
    manifests = []
    definitions = {}
    byte_digests = {}
    for library in sorted(libraries, key=lambda item: item["library_id"]):
        data = canonical_bytes(library)
        identifier = library["library_id"]
        commitment = "sha256:" + hashlib.sha256(data).hexdigest()
        byte_digests[identifier] = commitment
        manifests.append({"library_id": identifier, "library_digest": commitment})
        retained.append({"library_id": identifier, "library_digest": commitment,
                         "base64": base64.b64encode(data).decode("ascii")})
        if type(library["definitions"]) is list:
            for definition in library["definitions"]:
                definitions[(identifier, definition["operator_name"])] = _digest(definition)
    value["libraries"], value["library_manifest"] = retained, manifests
    if value["bindings"] is not None:
        for row in value["bindings"]:
            key = (row["library_id"], row["operator_name"])
            if key in definitions:
                row["definition_digest"] = definitions[key]
    if value["closure"] is not None:
        for row in value["closure"]:
            key = (row["library_id"], row["operator_name"])
            if key in definitions:
                row["definition_digest"] = definitions[key]
            if row["library_id"] in byte_digests:
                row["library_digest"] = byte_digests[row["library_id"]]
    value["objects"][0]["payload"]["graph_digest"] = _digest(value["graph"])


def _selection(value: dict[str, Any] | None = None, *, limits: dict[str, int] | None = None
               ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    value = _specimen()[0] if value is None else value
    objects = [NamespaceObject.create(**row) for row in value["objects"]]
    arch = objects[0]
    data = canonical_bytes(value)
    policy = resolution.arch_resolution_policy(trust_roots=["independent-selection"])
    request = resolution.arch_resolution_request(subject_id=arch.object_id, object_digest=arch.digest,
        collection_digest=composition_digest(objects), graph_digest=arch.payload["graph_digest"],
        bindings_digest=_digest(value["bindings"]), library_manifest_digest=_digest(value["library_manifest"]),
        closure_digest=_digest(value["closure"]), evidence_ref="sha256:" + hashlib.sha256(data).hexdigest(),
        policy=policy, limits=limits)
    return request, policy, data


def _replay(request: dict[str, Any], policy: dict[str, Any], data: bytes | None
            ) -> tuple[dict[str, Any], bytes]:
    certificate = resolution.build_arch_resolution_certificate(request, data, policy=policy)
    result = resolution.recheck_arch_resolution_certificate(certificate,
        expected_request=request, policy=policy)
    return result, certificate


def _status(value: dict[str, Any]) -> dict[str, Any]:
    return _replay(*_selection(value))[0]


def fixture_for_integration(status: str) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    """Return an actual native instance for coordinator-owned public route replay."""
    if status not in ("PASS", "FAIL", "UNKNOWN"):
        raise ValueError("unsupported integration fixture status")
    value, libraries = _specimen()
    if status == "FAIL":
        libraries[1]["definitions"][1]["input_count"] = 1
        _seal(value, libraries)
    request, policy, data = _selection(value)
    certificate = resolution.build_arch_resolution_certificate(request,
        None if status == "UNKNOWN" else data, policy=policy)
    return certificate, request, policy


def _replace_library_bytes(value: dict[str, Any], identifier: str, data: bytes) -> None:
    commitment = "sha256:" + hashlib.sha256(data).hexdigest()
    for row in value["library_manifest"]:
        if row["library_id"] == identifier:
            row["library_digest"] = commitment
    for row in value["libraries"]:
        if row["library_id"] == identifier:
            row["library_digest"] = commitment
            row["base64"] = base64.b64encode(data).decode("ascii")
    for row in value["closure"]:
        if row["library_id"] == identifier:
            row["library_digest"] = commitment


def test_exact_transitive_operator_definitions_and_bytes_replay_without_promotion() -> None:
    request, policy, data = _selection()
    result, certificate = _replay(request, policy, data)
    assert result["status"] == "PASS"
    assert result["object_kind"] == "ARCH" and result["scope"] == resolution.SCOPE
    for field in ("whole_tier_conformance", "object_profile_conformance", "authority",
                  "actual_execution", "operator_truth_and_safety", "numerical_validity"):
        assert result[field] == "NOT_ESTABLISHED"
    assert result["broader_submodule_closure"] == "UNKNOWN"
    observations = result["evaluation"]["observations"]
    assert observations["reachable_definition_count"] == 5
    assert observations["operator_tag_count"] == 3
    assert observations["library_count"] == 2
    assert observations["architecture_namespace_cone_ids"] == ["selected-arch"]
    assert certificate == resolution.build_arch_resolution_certificate(request, data, policy=policy)


@pytest.mark.parametrize("mutation", [
    "definition-cycle", "definition-self-cycle", "dangling-definition", "unselected-library",
    "duplicate-dependency", "omitted-closure", "extra-closure", "duplicate-closure",
    "unsorted-closure", "omitted-tag", "extra-tag", "duplicate-tag", "unsorted-tags",
    "wrong-arity", "boolean-arity", "tensor-cycle", "tensor-dangling", "tensor-unreachable",
    "duplicate-node", "missing-output", "duplicate-output", "namespace-cycle",
])
def test_reselected_hashes_do_not_hide_reference_or_completeness_refutations(mutation: str) -> None:
    value, libraries = _specimen()
    core = libraries[1]["definitions"]
    if mutation == "definition-cycle":
        core[2]["dependencies"] = [{"library_id": "core", "operator_name": "RELU"}]
    elif mutation == "definition-self-cycle":
        core[0]["dependencies"] = [{"library_id": "core", "operator_name": "INPUT"}]
    elif mutation == "dangling-definition":
        core[1]["dependencies"] = [{"library_id": "core", "operator_name": "ABSENT"}]
    elif mutation == "unselected-library":
        core[1]["dependencies"] = [{"library_id": "unselected", "operator_name": "DOT"}]
    elif mutation == "duplicate-dependency":
        core[1]["dependencies"] *= 2
    elif mutation == "omitted-closure":
        value["closure"].pop(0)
    elif mutation == "extra-closure":
        value["closure"].append({"library_id": "core", "operator_name": "UNUSED",
            "definition_digest": "sha256:" + "0" * 64, "library_digest": "sha256:" + "0" * 64})
    elif mutation == "duplicate-closure":
        value["closure"].append(deepcopy(value["closure"][-1]))
    elif mutation == "unsorted-closure":
        value["closure"].reverse()
    elif mutation == "omitted-tag":
        value["bindings"].pop()
    elif mutation == "extra-tag":
        value["bindings"].append({"op": "UNUSED", "library_id": "core", "operator_name": "INPUT",
                                  "definition_digest": "sha256:" + "0" * 64})
    elif mutation == "duplicate-tag":
        value["bindings"].append(deepcopy(value["bindings"][-1]))
    elif mutation == "unsorted-tags":
        value["bindings"].reverse()
    elif mutation == "wrong-arity":
        core[1]["input_count"] = 1
    elif mutation == "boolean-arity":
        core[0]["input_count"] = False
    elif mutation == "tensor-cycle":
        value["graph"]["nodes"][0]["inputs"] = ["output"]
    elif mutation == "tensor-dangling":
        value["graph"]["nodes"][2]["inputs"] = ["x", "absent"]
    elif mutation == "tensor-unreachable":
        value["graph"]["outputs"] = ["x"]
    elif mutation == "duplicate-node":
        value["graph"]["nodes"][1]["name"] = "x"
    elif mutation == "missing-output":
        value["graph"]["outputs"] = ["absent"]
    elif mutation == "duplicate-output":
        value["graph"]["outputs"] *= 2
    elif mutation == "namespace-cycle":
        value["objects"][1]["operands"]["architecture"] = ["retained-holder"]
    _seal(value, libraries)
    result = _status(value)
    assert result["status"] == "FAIL", mutation
    if mutation in ("definition-cycle", "definition-self-cycle"):
        assert "contains a cycle" in result["evaluation"]["details"]
        assert "substitutes" not in result["evaluation"]["details"]


@pytest.mark.parametrize("missing", ["bundle", "objects", "graph", "bindings", "library_manifest",
    "libraries", "closure", "library-bytes", "library-entry", "definitions", "body", "version"])
def test_absent_and_unsupported_retained_definition_evidence_stays_unknown(missing: str) -> None:
    value, libraries = _specimen()
    request, policy, _ = _selection(value)
    if missing == "bundle":
        data = None
    else:
        if missing == "definitions":
            libraries[1]["definitions"] = None
            _seal(value, libraries)
        elif missing == "body":
            libraries[1]["definitions"][2]["body"] = None
            _seal(value, libraries)
        elif missing == "version":
            libraries[0]["schema_version"] = "unsupported-library-version"
            _seal(value, libraries)
        elif missing == "library-bytes":
            value["libraries"][0]["base64"] = None
        elif missing == "library-entry":
            value["libraries"].pop(0)
        else:
            value[missing] = None
        # Keep independently selected semantic commitments when the retained field is absent.
        if missing in ("definitions", "body", "version"):
            request, policy, data = _selection(value)
        else:
            data = canonical_bytes(value)
            request["evidence_ref"] = "sha256:" + hashlib.sha256(data).hexdigest()
    result = _replay(request, policy, data)[0]
    assert result["status"] == "UNKNOWN", missing


@pytest.mark.parametrize("unknown", ["library-bytes", "library-entry", "body", "version", "closure"])
def test_valid_hash_cycle_wins_over_missing_evidence(unknown: str) -> None:
    value, libraries = _specimen()
    libraries[1]["definitions"][2]["dependencies"] = [{"library_id": "core", "operator_name": "RELU"}]
    if unknown == "body":
        libraries[1]["definitions"][2]["body"] = None
    elif unknown == "version":
        libraries[0]["schema_version"] = "unsupported-version"
    _seal(value, libraries)
    if unknown == "library-bytes":
        value["libraries"][0]["base64"] = None
    elif unknown == "library-entry":
        value["libraries"].pop(0)
    elif unknown == "closure":
        value["closure"] = None
    result = _status(value)
    assert result["status"] == "FAIL"
    assert "contains a cycle" in result["evaluation"]["details"]
    assert "substitutes" not in result["evaluation"]["details"]


def test_known_reference_substitution_wins_over_missing_library_bytes() -> None:
    value, _ = _specimen()
    value["libraries"][0]["base64"] = None
    value["bindings"][1]["definition_digest"] = "sha256:" + "0" * 64
    result = _status(value)
    assert result["status"] == "FAIL"
    assert "substitutes selected definition" in result["evaluation"]["details"]


@pytest.mark.parametrize("unused_body", [{"opaque": "unused"}, None])
def test_unused_library_definition_does_not_enlarge_selected_closure(unused_body: Any) -> None:
    value, libraries = _specimen()
    definition = _definition("UNUSED", 0)
    definition["body"] = unused_body
    libraries[1]["definitions"].append(definition)
    _seal(value, libraries)
    result = _status(value)
    assert result["status"] == "PASS"
    assert result["evaluation"]["observations"]["reachable_definition_count"] == 5


def test_unused_selected_library_is_refuted() -> None:
    value, libraries = _specimen()
    libraries.append({"schema_version": resolution.LIBRARY_VERSION, "library_id": "unused",
                      "definitions": [_definition("OTHER", 0)]})
    _seal(value, libraries)
    result = _status(value)
    assert result["status"] == "FAIL"
    assert "unreachable library" in result["evaluation"]["details"]


def test_shape_and_opaque_body_truth_are_not_promoted() -> None:
    value, libraries = _specimen()
    value["graph"]["nodes"][-1]["shape"] = [999]
    libraries[1]["definitions"][0]["body"] = {"uninterpreted_reference": "unretained/proprietary"}
    _seal(value, libraries)
    result = _status(value)
    assert result["status"] == "PASS"
    assert result["numerical_validity"] == result["operator_truth_and_safety"] == "NOT_ESTABLISHED"
    assert result["broader_submodule_closure"] == "UNKNOWN"


@pytest.mark.parametrize("limit,value", [
    ("max_operations", 1), ("max_items", 1), ("max_objects", 1), ("max_nodes", 1),
    ("max_libraries", 1), ("max_definitions", 4), ("max_references", 1), ("max_depth", 2),
    ("max_composition_operations", 1), ("max_library_bytes", 1), ("max_total_library_bytes", 1),
    ("max_evidence_bytes", 1), ("max_payload_bytes", 1), ("max_reference_bytes", 1),
])
def test_selected_budget_exhaustion_is_unknown(limit: str, value: int) -> None:
    request, policy, data = _selection(limits={limit: value})
    assert _replay(request, policy, data)[0]["status"] == "UNKNOWN", limit


def test_exact_operation_budget_boundary() -> None:
    request, policy, data = _selection()
    result = _replay(request, policy, data)[0]
    operations = result["evaluation"]["observations"]["operations"]
    request["limits"]["max_operations"] = operations
    assert _replay(request, policy, data)[0]["status"] == "PASS"
    request["limits"]["max_operations"] = operations - 1
    assert _replay(request, policy, data)[0]["status"] == "UNKNOWN"


@pytest.mark.parametrize("field", ["coordinate", "object_kind", "semantic_version", "object_digest",
    "collection_digest", "graph_digest", "bindings_digest", "library_manifest_digest", "closure_digest",
    "policy_digest", "proposition_digest"])
def test_substituted_external_selection_is_rejected(field: str) -> None:
    request, policy, data = _selection()
    _, certificate = _replay(request, policy, data)
    request[field] = "sha256:" + "0" * 64 if field.endswith("digest") else "different"
    with pytest.raises(resolution.ArchResolutionError):
        resolution.recheck_arch_resolution_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("tamper", ["status", "scope", "observations", "evidence", "digest", "extra-field"])
def test_rehashed_certificate_tampering_is_rejected(tamper: str) -> None:
    request, policy, data = _selection()
    _, certificate = _replay(request, policy, data)
    value = json.loads(certificate)
    if tamper == "status":
        value["result"]["status"] = "UNKNOWN"
    elif tamper == "scope":
        value["result"]["whole_tier_conformance"] = "PASS"
    elif tamper == "observations":
        value["result"]["evaluation"]["observations"]["reachable_definition_count"] = 99
    elif tamper == "evidence":
        value["evidence_payloads"] = {}
    elif tamper == "extra-field":
        value["invented"] = True
    value["digest"] = _digest({key: item for key, item in value.items() if key != "digest"})
    if tamper == "digest":
        value["digest"] = "sha256:" + "0" * 64
    with pytest.raises(resolution.ArchResolutionError):
        resolution.recheck_arch_resolution_certificate(canonical_bytes(value),
            expected_request=request, policy=policy)


@pytest.mark.parametrize("contradiction", ["library-digest", "definition-digest", "raw-bytes",
    "noncanonical-library", "library-identity", "malformed-library", "malformed-base64", "omitted-field"])
def test_present_contradictory_retained_material_fails(contradiction: str) -> None:
    value, libraries = _specimen()
    if contradiction == "library-digest":
        value["closure"][0]["library_digest"] = "sha256:" + "0" * 64
    elif contradiction == "definition-digest":
        value["closure"][0]["definition_digest"] = "sha256:" + "0" * 64
    elif contradiction == "raw-bytes":
        value["libraries"][0]["base64"] = base64.b64encode(b"changed bytes").decode("ascii")
    elif contradiction == "noncanonical-library":
        _replace_library_bytes(value, "blas", json.dumps(libraries[0], indent=2).encode())
    elif contradiction == "library-identity":
        libraries[0]["library_id"] = "substituted"
        _replace_library_bytes(value, "blas", canonical_bytes(libraries[0]))
    elif contradiction == "malformed-library":
        _replace_library_bytes(value, "blas", b"not JSON")
    elif contradiction == "malformed-base64":
        value["libraries"][0]["base64"] = "!"
    elif contradiction == "omitted-field":
        del value["libraries"][0]["base64"]
    assert _status(value)["status"] == "FAIL", contradiction


def test_replaced_evidence_bytes_cannot_be_admitted() -> None:
    request, policy, data = _selection()
    with pytest.raises(resolution.ArchResolutionError):
        resolution.build_arch_resolution_certificate(request, data + b" ", policy=policy)


def test_registration_and_descriptor_bind_the_new_predicate() -> None:
    assert resolution.COORDINATE == "ARCH-4.1"
    assert resolution.PROPOSITION_DIGEST == _digest(resolution.registration())
    assert resolution.ArchResolutionDescriptor.PROPOSITION_DIGEST == resolution.PROPOSITION_DIGEST
    assert "definition dependencies resolve" in resolution.registration()["proposition"]
