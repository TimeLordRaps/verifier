"""Current architecture (ARCH) finite tensor-shape checks.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Dimensions and element counts are dimensionless.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import arch_shapes


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def graph() -> dict:
    return {"nodes": [
        {"name": "x", "op": "INPUT", "inputs": [], "shape": [2, 3]},
        {"name": "w", "op": "INPUT", "inputs": [], "shape": [3, 4]},
        {"name": "product", "op": "MATMUL", "inputs": ["x", "w"], "shape": [2, 4]},
        {"name": "bias", "op": "INPUT", "inputs": [], "shape": [2, 4]},
        {"name": "sum", "op": "ADD", "inputs": ["product", "bias"], "shape": [2, 4]},
        {"name": "out", "op": "RELU", "inputs": ["sum"], "shape": [2, 4]},
    ], "outputs": ["out"]}


def selected(*, retained: dict | None = None, include_inputs: bool = True,
             payload_digest: str | None = None, **limits: int):
    retained = deepcopy(graph() if retained is None else retained)
    subject = NamespaceObject.create("arch-root", "ARCH", {
        "scope": "retained-static-tensor-graph",
        "graph_digest": payload_digest or digest(retained),
    })
    evidence = canonical_bytes({
        "schema_version": arch_shapes.EVIDENCE_VERSION,
        "objects": [subject.to_dict()],
        "inputs": {"graph": retained} if include_inputs else None,
    })
    policy = arch_shapes.arch_shapes_policy(trust_roots=["test:selected-graph"])
    request = arch_shapes.arch_shapes_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits)
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = arch_shapes.build_arch_shapes_certificate(request, evidence, policy=policy)
    return certificate, routes.replay_current_object_certificate(
        certificate, semantic_version=arch_shapes.SEMANTIC_VERSION,
        objective=arch_shapes.COORDINATE, represented_kind="ARCH",
        expected_request=request, policy=policy)


def replay_with_selected_payload(payload: dict, retained: dict,
                                 input_mode: str = "present") -> str:
    subject = NamespaceObject.create("arch-precedence", "ARCH", payload)
    inputs = ({"graph": retained} if input_mode == "present" else
              {"graph": None} if input_mode == "null-graph" else None)
    evidence = canonical_bytes({
        "schema_version": arch_shapes.EVIDENCE_VERSION,
        "objects": [subject.to_dict()], "inputs": inputs,
    })
    policy = arch_shapes.arch_shapes_policy(trust_roots=["test:precedence"])
    request = arch_shapes.arch_shapes_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        evidence_ref=digest(json.loads(evidence)), policy=policy)
    return replay(request, policy, evidence)[1]["computational_status"]


@pytest.mark.parametrize("payload_mode", ["valid", "wrong-scope", "extra-field", "malformed-digest"])
@pytest.mark.parametrize("input_mode", ["present", "null-inputs", "null-graph"])
def test_present_payload_contradictions_survive_missing_inputs(payload_mode: str, input_mode: str):
    retained = graph()
    payload = {"scope": "retained-static-tensor-graph", "graph_digest": digest(retained)}
    if payload_mode == "wrong-scope":
        payload["scope"] = "different-scope"
    elif payload_mode == "extra-field":
        payload["unexpected"] = True
    elif payload_mode == "malformed-digest":
        payload["graph_digest"] = "not-a-byte-commitment"
    expected = "FAIL" if payload_mode != "valid" else "PASS" if input_mode == "present" else "UNKNOWN"
    assert replay_with_selected_payload(payload, retained, input_mode) == expected


@pytest.mark.parametrize("mutation", ["valid", "invalid-dimension", "unsupported-op", "unknown-input"])
@pytest.mark.parametrize("outputs", ["present", "empty"])
def test_present_node_contradictions_survive_missing_outputs(mutation: str, outputs: str):
    retained = graph()
    if mutation == "invalid-dimension":
        retained["nodes"][0]["shape"][0] = 0
    elif mutation == "unsupported-op":
        retained["nodes"][0]["op"] = "UNSELECTED"
    elif mutation == "unknown-input":
        retained["nodes"][2]["inputs"][0] = "unselected-input"
    if outputs == "empty":
        retained["outputs"] = []
    payload = {"scope": "retained-static-tensor-graph", "graph_digest": digest(retained)}
    expected = "FAIL" if mutation != "valid" else "PASS" if outputs == "present" else "UNKNOWN"
    assert replay_with_selected_payload(payload, retained) == expected


def test_selected_output_without_retained_node_refutes_but_empty_pair_is_unknown():
    retained = {"nodes": [], "outputs": ["missing"]}
    payload = {"scope": "retained-static-tensor-graph", "graph_digest": digest(retained)}
    assert replay_with_selected_payload(payload, retained) == "FAIL"
    retained["outputs"] = []
    payload["graph_digest"] = digest(retained)
    assert replay_with_selected_payload(payload, retained) == "UNKNOWN"


def test_matmul_add_relu_shapes_are_recomputed_and_bounded():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["computational_status"] == "PASS"
    native = result["native_result"]
    assert native["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert native["execution_equivalence"] == "NOT_ESTABLISHED"
    assert certificate == arch_shapes.build_arch_shapes_certificate(request, evidence, policy=policy)


@pytest.mark.parametrize("change", [
    lambda g: g["nodes"][2]["shape"].__setitem__(1, 5),
    lambda g: g["nodes"][1]["shape"].__setitem__(0, 5),
    lambda g: g["nodes"][4]["shape"].__setitem__(0, 3),
    lambda g: g["nodes"][5]["inputs"].__setitem__(0, "missing"),
    lambda g: g["nodes"][5]["inputs"].__setitem__(0, "out"),
    lambda g: g["nodes"][5].__setitem__("op", "CUSTOM"),
    lambda g: g["nodes"][5]["shape"].__setitem__(0, True),
    lambda g: g["nodes"][5]["shape"].__setitem__(0, 0),
    lambda g: g["nodes"][5]["shape"].__setitem__(0, 2**53),
    lambda g: g["nodes"][5].__setitem__("name", "sum"),
    lambda g: g["outputs"].__setitem__(0, "missing"),
])
def test_rehashed_inconsistent_shapes_or_graph_fail(change):
    retained = graph()
    change(retained)
    request, policy, evidence = selected(retained=retained)
    assert replay(request, policy, evidence)[1]["computational_status"] == "FAIL"


def test_disconnected_node_and_duplicate_output_fail():
    retained = graph()
    retained["nodes"].append({"name": "orphan", "op": "INPUT", "inputs": [], "shape": [1]})
    request, policy, evidence = selected(retained=retained)
    assert replay(request, policy, evidence)[1]["computational_status"] == "FAIL"
    retained = graph()
    retained["outputs"] = ["out", "out"]
    request, policy, evidence = selected(retained=retained)
    assert replay(request, policy, evidence)[1]["computational_status"] == "FAIL"


def test_consistent_tensor_renaming_and_equal_shape_add_commutation():
    original = graph()
    variants = [deepcopy(original), deepcopy(original)]
    variants[0]["nodes"][0]["name"] = "input-renamed"
    variants[0]["nodes"][2]["inputs"][0] = "input-renamed"
    variants[1]["nodes"][4]["inputs"].reverse()
    for retained in variants:
        request, policy, evidence = selected(retained=retained)
        assert replay(request, policy, evidence)[1]["computational_status"] == "PASS"


def test_rehashed_graph_digest_substitution_fails():
    request, policy, evidence = selected(payload_digest=digest({"different": True}))
    assert replay(request, policy, evidence)[1]["computational_status"] == "FAIL"


def test_missing_inputs_and_exhausted_budgets_remain_unknown():
    request, policy, evidence = selected(include_inputs=False)
    assert replay(request, policy, evidence)[1]["computational_status"] == "UNKNOWN"
    request, policy, evidence = selected()
    assert replay(request, policy, None)[1]["computational_status"] == "UNKNOWN"
    for field in ("max_operations", "max_items", "max_evidence_bytes",
                  "max_composition_operations", "max_payload_bytes"):
        request, policy, evidence = selected(**{field: 1})
        assert replay(request, policy, evidence)[1]["computational_status"] == "UNKNOWN"


def test_external_selection_and_rehashed_result_substitution_refuse():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    wrong = deepcopy(request)
    wrong["subject_id"] = "different"
    with pytest.raises(ValueError):
        arch_shapes.recheck_arch_shapes_certificate(certificate, expected_request=wrong, policy=policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(ValueError):
        arch_shapes.recheck_arch_shapes_certificate(canonical_bytes(forged), expected_request=request, policy=policy)


def test_public_route_and_polish_preserve_unknown_aggregate(tmp_path, capsys):
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish
    request, policy, evidence = selected()
    certificate = arch_shapes.build_arch_shapes_certificate(request, evidence, policy=policy)
    for name, value in (("request", canonical_bytes(request)),
                        ("policy", canonical_bytes(policy)), ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(value)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
                 "--semantic-version", arch_shapes.SEMANTIC_VERSION,
                 "--objective", arch_shapes.COORDINATE, "--represented-kind", "ARCH",
                 "--request", str(tmp_path / "request.json"),
                 "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    cd = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(evidence)["objects"],
              "certificates": {cd: certificate.decode()}}
    polished_request = {"schema_version": "verifier-polish-request-1",
                        "root_id": "arch-root", "collection_digest": request["collection_digest"],
                        "bundle_digest": digest(bundle),
                        "requirements": [{"object_id": "arch-root", "tier": tier,
                                          "applicability": "REQUIRED", "rationale": "Selected tensor graph only",
                                          "objectives": []} for tier in range(1, 10)]}
    polished_request["requirements"][2]["objectives"] = [{
        "semantic_version": arch_shapes.SEMANTIC_VERSION,
        "coordinate": arch_shapes.COORDINATE,
        "request": request, "policy": policy, "certificate_digest": cd}]
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(polished_request))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["status"] == "UNKNOWN" and report["polished"] is False
