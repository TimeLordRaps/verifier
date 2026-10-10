"""Current retained HARDWARE containment is distinct from declared inventory.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Topology is a finite containment graph, not a
statement about physical wiring or permitted cyclic communication networks.
The graphics processing unit (GPU) is a retained device kind in the fixtures.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import hardware_topology


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def selected(*, devices: list[dict] | None = None,
             topology: list[dict] | None = None, include_inputs: bool = True,
             **limits: int):
    devices = devices if devices is not None else [
        {"id": "rack", "kind": "OTHER", "capacities": {"COMPUTE_SLOT": 1}},
        {"id": "gpu", "kind": "GPU", "capacities": {"MEMORY_BYTE": 8}},
        {"id": "store", "kind": "STORAGE", "capacities": {"STORAGE_BYTE": 20}},
    ]
    topology = topology if topology is not None else [
        {"parent": "rack", "child": "gpu"},
        {"parent": "rack", "child": "store"},
    ]
    subject = NamespaceObject.create("hardware-root", "HARDWARE", {
        "scope": "retained-hardware-records",
        "devices_digest": digest(devices),
        "topology_digest": digest(topology),
    })
    objects = [subject]
    evidence = canonical_bytes({
        "schema_version": hardware_topology.EVIDENCE_VERSION,
        "objects": [subject.to_dict()],
        "inputs": {"devices": devices, "topology": topology} if include_inputs else None,
    })
    policy = hardware_topology.hardware_topology_policy(
        trust_roots=["selected-retained-records"])
    request = hardware_topology.hardware_topology_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits,
    )
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes):
    certificate = hardware_topology.build_hardware_topology_certificate(
        request, evidence, policy=policy)
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=hardware_topology.SEMANTIC_VERSION,
        objective=hardware_topology.COORDINATE, represented_kind="HARDWARE",
        expected_request=request, policy=policy)
    return certificate, result


def test_exact_retained_containment_replays_without_physical_promotion():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["computational_status"] == "PASS"
    assert result["native_result"]["evaluation"]["observations"]["hardware"]["edges"] == 2
    assert result["native_result"]["physical_authenticity"] == "NOT_ESTABLISHED"
    assert result["native_result"]["live_availability"] == "NOT_ESTABLISHED"
    assert result["native_result"]["credit_authority"] == "NOT_ESTABLISHED"
    assert result["native_result"]["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert certificate == hardware_topology.build_hardware_topology_certificate(
        request, evidence, policy=policy)
    inventory_route = routes.select_current_object_route(
        semantic_version=hardware_topology.SEMANTIC_VERSION,
        objective="HARDWARE-1.3", represented_kind="HARDWARE")
    topology_route = routes.select_current_object_route(
        semantic_version=hardware_topology.SEMANTIC_VERSION,
        objective="HARDWARE-1.2", represented_kind="HARDWARE")
    assert inventory_route.module is not topology_route.module


def test_empty_exact_topology_is_admissible_with_real_inventory():
    request, policy, evidence = selected(topology=[])
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "PASS"
    assert result["native_result"]["evaluation"]["observations"]["hardware"]["edges"] == 0


def test_edge_order_changes_commitment_but_not_acyclic_result():
    first = [{"parent": "rack", "child": "gpu"},
             {"parent": "rack", "child": "store"}]
    second = list(reversed(first))
    first_request, first_policy, first_evidence = selected(topology=first)
    second_request, second_policy, second_evidence = selected(topology=second)
    first_cert, first_result = replay(first_request, first_policy, first_evidence)
    second_cert, second_result = replay(second_request, second_policy,
                                      second_evidence)
    assert first_request["object_digest"] != second_request["object_digest"]
    assert first_cert != second_cert
    assert first_result["computational_status"] == second_result["computational_status"] == "PASS"


def test_disconnected_inventory_and_longer_cycle_have_distinct_outcomes():
    request, policy, evidence = selected(topology=[{"parent": "rack", "child": "gpu"}])
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "PASS"
    request, policy, evidence = selected(topology=[
        {"parent": "rack", "child": "gpu"},
        {"parent": "gpu", "child": "store"},
        {"parent": "store", "child": "rack"},
    ])
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "FAIL"


@pytest.mark.parametrize("edges", [
    [{"parent": "rack", "child": "gpu"}, {"parent": "gpu", "child": "rack"}],
    [{"parent": "rack", "child": "rack"}],
    [{"parent": "rack", "child": "missing"}],
    [{"parent": "rack", "child": "gpu"}, {"parent": "rack", "child": "gpu"}],
])
def test_cycle_self_edge_unresolved_or_duplicate_containment_fails(edges):
    request, policy, evidence = selected(topology=edges)
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "FAIL"


def test_changed_retained_edge_bytes_fail_against_selected_subject():
    request, policy, evidence = selected()
    changed = json.loads(evidence)
    changed["inputs"]["topology"][0]["child"] = "store"
    with pytest.raises(hardware_topology.HardwareTopologyError, match="evidence differs"):
        hardware_topology.build_hardware_topology_certificate(
            request, canonical_bytes(changed), policy=policy)
    request["evidence_ref"] = digest(changed)
    _, result = replay(request, policy, canonical_bytes(changed))
    assert result["computational_status"] == "FAIL"


def test_missing_inputs_remain_unknown_and_budget_exhaustion_does_not_pass():
    request, policy, evidence = selected(include_inputs=False)
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "UNKNOWN"
    request, policy, evidence = selected(max_operations=1)
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "UNKNOWN"


def test_external_selection_and_carried_result_substitution_are_refused():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    changed_request = deepcopy(request)
    changed_request["subject_id"] = "another"
    with pytest.raises(ValueError):
        routes.replay_current_object_certificate(
            certificate, semantic_version=hardware_topology.SEMANTIC_VERSION,
            objective=hardware_topology.COORDINATE, represented_kind="HARDWARE",
            expected_request=changed_request, policy=policy)
    changed_policy = deepcopy(policy)
    changed_policy["trust_roots"] = ["another"]
    with pytest.raises(ValueError):
        routes.replay_current_object_certificate(
            certificate, semantic_version=hardware_topology.SEMANTIC_VERSION,
            objective=hardware_topology.COORDINATE, represented_kind="HARDWARE",
            expected_request=request, policy=changed_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    with pytest.raises(ValueError):
        routes.replay_current_object_certificate(
            canonical_bytes(forged), semantic_version=hardware_topology.SEMANTIC_VERSION,
            objective=hardware_topology.COORDINATE, represented_kind="HARDWARE",
            expected_request=request, policy=policy)


def test_public_command_replays_topology_without_promoting_physical_claim(tmp_path, capsys):
    from verifier.runtime.public_cli import main

    request, policy, evidence = selected()
    for name, data in {
        "request": canonical_bytes(request), "policy": canonical_bytes(policy),
        "certificate": hardware_topology.build_hardware_topology_certificate(
            request, evidence, policy=policy),
    }.items():
        (tmp_path / (name + ".json")).write_bytes(data)
    exit_code = main([
        "current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", hardware_topology.SEMANTIC_VERSION,
        "--objective", hardware_topology.COORDINATE,
        "--represented-kind", "HARDWARE",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json",
    ])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["physical_authenticity"] == "NOT_ESTABLISHED"


def test_canonical_certificate_refuses_retained_edge_redaction():
    from verifier.privacy import (
        DisclosureSurface, DisclosureBound, ObserverParty, EmissionContext,
        EmissionEvaluator, EmissionRefusalError)

    request, policy, evidence = selected()
    certificate = json.loads(hardware_topology.build_hardware_topology_certificate(
        request, evidence, policy=policy))
    fields = tuple(key for key in certificate if key != "evidence_payloads")
    surface = DisclosureSurface("HARDWARE", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(certificate, surface, bounds,
                                              context)


@pytest.mark.parametrize("relative", [
    "domains/contracts/hardware_topology.py", "domains/hardware.py",
    "standard/CURRENT_HARDWARE_TOPOLOGY.md", "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate = hardware_topology.build_hardware_topology_certificate(
        request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(hardware_topology.__file__).parents[2] / relative

    def changed(path):
        data = original(path)
        return data + b"\nchanged topology dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        hardware_topology.recheck_hardware_topology_certificate(
            certificate, expected_request=request, policy=policy)


def test_topology_dependencies_invalidate_polish_mechanism(monkeypatch):
    from verifier.runtime import polish

    original = Path.read_bytes
    target = Path(polish.__file__).parents[1] / "domains/contracts/hardware_topology.py"
    before = polish.mechanism_digest()

    def changed(path):
        data = original(path)
        return data + b"\nchanged topology dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


def test_topology_objective_pass_leaves_polish_unknown():
    from verifier.runtime.polish import assess_polish

    request, policy, evidence = selected()
    certificate = hardware_topology.build_hardware_topology_certificate(
        request, evidence, policy=policy)
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(evidence)["objects"],
              "certificates": {digest(json.loads(certificate)): certificate.decode()}}
    selected_request = {
        "schema_version": "verifier-polish-request-1",
        "root_id": "hardware-root", "collection_digest": request["collection_digest"],
        "bundle_digest": digest(bundle),
        "requirements": [{"object_id": "hardware-root", "tier": tier,
                          "applicability": "REQUIRED",
                          "rationale": "Selected retained containment only",
                          "objectives": []} for tier in range(1, 10)],
    }
    selected_request["requirements"][0]["objectives"] = [{
        "semantic_version": hardware_topology.SEMANTIC_VERSION,
        "coordinate": hardware_topology.COORDINATE, "request": request,
        "policy": policy, "certificate_digest": digest(json.loads(certificate)),
    }]
    report = assess_polish(canonical_bytes(bundle),
                           request_bytes=canonical_bytes(selected_request))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert report["status"] == "UNKNOWN" and report["polished"] is False
