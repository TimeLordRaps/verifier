"""Current HARDWARE-2.1 retained reservation accounting, not physical capacity.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); graphics processing unit (GPU). MEMORY_BYTE is
bytes, COMPUTE_SLOT is a dimensionless local count, and times are integer
microseconds on one declared clock.
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
from verifier.domains.contracts import hardware_capacity


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def selected(*, allocations: list[dict] | None = None,
             include_inputs: bool = True):
    devices = [
        {"id": "gpu-a", "kind": "GPU",
         "capacities": {"MEMORY_BYTE": 8, "COMPUTE_SLOT": 2}},
        {"id": "gpu-b", "kind": "GPU",
         "capacities": {"MEMORY_BYTE": 16}},
    ]
    if allocations is None:
        allocations = [
            {"id": "lease-a", "device": "gpu-a", "unit": "MEMORY_BYTE",
             "quantity": 8, "start_us": 0, "end_us": 10},
            {"id": "lease-b", "device": "gpu-a", "unit": "MEMORY_BYTE",
             "quantity": 8, "start_us": 10, "end_us": 20},
        ]
    payload = {"scope": "retained-hardware-records", "clock": "test-clock",
               "devices_digest": digest(devices),
               "allocations_digest": digest(allocations)}
    subject = NamespaceObject.create("hardware-a", "HARDWARE", payload)
    evidence = {"schema_version": hardware_capacity.EVIDENCE_VERSION,
                "objects": [subject.to_dict()],
                "inputs": {"devices": devices, "allocations": allocations}
                if include_inputs else None}
    policy = hardware_capacity.hardware_capacity_policy(
        trust_roots=["selected-retained-reservations"])
    request = hardware_capacity.hardware_capacity_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        evidence_ref=digest(evidence), policy=policy)
    return request, policy, canonical_bytes(evidence)


def replay(request: dict, policy: dict, evidence: bytes):
    certificate = hardware_capacity.build_hardware_capacity_certificate(
        request, evidence, policy=policy)
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=hardware_capacity.SEMANTIC_VERSION,
        objective=hardware_capacity.COORDINATE, represented_kind="HARDWARE",
        expected_request=request, policy=policy)
    return certificate, result


def test_half_open_capacity_boundary_replays_without_physical_promotion():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["computational_status"] == "PASS"
    assert result["native_result"]["physical_authenticity"] == "NOT_ESTABLISHED"
    assert result["native_result"]["live_availability"] == "NOT_ESTABLISHED"
    assert result["native_result"]["credit_authority"] == "NOT_ESTABLISHED"
    assert result["native_result"]["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert certificate == hardware_capacity.build_hardware_capacity_certificate(
        request, evidence, policy=policy)


def test_canonical_hardware_certificate_refuses_retained_evidence_redaction():
    from verifier.privacy import (
        DisclosureSurface, DisclosureBound, ObserverParty, EmissionContext,
        EmissionEvaluator, EmissionRefusalError)

    request, policy, evidence = selected()
    certificate = json.loads(hardware_capacity.build_hardware_capacity_certificate(
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


def test_overlap_above_declared_capacity_fails():
    leases = [
        {"id": "lease-a", "device": "gpu-a", "unit": "MEMORY_BYTE",
         "quantity": 8, "start_us": 0, "end_us": 10},
        {"id": "lease-b", "device": "gpu-a", "unit": "MEMORY_BYTE",
         "quantity": 1, "start_us": 5, "end_us": 15},
    ]
    request, policy, evidence = selected(allocations=leases)
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "FAIL"


def test_other_device_or_unit_cannot_subsidize_a_local_capacity_overrun():
    leases = [{"id": "lease", "device": "gpu-a", "unit": "MEMORY_BYTE",
               "quantity": 9, "start_us": 0, "end_us": 10}]
    request, policy, evidence = selected(allocations=leases)
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "FAIL"


def test_missing_retained_allocations_stay_unknown():
    request, policy, evidence = selected(include_inputs=False)
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("change", [
    {"quantity": 0}, {"quantity": -1}, {"quantity": True},
    {"start_us": 10}, {"end_us": 0},
    {"device": "missing"}, {"unit": "STORAGE_BYTE"},
])
def test_invalid_or_unaccountable_reservation_fails(change: dict):
    lease = {"id": "lease", "device": "gpu-a", "unit": "MEMORY_BYTE",
             "quantity": 1, "start_us": 0, "end_us": 10}
    lease.update(change)
    request, policy, evidence = selected(allocations=[lease])
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "FAIL"


def test_duplicate_reservation_identifier_fails():
    lease = {"id": "same", "device": "gpu-a", "unit": "COMPUTE_SLOT",
             "quantity": 1, "start_us": 0, "end_us": 10}
    request, policy, evidence = selected(allocations=[lease, deepcopy(lease)])
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "FAIL"


def test_empty_retained_reservations_have_zero_occupancy():
    request, policy, evidence = selected(allocations=[])
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "PASS"


def test_empty_reservations_with_false_commitment_fail():
    request, policy, evidence = selected(allocations=[])
    altered = json.loads(evidence)
    altered["objects"][0]["payload"]["allocations_digest"] = digest([{"not": "empty"}])
    subject = NamespaceObject.create(**altered["objects"][0])
    request["object_digest"] = subject.digest
    request["collection_digest"] = composition_digest([subject])
    request["evidence_ref"] = digest(altered)
    _, result = replay(request, policy, canonical_bytes(altered))
    assert result["computational_status"] == "FAIL"


def test_selected_checker_budget_exhaustion_is_unknown():
    request, policy, evidence = selected()
    request["limits"]["max_operations"] = 1
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "UNKNOWN"


def test_rehashed_false_allocation_does_not_inherit_a_prior_pass():
    request, policy, evidence = selected()
    changed = json.loads(evidence)
    changed["inputs"]["allocations"][0]["quantity"] = 9
    request["evidence_ref"] = digest(changed)
    _, result = replay(request, policy, canonical_bytes(changed))
    assert result["computational_status"] == "FAIL"


def test_external_policy_and_rehashed_certificate_substitution_are_rejected():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    changed_policy = deepcopy(policy)
    changed_policy["trust_roots"] = ["other"]
    with pytest.raises(ValueError):
        routes.replay_current_object_certificate(
            certificate, semantic_version=hardware_capacity.SEMANTIC_VERSION,
            objective=hardware_capacity.COORDINATE, represented_kind="HARDWARE",
            expected_request=request, policy=changed_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged["digest"] = digest({key: value for key, value in forged.items()
                               if key != "digest"})
    with pytest.raises(ValueError):
        routes.replay_current_object_certificate(
            canonical_bytes(forged),
            semantic_version=hardware_capacity.SEMANTIC_VERSION,
            objective=hardware_capacity.COORDINATE, represented_kind="HARDWARE",
            expected_request=request, policy=policy)


def test_public_hardware_capacity_command_replays_selected_bytes(tmp_path, capsys):
    from verifier.runtime.public_cli import main
    request, policy, evidence = selected()
    certificate = hardware_capacity.build_hardware_capacity_certificate(
        request, evidence, policy=policy)
    for name, content in (("request", canonical_bytes(request)),
                          ("policy", canonical_bytes(policy)),
                          ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(content)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
                 "--semantic-version", hardware_capacity.SEMANTIC_VERSION,
                 "--objective", hardware_capacity.COORDINATE,
                 "--represented-kind", "HARDWARE",
                 "--request", str(tmp_path / "request.json"),
                 "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


@pytest.mark.parametrize("relative", [
    "domains/contracts/hardware_capacity.py", "domains/hardware.py",
    "domains/common.py", "standard/CURRENT_HARDWARE_CAPACITY.md",
])
def test_changed_native_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate = hardware_capacity.build_hardware_capacity_certificate(
        request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(hardware_capacity.__file__).parents[2] / relative
    def changed(path):
        content = original(path)
        return content + b"\nchanged dependency\n" if path == target else content
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        hardware_capacity.recheck_hardware_capacity_certificate(
            certificate, expected_request=request, policy=policy)


def test_capacity_polish_replay_remains_incomplete():
    from verifier.runtime.polish import assess_polish
    request, policy, evidence = selected()
    certificate = hardware_capacity.build_hardware_capacity_certificate(
        request, evidence, policy=policy)
    cert_ref = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(evidence)["objects"],
              "certificates": {cert_ref: certificate.decode()}}
    intent = {"schema_version": "verifier-polish-request-1",
              "root_id": "hardware-a", "collection_digest": request["collection_digest"],
              "bundle_digest": digest(bundle),
              "requirements": [{"object_id": "hardware-a", "tier": tier,
                                "applicability": "REQUIRED",
                                "rationale": "Selected reservation arithmetic only",
                                "objectives": []} for tier in range(1, 10)]}
    intent["requirements"][1]["objectives"] = [{
        "semantic_version": hardware_capacity.SEMANTIC_VERSION,
        "coordinate": hardware_capacity.COORDINATE, "request": request,
        "policy": policy, "certificate_digest": cert_ref}]
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(intent))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["status"] == "UNKNOWN" and report["polished"] is False
