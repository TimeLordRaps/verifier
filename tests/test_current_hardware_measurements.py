"""Current HARDWARE-2.2 retained measurement envelope, not sensor attestation.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); graphics processing unit (GPU). Byte units are bytes, slot units are
dimensionless per-device counts, and instants are integer microseconds on
one declared clock.
"""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def selected(*, measurements: list[dict] | None = None,
             devices: list[dict] | None = None,
             include_inputs: bool = True,
             measurement_commitment: str | None = None):
    from verifier.domains.contracts import hardware_measurements

    if devices is None:
        devices = [{"id": "meter-a", "kind": "GPU",
                    "capacities": {"MEMORY_BYTE": 8, "COMPUTE_SLOT": 2}}]
    if measurements is None:
        measurements = [
            {"id": "sample-a", "device": "meter-a", "unit": "MEMORY_BYTE",
             "quantity": 8, "at_us": 100},
            {"id": "sample-b", "device": "meter-a", "unit": "MEMORY_BYTE",
             "quantity": 0, "at_us": 101},
        ]
    subject = NamespaceObject.create("meter", "HARDWARE", {
        "scope": "retained-hardware-records", "clock": "test-clock",
        "devices_digest": digest(devices),
        "measurements_digest": measurement_commitment or digest(measurements),
    })
    evidence = {"schema_version": hardware_measurements.EVIDENCE_VERSION,
                "objects": [subject.to_dict()],
                "inputs": {"devices": devices, "measurements": measurements}
                if include_inputs else None}
    policy = hardware_measurements.hardware_measurements_policy(
        trust_roots=["selected-retained-observations"])
    request = hardware_measurements.hardware_measurements_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        evidence_ref=digest(evidence), policy=policy)
    return request, policy, canonical_bytes(evidence)


def test_exact_retained_measurement_envelope_replays_without_sensor_promotion():
    from verifier.domains.contracts import hardware_measurements
    from verifier.domains.contracts import current_object_routes as routes

    request, policy, evidence = selected()
    certificate = hardware_measurements.build_hardware_measurements_certificate(
        request, evidence, policy=policy)
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=hardware_measurements.SEMANTIC_VERSION,
        objective=hardware_measurements.COORDINATE, represented_kind="HARDWARE",
        expected_request=request, policy=policy)
    assert result["computational_status"] == "PASS"
    assert result["native_result"]["sensor_authenticity"] == "NOT_ESTABLISHED"
    assert result["native_result"]["physical_authenticity"] == "NOT_ESTABLISHED"
    assert result["native_result"]["live_availability"] == "NOT_ESTABLISHED"


def replay(request: dict, policy: dict, evidence: bytes):
    from verifier.domains.contracts import hardware_measurements
    from verifier.domains.contracts import current_object_routes as routes

    certificate = hardware_measurements.build_hardware_measurements_certificate(
        request, evidence, policy=policy)
    result = routes.replay_current_object_certificate(
        certificate, semantic_version=hardware_measurements.SEMANTIC_VERSION,
        objective=hardware_measurements.COORDINATE, represented_kind="HARDWARE",
        expected_request=request, policy=policy)
    return certificate, result


@pytest.mark.parametrize("sample", [
    {"quantity": 9}, {"quantity": -1}, {"quantity": True},
    {"quantity": 1.5}, {"at_us": -1}, {"at_us": "now"},
    {"at_us": 2**53},
    {"device": "unknown"}, {"unit": "STORAGE_BYTE"},
    {"unit": "COMPUTE_SLOT", "quantity": 3},
])
def test_false_or_unaccountable_measurement_fails(sample: dict):
    value = {"id": "sample", "device": "meter-a", "unit": "MEMORY_BYTE",
             "quantity": 8, "at_us": 100}
    value.update(sample)
    request, policy, evidence = selected(measurements=[value])
    assert replay(request, policy, evidence)[1]["computational_status"] == "FAIL"


def test_samples_are_not_summed_across_instants_or_devices():
    devices = [{"id": name, "kind": "GPU", "capacities": {"MEMORY_BYTE": 8}}
               for name in ("meter-a", "meter-b")]
    samples = [{"id": f"sample-{index}", "device": device,
                "unit": "MEMORY_BYTE", "quantity": 8, "at_us": instant}
               for index, (device, instant) in enumerate(
                   (("meter-a", 100), ("meter-a", 100),
                    ("meter-a", 101), ("meter-b", 100)))]
    request, policy, evidence = selected(devices=devices, measurements=samples)
    assert replay(request, policy, evidence)[1]["computational_status"] == "PASS"


def test_maximum_supported_instant_remains_admitted():
    sample = {"id": "last", "device": "meter-a", "unit": "MEMORY_BYTE",
              "quantity": 8, "at_us": 2**53 - 1}
    request, policy, evidence = selected(measurements=[sample])
    assert replay(request, policy, evidence)[1]["computational_status"] == "PASS"


def test_duplicate_sample_identifier_fails():
    sample = {"id": "duplicate", "device": "meter-a", "unit": "MEMORY_BYTE",
              "quantity": 1, "at_us": 100}
    request, policy, evidence = selected(measurements=[sample, deepcopy(sample)])
    assert replay(request, policy, evidence)[1]["computational_status"] == "FAIL"


def test_exact_empty_measurement_set_and_false_commitment():
    request, policy, evidence = selected(measurements=[])
    assert replay(request, policy, evidence)[1]["computational_status"] == "PASS"
    wrong, wrong_policy, wrong_evidence = selected(
        measurements=[], measurement_commitment=digest(["not empty"]))
    assert replay(wrong, wrong_policy, wrong_evidence)[1]["computational_status"] == "FAIL"


def test_missing_inputs_and_exhausted_checker_budget_remain_unknown():
    request, policy, evidence = selected(include_inputs=False)
    assert replay(request, policy, evidence)[1]["computational_status"] == "UNKNOWN"
    request, policy, evidence = selected()
    from verifier.domains.contracts import hardware_measurements
    constrained = hardware_measurements.hardware_measurements_request(
        subject_id=request["subject_id"], object_digest=request["object_digest"],
        collection_digest=request["collection_digest"],
        evidence_ref=request["evidence_ref"], policy=policy,
        limits={"max_operations": 1})
    assert replay(constrained, policy, evidence)[1]["computational_status"] == "UNKNOWN"


def test_external_policy_and_rehashed_result_substitution_are_rejected():
    from verifier.domains.contracts import hardware_measurements
    from verifier.domains.contracts import current_object_routes as routes

    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    changed_policy = deepcopy(policy)
    changed_policy["trust_roots"] = ["other"]
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version=hardware_measurements.SEMANTIC_VERSION,
            objective=hardware_measurements.COORDINATE, represented_kind="HARDWARE",
            expected_request=request, policy=changed_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged["digest"] = digest({key: value for key, value in forged.items()
                               if key != "digest"})
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            canonical_bytes(forged),
            semantic_version=hardware_measurements.SEMANTIC_VERSION,
            objective=hardware_measurements.COORDINATE, represented_kind="HARDWARE",
            expected_request=request, policy=policy)


def test_public_command_replays_exact_retained_certificate(tmp_path: Path, capsys):
    from verifier.domains.contracts import hardware_measurements
    from verifier.runtime.public_cli import main

    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    for name, content in (("request", canonical_bytes(request)),
                          ("policy", canonical_bytes(policy)),
                          ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(content)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
                 "--semantic-version", hardware_measurements.SEMANTIC_VERSION,
                 "--objective", hardware_measurements.COORDINATE,
                 "--represented-kind", "HARDWARE",
                 "--request", str(tmp_path / "request.json"),
                 "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def test_canonical_measurement_certificate_refuses_evidence_redaction():
    from verifier.privacy import (
        DisclosureSurface, DisclosureBound, ObserverParty, EmissionContext,
        EmissionEvaluator, EmissionRefusalError)

    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    value = json.loads(certificate)
    fields = tuple(key for key in value if key != "evidence_payloads")
    surface = DisclosureSurface("HARDWARE", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


def test_measurement_polish_replay_stays_incomplete():
    from verifier.domains.contracts import hardware_measurements
    from verifier.runtime.polish import assess_polish

    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    certificate_ref = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(evidence)["objects"],
              "certificates": {certificate_ref: certificate.decode()}}
    intent = {"schema_version": "verifier-polish-request-1",
              "root_id": "meter", "collection_digest": request["collection_digest"],
              "bundle_digest": digest(bundle),
              "requirements": [{"object_id": "meter", "tier": tier,
                                "applicability": "REQUIRED",
                                "rationale": "Selected measurement envelope only",
                                "objectives": []} for tier in range(1, 10)]}
    intent["requirements"][1]["objectives"] = [{
        "semantic_version": hardware_measurements.SEMANTIC_VERSION,
        "coordinate": hardware_measurements.COORDINATE,
        "request": request, "policy": policy,
        "certificate_digest": certificate_ref}]
    report = assess_polish(canonical_bytes(bundle),
                           request_bytes=canonical_bytes(intent))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["status"] == "UNKNOWN" and report["polished"] is False


@pytest.mark.parametrize("relative", [
    "domains/contracts/hardware_measurements.py", "domains/hardware.py",
    "domains/common.py", "standard/CURRENT_HARDWARE_MEASUREMENTS.md",
])
def test_changed_native_dependency_invalidates_selected_policy(
        relative: str, monkeypatch: pytest.MonkeyPatch):
    from verifier.domains.contracts import hardware_measurements

    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    target = Path(hardware_measurements.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        hardware_measurements.recheck_hardware_measurements_certificate(
            certificate, expected_request=request, policy=policy)
