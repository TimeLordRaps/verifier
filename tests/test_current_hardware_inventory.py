"""Versioned HARDWARE retained-inventory objective, separate from typed facets.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); graphics processing unit (GPU). Device capacities
are bytes or dimensionless per-device slots as named by their unit; no physical
attestation is inferred.
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
from verifier.domains.contracts import hardware_inventory


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def selected(*, devices: list[dict] | None = None, include_inputs: bool = True,
             **limits: int):
    devices = devices if devices is not None else [
        {"id": "gpu", "kind": "GPU", "capacities": {"MEMORY_BYTE": 8, "COMPUTE_SLOT": 2}},
        {"id": "store", "kind": "STORAGE", "capacities": {"STORAGE_BYTE": 20}},
    ]
    artifact = {"scope": "retained-hardware-records", "devices_digest": digest(devices)}
    subject = NamespaceObject.create("hardware-root", "HARDWARE", artifact)
    objects = [subject]
    evidence = canonical_bytes({
        "schema_version": hardware_inventory.EVIDENCE_VERSION,
        "objects": [subject.to_dict() for subject in objects],
        "inputs": {"devices": devices} if include_inputs else None,
    })
    policy = hardware_inventory.hardware_inventory_policy(trust_roots=["selected-retained-records"])
    request = hardware_inventory.hardware_inventory_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects), evidence_ref=digest(json.loads(evidence)),
        policy=policy, limits=limits,
    )
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes):
    cert = hardware_inventory.build_hardware_inventory_certificate(request, evidence, policy=policy)
    result = routes.replay_current_object_certificate(
        cert, semantic_version=hardware_inventory.SEMANTIC_VERSION,
        objective=hardware_inventory.COORDINATE, represented_kind="HARDWARE",
        expected_request=request, policy=policy)
    return cert, result


def test_retained_inventory_replays_at_distinct_coordinate_without_physical_promotion():
    request, policy, evidence = selected()
    cert, result = replay(request, policy, evidence)
    assert result["computational_status"] == "PASS"
    assert result["native_result"]["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert result["native_result"]["physical_authenticity"] == "NOT_ESTABLISHED"
    assert result["native_result"]["live_availability"] == "NOT_ESTABLISHED"
    assert result["native_result"]["credit_authority"] == "NOT_ESTABLISHED"
    assert cert == hardware_inventory.build_hardware_inventory_certificate(request, evidence, policy=policy)
    typed = routes.select_current_object_route(
        semantic_version="verifier-current-object-obligations-1",
        objective="HARDWARE-1.1", represented_kind="HARDWARE")
    retained = routes.select_current_object_route(
        semantic_version=hardware_inventory.SEMANTIC_VERSION,
        objective="HARDWARE-1.3", represented_kind="HARDWARE")
    assert typed.module is not retained.module


def test_substituted_retained_devices_fail_without_changing_the_selected_subject():
    request, policy, evidence = selected()
    changed = json.loads(evidence)
    changed["inputs"]["devices"][0]["capacities"]["MEMORY_BYTE"] = 9
    changed_bytes = canonical_bytes(changed)
    with pytest.raises(hardware_inventory.HardwareInventoryError, match="evidence differs"):
        hardware_inventory.build_hardware_inventory_certificate(request, changed_bytes, policy=policy)
    request["evidence_ref"] = digest(changed)
    _, result = replay(request, policy, changed_bytes)
    assert result["computational_status"] == "FAIL"


@pytest.mark.parametrize("capacity", [True, -1, 1.5, "8"])
def test_non_integer_or_negative_capacity_is_not_admitted(capacity):
    devices = [{"id": "gpu", "kind": "GPU", "capacities": {"MEMORY_BYTE": capacity}}]
    request, policy, evidence = selected(devices=devices)
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "FAIL"


def test_missing_retained_inputs_remain_unknown():
    request, policy, evidence = selected(include_inputs=False)
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "UNKNOWN"


def test_external_request_policy_and_certificate_substitutions_are_refused():
    request, policy, evidence = selected()
    cert, _ = replay(request, policy, evidence)
    changed_request = deepcopy(request)
    changed_request["subject_id"] = "other"
    with pytest.raises(ValueError):
        routes.replay_current_object_certificate(
            cert, semantic_version=hardware_inventory.SEMANTIC_VERSION,
            objective=hardware_inventory.COORDINATE, represented_kind="HARDWARE",
            expected_request=changed_request, policy=policy)
    changed_policy = deepcopy(policy)
    changed_policy["trust_roots"] = ["other"]
    with pytest.raises(ValueError):
        routes.replay_current_object_certificate(
            cert, semantic_version=hardware_inventory.SEMANTIC_VERSION,
            objective=hardware_inventory.COORDINATE, represented_kind="HARDWARE",
            expected_request=request, policy=changed_policy)
    forged = json.loads(cert)
    forged["result"]["status"] = "PASS" if forged["result"]["status"] != "PASS" else "FAIL"
    with pytest.raises(ValueError):
        routes.replay_current_object_certificate(
            canonical_bytes(forged), semantic_version=hardware_inventory.SEMANTIC_VERSION,
            objective=hardware_inventory.COORDINATE, represented_kind="HARDWARE",
            expected_request=request, policy=policy)


@pytest.mark.parametrize("field", ["schema_version", "mechanism_id"])
def test_direct_builder_refuses_custom_policy_comparison_before_invocation(field):
    request, policy, evidence = selected()
    class CandidateString(str):
        def __ne__(self, other):
            raise AssertionError("candidate comparison executed")
    policy[field] = CandidateString(policy[field])
    with pytest.raises(hardware_inventory.HardwareInventoryError):
        hardware_inventory.build_hardware_inventory_certificate(request, evidence, policy=policy)


@pytest.mark.parametrize("surface", ["policy", "request"])
def test_nonplain_record_key_is_refused_before_equality(surface):
    request, policy, evidence = selected()
    class ArmedKey(str):
        armed = False
        def __eq__(self, other):
            if self.armed:
                raise AssertionError("candidate key comparison executed")
            return str.__eq__(self, other)
        __hash__ = str.__hash__
    key = ArmedKey("schema_version")
    target = policy if surface == "policy" else request
    target[key] = target.pop("schema_version")
    key.armed = True
    with pytest.raises(hardware_inventory.HardwareInventoryError):
        hardware_inventory.build_hardware_inventory_certificate(request, evidence, policy=policy)


def test_policy_owns_caller_trust_root_list_after_admission():
    roots = ["selected-retained-records"]
    policy = hardware_inventory.hardware_inventory_policy(trust_roots=roots)
    roots.append("later-unselected-root")
    assert policy["trust_roots"] == ["selected-retained-records"]


def test_public_hardware_command_replays_exact_selected_certificate(tmp_path, capsys):
    from verifier.runtime.public_cli import main
    request, policy, evidence = selected()
    values = {
        "request": canonical_bytes(request), "policy": canonical_bytes(policy),
        "certificate": hardware_inventory.build_hardware_inventory_certificate(
            request, evidence, policy=policy),
    }
    for name, content in values.items():
        (tmp_path / (name + ".json")).write_bytes(content)
    result = main([
        "current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", hardware_inventory.SEMANTIC_VERSION,
        "--objective", hardware_inventory.COORDINATE,
        "--represented-kind", "HARDWARE",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json",
    ])
    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["physical_authenticity"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("bound", ["max_operations", "max_composition_operations",
    "max_items", "max_evidence_bytes", "max_payload_bytes", "max_reference_bytes"])
def test_exhausted_selected_hardware_bound_remains_unknown(bound):
    request, policy, evidence = selected(**{bound: 1})
    _, result = replay(request, policy, evidence)
    assert result["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("relative", [
    "domains/contracts/hardware_inventory.py", "domains/hardware.py",
    "domains/common.py", "core/namespace.py", "core/certificate.py",
    "core/evidence.py", "core/receipt.py",
    "standard/CURRENT_HARDWARE_INVENTORY.md", "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_hardware_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate = hardware_inventory.build_hardware_inventory_certificate(
        request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(hardware_inventory.__file__).parents[2] / relative
    def changed(path):
        content = original(path)
        return content + b"\nchanged hardware dependency\n" if path == target else content
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        hardware_inventory.recheck_hardware_inventory_certificate(
            certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("relative", ["domains/contracts/hardware_inventory.py",
    "domains/hardware.py", "standard/CURRENT_HARDWARE_INVENTORY.md"])
def test_hardware_dependency_invalidates_polish_mechanism(relative, monkeypatch):
    from verifier.runtime import polish
    original = Path.read_bytes
    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()
    def changed(path):
        content = original(path)
        return content + b"\nchanged hardware dependency\n" if path == target else content
    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


def test_hardware_polish_replay_does_not_issue_polished_status():
    from verifier.runtime.polish import assess_polish
    request, policy, evidence = selected()
    certificate = hardware_inventory.build_hardware_inventory_certificate(
        request, evidence, policy=policy)
    objects = json.loads(evidence)["objects"]
    certificate_digest = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1", "objects": objects,
              "certificates": {certificate_digest: certificate.decode()}}
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "hardware-root", "collection_digest": request["collection_digest"],
        "bundle_digest": digest(bundle),
        "requirements": [{"object_id": "hardware-root", "tier": tier,
            "applicability": "REQUIRED", "rationale": "Selected retained inventory only",
            "objectives": []} for tier in range(1, 10)]}
    selected_request["requirements"][0]["objectives"] = [{
        "semantic_version": hardware_inventory.SEMANTIC_VERSION,
        "coordinate": hardware_inventory.COORDINATE, "request": request,
        "policy": policy, "certificate_digest": certificate_digest,
    }]
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected_request))
    assert report["objectives"][0]["status"] == "PASS"
    assert report["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert report["status"] == "UNKNOWN" and report["polished"] is False
    request["collection_digest"] = "sha256:" + "0" * 64
    report = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(selected_request))
    assert report["objectives"][0]["reason"] == "SUBJECT_BINDING_DIFFERS"
