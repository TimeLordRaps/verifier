"""Exact declared OWNER hardware eligibility with fresh finite evidence replay.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Simulation (SIM). Fixtures are bounded declarations, not legal or physical proof.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import owner_eligibility as native
from verifier.domains.contracts import current_object_routes as routes
from test_namespace_objects import ownership_specimen


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def selected(kind: str = "BOT", realm: str = "virtual", *,
             mutation: str | None = None, limits: dict[str, int] | None = None) -> tuple[dict, dict, bytes]:
    objects, isolation, binding = ownership_specimen(kind, realm)
    if mutation == "missing-isolation":
        isolation = None
    elif mutation == "missing-binding":
        binding = None
    elif mutation in ("other-sim", "other-resource", "unknown-realm", "non-hardware"):
        index = next(i for i, item in enumerate(objects) if item.object_id == "owned")
        item = objects[index]
        payload = item.payload
        if mutation == "other-sim":
            payload["simulation_id"] = "other"
        elif mutation == "other-resource":
            payload["resource_kind"] = "compute"
        elif mutation == "unknown-realm":
            payload.pop("realm")
        objects[index] = NamespaceObject.create("owned",
            "OBJECT" if mutation == "non-hardware" else "HARDWARE", payload)
    elif mutation in ("sim-evidence-differs", "missing-sim-evidence", "outside-effect"):
        if mutation == "outside-effect":
            isolation["transitions"][0]["outcomes"][0]["effects"][0]["kind"] = "outside_write"
        else:
            index = next(i for i, item in enumerate(objects) if item.object_id == "sim")
            item = objects[index]
            payload = item.payload
            if mutation == "missing-sim-evidence":
                payload.pop("isolation_evidence_digest")
            else:
                payload["isolation_evidence_digest"] = "sha256:" + "0" * 64
            objects[index] = NamespaceObject.create("sim", "SIM", payload, dict(item.operands))
    raw = canonical_bytes({"schema_version": native.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects], "isolation_evidence": isolation})
    policy = native.owner_eligibility_policy(trust_roots=["test:exact-independent-selection"])
    owner = next(item for item in objects if item.object_id == "owner")
    request = native.owner_eligibility_request(subject_id=owner.object_id,
        object_digest=owner.digest, collection_digest=composition_digest(objects),
        evidence_ref=digest(raw), isolation_binding=binding, policy=policy, limits=limits)
    return request, policy, raw


def replay(request: dict, policy: dict, raw: bytes | None) -> dict[str, Any]:
    certificate = native.build_owner_eligibility_certificate(request, raw, policy=policy)
    return native.recheck_owner_eligibility_certificate(certificate,
        expected_request=request, policy=policy)


@pytest.mark.parametrize("kind,realm,status", [
    ("HUMAN", "physical", "PASS"), ("HUMAN", "virtual", "PASS"),
    ("AGENT", "physical", "FAIL"), ("AGENT", "virtual", "FAIL"),
    ("BOT", "physical", "FAIL"), ("BOT", "virtual", "PASS")])
def test_existing_kind_restriction_transports_exactly(kind: str, realm: str, status: str) -> None:
    result = replay(*selected(kind, realm))
    assert result["status"] == status
    assert result["scope"] == "declared_hardware_ownership_eligibility"
    for field in ("legal_title", "authority", "human_authenticity", "physical_host_containment",
                  "actual_enforcement", "whole_owner_statics_tier", "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("mutation,status", [
    ("missing-isolation", "UNKNOWN"), ("missing-binding", "UNKNOWN"),
    ("unknown-realm", "UNKNOWN"), ("missing-sim-evidence", "UNKNOWN"),
    ("other-sim", "FAIL"), ("other-resource", "FAIL"),
    ("sim-evidence-differs", "FAIL"), ("outside-effect", "FAIL")])
def test_missing_support_and_refutations_remain_distinct(mutation: str, status: str) -> None:
    assert replay(*selected(mutation=mutation))["status"] == status


def test_missing_retained_bundle_stays_unknown() -> None:
    request, policy, _ = selected()
    assert replay(request, policy, None)["status"] == "UNKNOWN"


def test_non_hardware_eligibility_stays_unknown() -> None:
    assert replay(*selected("HUMAN", "physical", mutation="non-hardware"))["status"] == "UNKNOWN"


def test_typed_graph_hardware_is_expanded_by_existing_native_contract() -> None:
    request, policy, raw = selected("HUMAN", "physical")
    value = json.loads(raw)
    objects = [NamespaceObject.create(**row) for row in value["objects"]]
    index = next(i for i, item in enumerate(objects) if item.object_id == "owner")
    owner = NamespaceObject.create("owner", "OWNER", {}, {"actor": ["actor"], "object": ["hardware-group"]})
    objects[index] = owner
    objects.append(NamespaceObject.create("hardware-group", "GRAPH", {"element_kind": "HARDWARE"},
                                         {"members": ["owned"]}))
    raw = canonical_bytes({**value, "objects": [item.to_dict() for item in objects]})
    request.update(object_digest=owner.digest, collection_digest=composition_digest(objects),
                   evidence_ref=digest(raw))
    assert replay(request, policy, raw)["status"] == "PASS"


@pytest.mark.parametrize("field", ["subject_id", "object_digest", "collection_digest"])
def test_external_exact_subject_and_collection_cannot_be_substituted(field: str) -> None:
    request, policy, raw = selected()
    request[field] = "other-owner" if field == "subject_id" else "sha256:" + "0" * 64
    assert replay(request, policy, raw)["status"] == "FAIL"


@pytest.mark.parametrize("field,value", [("status", "PASS"), ("authority", "PASS"),
                                        ("physical_host_containment", "PASS")])
def test_rehashed_invented_clearance_is_refused(field: str, value: str) -> None:
    request, policy, raw = selected("AGENT", "physical")
    certificate = json.loads(native.build_owner_eligibility_certificate(request, raw, policy=policy))
    certificate["result"][field] = value
    certificate.pop("digest")
    certificate["digest"] = "sha256:" + canonical_digest(certificate)
    with pytest.raises(native.OwnerEligibilityError):
        native.recheck_owner_eligibility_certificate(canonical_bytes(certificate),
            expected_request=request, policy=policy)


@pytest.mark.parametrize("limits", [{"max_objects": 1}, {"max_operations": 1},
    {"max_composition_operations": 1}, {"max_payload_bytes": 1}, {"max_nesting_depth": 1}])
def test_selected_finite_exhaustion_is_unknown(limits: dict[str, int]) -> None:
    assert replay(*selected(limits=limits))["status"] == "UNKNOWN"


def test_omitted_isolation_key_is_malformed() -> None:
    request, policy, raw = selected()
    value = json.loads(raw)
    value.pop("isolation_evidence")
    raw = canonical_bytes(value)
    request["evidence_ref"] = digest(raw)
    assert replay(request, policy, raw)["status"] == "FAIL"


def test_deep_decoder_exhaustion_precedes_recursive_parse() -> None:
    request, policy, _ = selected()
    raw = b'[' * 80 + b'0' + b']' * 80
    request["evidence_ref"] = digest(raw)
    assert replay(request, policy, raw)["status"] == "UNKNOWN"


def test_constructor_captures_external_isolation_binding() -> None:
    request, policy, raw = selected()
    binding = deepcopy(request["isolation_binding"])
    captured = native.owner_eligibility_request(subject_id=request["subject_id"],
        object_digest=request["object_digest"], collection_digest=request["collection_digest"],
        evidence_ref=request["evidence_ref"], isolation_binding=binding, policy=policy)
    binding["sim_id"] = "substituted"
    assert replay(captured, policy, raw)["status"] == "PASS"


def test_versioned_registration_is_current_and_legacy_meaning_is_not_transferred() -> None:
    request, policy, raw = selected()
    certificate = native.build_owner_eligibility_certificate(request, raw, policy=policy)
    report = routes.replay_current_object_certificate(certificate,
        semantic_version=native.SEMANTIC_VERSION, objective="OWNER-3.1", represented_kind="OWNER",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(certificate,
            semantic_version="verifier-domain-obligations-1", objective="OWNER-3.1",
            represented_kind="OWNER", expected_request=request, policy=policy)


def test_required_projection_selects_predicate_without_upgrading_coverage() -> None:
    from verifier.domains.inventory import get_slot, slot_inventory
    slot = get_slot("OWNER", 3)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == "OWNER-3.1"
    assert len(slot_inventory()) == 234
    assert all(row["applicability"] == "REQUIRED" for row in slot_inventory())
    assert native.registration()["scope"] == "declared_hardware_ownership_eligibility"
