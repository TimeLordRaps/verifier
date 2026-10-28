"""Current ROLE finite selected lifecycle and ordered occupancy replay.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). No actual authority, enforcement or history claim.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import role_constraints as static
from verifier.domains.contracts import role_lifecycle as lifecycle
from test_current_role_constraints import selected as static_selected


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def byte_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def selected(*, states=None, mutate_objects=None, mutate_matrix=None,
             mutate_protocol=None, mutate_evidence=None, child_limits=None, **limits: int):
    states = states or ["inactive", "active", "suspended", "deprovisioned"]
    protocol = {"schema_version": lifecycle.PROTOCOL_VERSION,
        "states": ["active", "deprovisioned", "inactive", "suspended"],
        "transitions": [
            {"from_state": "active", "to_state": "suspended", "add_permissions": [],
             "remove_permissions": ["write"], "add_scopes": [], "remove_scopes": ["project"],
             "allow_taking": False, "allow_leaving": True},
            {"from_state": "inactive", "to_state": "active", "add_permissions": ["write"],
             "remove_permissions": [], "add_scopes": ["project"], "remove_scopes": [],
             "allow_taking": True, "allow_leaving": False},
            {"from_state": "suspended", "to_state": "deprovisioned", "add_permissions": [],
             "remove_permissions": [], "add_scopes": [], "remove_scopes": [],
             "allow_taking": False, "allow_leaving": False},
        ]}
    if mutate_protocol:
        mutate_protocol(protocol)
    endpoints, selections, occupants = [], [], []
    for position, state in enumerate(states):
        active = state == "active"

        def objects(rows):
            role = next(row for row in rows if row["object_id"] == "author")
            role["payload"].update(lifecycle_state=state,
                permissions=["write"] if active else [], admitted_scopes=["project"] if active else [])
            if not active:
                rows[:] = [row for row in rows if row["object_id"] != "identity-a"]
            if mutate_objects:
                mutate_objects(rows, position)

        def matrix(value):
            value["roles"][0].update(min_occupants=1 if active else 0, max_occupants=1)
            if not active:
                value["occupancies"] = [row for row in value["occupancies"] if row["role_id"] != "author"]
            if mutate_matrix:
                mutate_matrix(value, position)

        child_request, child_policy, child_evidence = static_selected(
            mutate_objects=objects, mutate_matrix=matrix, **(child_limits or {}))
        certificate = static.build_role_constraints_certificate(child_request, child_evidence, policy=child_policy)
        endpoints.append({"child_request": child_request, "child_policy": child_policy,
            "child_certificate": base64.b64encode(certificate).decode("ascii")})
        selections.append({"object_digest": child_request["object_digest"],
            "collection_digest": child_request["collection_digest"],
            "child_request_digest": digest(child_request), "child_policy_digest": digest(child_policy),
            "child_certificate_digest": byte_digest(certificate)})
        occupants.append({row["actor_id"] for row in json.loads(child_evidence)["inputs"]["matrix"]["occupancies"]
            if row["role_id"] == "author"})
    events = [{"position": position, "taking": sorted(occupants[position] - occupants[position - 1]),
        "leaving": sorted(occupants[position - 1] - occupants[position])}
        for position in range(1, len(occupants))]
    value = {"schema_version": lifecycle.EVIDENCE_VERSION, "protocol": protocol,
             "endpoints": endpoints, "events": events}
    if mutate_evidence:
        mutate_evidence(value, selections)
    evidence = canonical_bytes(value)
    policy = lifecycle.role_lifecycle_policy(trust_roots=["selected-role-lifecycle"])
    request = lifecycle.role_lifecycle_request(subject_id="author",
        object_digest=selections[-1]["object_digest"], collection_digest=selections[-1]["collection_digest"],
        endpoint_selections=selections, protocol_digest=digest(protocol), evidence_ref=byte_digest(evidence),
        policy=policy, limits=limits)
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = lifecycle.build_role_lifecycle_certificate(request, evidence, policy=policy)
    result = lifecycle.recheck_role_lifecycle_certificate(certificate,
        expected_request=request, policy=policy)
    return certificate, result


def fixture_for_integration(status: str):
    """Supply real native evidence for the root-owned public route tests."""
    if status == "PASS":
        request, policy, evidence = selected()
    elif status == "FAIL":
        request, policy, evidence = selected(mutate_protocol=lambda value:
            value["transitions"][1].update(allow_taking=False))
    elif status == "UNKNOWN":
        request, policy, _ = selected()
        evidence = None
    else:
        raise ValueError("unsupported integration fixture status")
    certificate = lifecycle.build_role_lifecycle_certificate(request, evidence, policy=policy)
    return certificate, request, policy


def test_selected_activation_suspension_deprovisioning_and_occupancy_replay():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["coordinate"] == "ROLE-2.1"
    assert result["object_kind"] == "ROLE"
    assert result["scope"] == lifecycle.SCOPE
    for field in ("object_profile_conformance", "whole_tier_conformance", "authority",
                  "actual_execution", "historical_occurrence", "enforcement"):
        assert result[field] == "NOT_ESTABLISHED"
    facts = result["evaluation"]["observations"]
    assert facts["endpoints"] == 4
    assert facts["transitions"] == 3
    assert facts["taking"] == 1 and facts["leaving"] == 1
    assert certificate == lifecycle.build_role_lifecycle_certificate(request, evidence, policy=policy)


def test_selected_paired_actor_replacement_is_one_exact_ordered_event():
    def mutate_objects(rows, position):
        if position == 1:
            rows[:] = [row for row in rows if row["object_id"] != "identity-a"]
            identity = next(row for row in rows if row["object_id"] == "identity-b")
            identity["operands"]["role"] = ["author"]

    def mutate_matrix(value, position):
        value["roles"][1].update(min_occupants=0)
        if position == 1:
            value["actors"][1]["allowed_roles"] = ["author", "reviewer"]
            value["occupancies"] = [{"identity_id": "identity-b", "actor_id": "actor-b",
                "role_id": "author", "scope": "project"}]

    def protocol(value):
        value["transitions"].append({"from_state": "active", "to_state": "active",
            "add_permissions": [], "remove_permissions": [], "add_scopes": [], "remove_scopes": [],
            "allow_taking": True, "allow_leaving": True})
        value["transitions"].sort(key=lambda row: (row["from_state"], row["to_state"]))

    request, policy, evidence = selected(states=["active", "active"],
        mutate_objects=mutate_objects, mutate_matrix=mutate_matrix, mutate_protocol=protocol)
    events = json.loads(evidence)["events"]
    assert events == [{"position": 1, "taking": ["actor-b"], "leaving": ["actor-a"]}]
    _, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["historical_occurrence"] == "NOT_ESTABLISHED"


def test_state_labels_have_only_externally_selected_protocol_meaning():
    names = {"inactive": "draft", "active": "enabled", "suspended": "paused", "deprovisioned": "retired"}

    def objects(rows, position):
        payload = next(row for row in rows if row["object_id"] == "author")["payload"]
        payload["lifecycle_state"] = names[payload["lifecycle_state"]]

    def protocol(value):
        value["states"] = sorted(names.values())
        for row in value["transitions"]:
            row["from_state"], row["to_state"] = names[row["from_state"]], names[row["to_state"]]
        value["transitions"].sort(key=lambda row: (row["from_state"], row["to_state"]))

    assert replay(*selected(mutate_objects=objects, mutate_protocol=protocol))[1]["status"] == "PASS"


@pytest.mark.parametrize("states", [
    ["inactive", "suspended"], ["active", "inactive"],
    ["deprovisioned", "active"], ["active", "active"],
])
def test_reselected_illegal_state_transition_fails(states):
    assert replay(*selected(states=states))[1]["status"] == "FAIL"


@pytest.mark.parametrize("mutation", [
    lambda value: value["transitions"][1].update(allow_taking=False),
    lambda value: value["transitions"][0].update(allow_leaving=False),
    lambda value: value["transitions"][1].update(add_permissions=[]),
    lambda value: value["transitions"][0].update(remove_permissions=[]),
    lambda value: value["transitions"][1].update(add_scopes=[]),
    lambda value: value["transitions"][0].update(remove_scopes=[]),
])
def test_reselected_false_transition_policy_fails(mutation):
    assert replay(*selected(mutate_protocol=mutation))[1]["status"] == "FAIL"


@pytest.mark.parametrize("mutation", [
    lambda value, _: value["events"][0].update(taking=[]),
    lambda value, _: value["events"][1].update(leaving=[]),
    lambda value, _: value["events"][0].update(position=2),
    lambda value, _: value["events"][0].update(taking=["actor-a", "actor-a"]),
    lambda value, _: value["events"].reverse(),
    lambda value, _: value["events"].append(deepcopy(value["events"][-1])),
])
def test_false_reselected_order_or_occupancy_events_fail(mutation):
    assert replay(*selected(mutate_evidence=mutation))[1]["status"] == "FAIL"


@pytest.mark.parametrize("field", ["protocol", "endpoints", "events"])
def test_absent_retained_component_is_unknown(field):
    assert replay(*selected(mutate_evidence=lambda value, _: value.update(
        {field: None})))[1]["status"] == "UNKNOWN"


def test_omitted_selected_endpoint_or_event_is_unknown():
    assert replay(*selected(mutate_evidence=lambda value, _: value["endpoints"].pop()))[1]["status"] == "UNKNOWN"
    assert replay(*selected(mutate_evidence=lambda value, _: value["events"].pop()))[1]["status"] == "UNKNOWN"
    request, policy, _ = selected()
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


def test_missing_lifecycle_declaration_and_unknown_child_are_unknown():
    def missing(rows, position):
        if position == 1:
            next(row for row in rows if row["object_id"] == "author")["payload"].pop("lifecycle_state")
    assert replay(*selected(mutate_objects=missing))[1]["status"] == "UNKNOWN"
    assert replay(*selected(child_limits={"max_operations": 1}))[1]["status"] == "UNKNOWN"
    assert replay(*selected(mutate_evidence=lambda value, _: value["endpoints"][1].update(
        child_certificate=None)))[1]["status"] == "UNKNOWN"


def test_child_failure_does_not_supply_endpoint_prerequisite():
    def invalid(rows, position):
        if position == 1:
            next(row for row in rows if row["object_id"] == "author")["payload"]["permissions"] = ["admin"]
    assert replay(*selected(mutate_objects=invalid))[1]["status"] == "FAIL"


@pytest.mark.parametrize("mutation", [
    lambda value, _: value["endpoints"][1]["child_request"].update(subject_id="reviewer"),
    lambda value, _: value["endpoints"][1]["child_policy"].update(trust_roots=["other"]),
    lambda value, _: value["endpoints"][1].update(child_certificate=value["endpoints"][0]["child_certificate"]),
])
def test_substituted_child_request_policy_or_certificate_fails(mutation):
    assert replay(*selected(mutate_evidence=mutation))[1]["status"] == "FAIL"


def test_rehashed_child_result_tamper_is_rejected_by_native_replay():
    def forge(value, selections):
        child = json.loads(base64.b64decode(value["endpoints"][1]["child_certificate"]))
        child["result"]["authority"] = "PASS"
        child.pop("digest")
        child["digest"] = digest(child)
        encoded = canonical_bytes(child)
        value["endpoints"][1]["child_certificate"] = base64.b64encode(encoded).decode("ascii")
        selections[1]["child_certificate_digest"] = byte_digest(encoded)
    assert replay(*selected(mutate_evidence=forge))[1]["status"] == "FAIL"


def test_valid_reselected_same_collection_child_with_another_role_subject_fails():
    def substitute(value, selections):
        endpoint = value["endpoints"][1]
        child = json.loads(base64.b64decode(endpoint["child_certificate"]))
        child_request = endpoint["child_request"]
        data = base64.b64decode(child["evidence_payloads"][child_request["evidence_ref"]])
        retained = json.loads(data)
        other = NamespaceObject.create(**next(row for row in retained["objects"]
            if row["object_id"] == "reviewer"))
        child_request.update(subject_id="reviewer", object_digest=other.digest)
        certificate = static.build_role_constraints_certificate(child_request, data,
            policy=endpoint["child_policy"])
        assert static.recheck_role_constraints_certificate(certificate,
            expected_request=child_request, policy=endpoint["child_policy"])["status"] == "PASS"
        endpoint["child_certificate"] = base64.b64encode(certificate).decode("ascii")
        selections[1].update(object_digest=other.digest,
            child_request_digest=digest(child_request), child_certificate_digest=byte_digest(certificate))
    assert replay(*selected(mutate_evidence=substitute))[1]["status"] == "FAIL"


@pytest.mark.parametrize("field,value", [
    ("object_kind", "OBJECT"), ("scope", "other-scope"), ("coordinate", "ROLE-3.2"),
    ("semantic_version", "legacy"), ("whole_tier_conformance", "PASS"),
    ("object_profile_conformance", "PASS"), ("authority", "PASS"),
    ("actual_execution", "PASS"), ("status", "REJECTED"),
])
def test_child_native_boundary_mutant_cannot_supply_endpoint(monkeypatch, field, value):
    request, policy, evidence = selected()
    original = static.recheck_role_constraints_certificate

    def mutant(*args, **kwargs):
        result = original(*args, **kwargs)
        result[field] = value
        return result

    monkeypatch.setattr(static, "recheck_role_constraints_certificate", mutant)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_nonrecord_child_native_result_fails_without_callback_or_crash(monkeypatch):
    request, policy, evidence = selected()
    monkeypatch.setattr(static, "recheck_role_constraints_certificate", lambda *a, **k: None)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_reselected_nonmutable_role_facet_change_fails():
    def mutate(rows, position):
        next(row for row in rows if row["object_id"] == "author")["payload"]["class_name"] = (
            "new-class" if position == 1 else "original-class")
    assert replay(*selected(mutate_objects=mutate))[1]["status"] == "FAIL"


@pytest.mark.parametrize("mutation", [
    lambda value: value["transitions"][1].update(allow_taking=1),
    lambda value: value["transitions"][1].update(add_permissions=["write", "write"]),
    lambda value: value["transitions"].append(deepcopy(value["transitions"][-1])),
    lambda value: value["states"].append("active"),
    lambda value: value.update(extra=True),
])
def test_malformed_present_protocol_fails(mutation):
    assert replay(*selected(mutate_protocol=mutation))[1]["status"] == "FAIL"


def test_unsupported_protocol_is_unknown():
    assert replay(*selected(mutate_protocol=lambda value: value.update(
        schema_version="unsupported")))[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("bound", list(lifecycle._CEILINGS))
def test_exhausted_parent_limits_are_unknown(bound):
    assert replay(*selected(**{bound: 1}))[1]["status"] == "UNKNOWN"


def test_exact_evidence_and_charged_operation_boundaries():
    request, policy, evidence = selected()
    facts = replay(request, policy, evidence)[1]["evaluation"]["observations"]
    for key, amount in (("max_evidence_bytes", len(evidence)),
                        ("max_operations", facts["operations"]),
                        ("max_child_operations", facts["child_operations_reserved"])):
        changed = deepcopy(request)
        changed["limits"][key] = amount
        assert replay(changed, policy, evidence)[1]["status"] == "PASS"
        changed["limits"][key] -= 1
        assert replay(changed, policy, evidence)[1]["status"] == "UNKNOWN"


def test_external_protocol_and_final_subject_bindings_cannot_be_substituted():
    request, policy, evidence = selected()
    for key in ("protocol_digest", "object_digest", "collection_digest"):
        changed = deepcopy(request)
        changed[key] = "sha256:" + "f" * 64
        assert replay(changed, policy, evidence)[1]["status"] == "FAIL"


def test_external_request_and_rehashed_parent_result_refuse():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    changed = deepcopy(request)
    changed["endpoint_selections"][1]["object_digest"] = "sha256:" + "f" * 64
    with pytest.raises(lifecycle.RoleLifecycleError):
        lifecycle.recheck_role_lifecycle_certificate(certificate, expected_request=changed, policy=policy)
    forged = json.loads(certificate)
    forged["result"]["historical_occurrence"] = "PASS"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(lifecycle.RoleLifecycleError):
        lifecycle.recheck_role_lifecycle_certificate(canonical_bytes(forged), expected_request=request, policy=policy)


@pytest.mark.parametrize("later_forgery", ["substitution", "rehashed_result"])
def test_missing_early_child_cannot_mask_available_later_forgery(later_forgery):
    def mutate(value, selections):
        value["endpoints"][0]["child_certificate"] = None
        endpoint = value["endpoints"][1]
        if later_forgery == "substitution":
            endpoint["child_certificate"] = value["endpoints"][2]["child_certificate"]
        else:
            child = json.loads(base64.b64decode(endpoint["child_certificate"]))
            child["result"]["authority"] = "PASS"
            child.pop("digest")
            child["digest"] = digest(child)
            encoded = canonical_bytes(child)
            endpoint["child_certificate"] = base64.b64encode(encoded).decode("ascii")
            selections[1]["child_certificate_digest"] = byte_digest(encoded)
    assert replay(*selected(mutate_evidence=mutate))[1]["status"] == "FAIL"


@pytest.mark.parametrize("missing", ["protocol", "events"])
def test_absent_component_cannot_mask_available_substituted_child(missing):
    def mutate(value, selections):
        value[missing] = None
        value["endpoints"][1]["child_certificate"] = value["endpoints"][2]["child_certificate"]
    assert replay(*selected(mutate_evidence=mutate))[1]["status"] == "FAIL"


def test_missing_policy_cannot_mask_present_child_certificate_commitment_mismatch():
    def mutate(value, selections):
        value["endpoints"][1]["child_policy"] = None
        value["endpoints"][1]["child_certificate"] = value["endpoints"][2]["child_certificate"]
    assert replay(*selected(mutate_evidence=mutate))[1]["status"] == "FAIL"


def test_missing_request_cannot_mask_present_child_policy_commitment_mismatch():
    def mutate(value, selections):
        value["endpoints"][1]["child_request"] = None
        value["endpoints"][1]["child_policy"]["trust_roots"] = ["substituted"]
    assert replay(*selected(mutate_evidence=mutate))[1]["status"] == "FAIL"


def test_absent_events_cannot_mask_feasible_false_state_permission_transition():
    assert replay(*selected(mutate_protocol=lambda value: value["transitions"][1].update(
        add_permissions=[]), mutate_evidence=lambda value, _: value.update(events=None)))[1]["status"] == "FAIL"


def test_missing_state_cannot_mask_independent_fixed_facet_change():
    def mutate(rows, position):
        payload = next(row for row in rows if row["object_id"] == "author")["payload"]
        payload["class_name"] = "changed" if position == 1 else "original"
        if position == 1:
            payload.pop("lifecycle_state")
    assert replay(*selected(mutate_objects=mutate))[1]["status"] == "FAIL"


def test_missing_state_cannot_mask_computable_false_occupancy_event():
    def mutate(rows, position):
        if position == 1:
            next(row for row in rows if row["object_id"] == "author")["payload"].pop("lifecycle_state")
    assert replay(*selected(mutate_objects=mutate, mutate_evidence=lambda value, _:
        value["events"][0].update(taking=[])))[1]["status"] == "FAIL"


def test_unsupported_protocol_cannot_mask_available_substituted_child():
    assert replay(*selected(mutate_protocol=lambda value: value.update(schema_version="unsupported"),
        mutate_evidence=lambda value, _: value["endpoints"][1].update(
            child_certificate=value["endpoints"][2]["child_certificate"])))[1]["status"] == "FAIL"
