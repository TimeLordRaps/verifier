"""Native ROLE-4.1 finite history and exact selected attribution regressions."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import pytest

from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import role_closure as closure
from verifier.domains.contracts import role_lifecycle as lifecycle
from test_current_role_lifecycle import selected as lifecycle_selected

def digest(value):
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()

def byte_digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()

def fixture(*, handover=False, multi=False, mutate=None, child_status="PASS", **limits):
    def objects(rows, position):
        if (handover and position == 1) or multi:
            if not multi:
                rows[:] = [row for row in rows if row["object_id"] != "identity-a"]
            identity = next(row for row in rows if row["object_id"] == "identity-b")
            identity["operands"]["role"] = ["author"]

    def matrix(value, position):
        if (handover and position == 1) or multi:
            value["roles"][1].update(min_occupants=0)
            value["actors"][1]["allowed_roles"] = ["author", "reviewer"]
            value["occupancies"] = [{"identity_id": "identity-b", "actor_id": "actor-b", "role_id": "author", "scope": "project"}]
            if multi:
                value["occupancies"].insert(0, {"identity_id": "identity-a", "actor_id": "actor-a", "role_id": "author", "scope": "project"})
                value["roles"][0].update(min_occupants=2, max_occupants=2)

    def protocol(value):
        value["transitions"].append({"from_state": "active", "to_state": "active", "add_permissions": [],
            "remove_permissions": [], "add_scopes": [], "remove_scopes": [], "allow_taking": True, "allow_leaving": True})
        value["transitions"].sort(key=lambda row: (row["from_state"], row["to_state"]))

    child_request, child_policy, child_evidence = lifecycle_selected(states=["active", "active"],
        mutate_objects=objects, mutate_matrix=matrix, mutate_protocol=protocol)
    if child_status == "UNKNOWN":
        child_evidence = None
    elif child_status == "LOCAL_UNKNOWN":
        carried = json.loads(child_evidence)
        carried["protocol"] = None
        child_evidence = canonical_bytes(carried)
        child_request["evidence_ref"] = byte_digest(child_evidence)
    elif child_status == "FAIL":
        carried = json.loads(child_evidence)
        carried["events"][0]["position"] = 2
        child_evidence = canonical_bytes(carried)
        child_request["evidence_ref"] = byte_digest(child_evidence)
    child_certificate = lifecycle.build_role_lifecycle_certificate(child_request, child_evidence, policy=child_policy)
    role = {"position": 0, "decision_id": "decision-0", "time_us": 9,
        "actor_id": "actor-a", "identity_id": "identity-a", "scope": "project", "decision_class": "write",
        "content_digest": "sha256:" + "a" * 64}
    decisions = [role, {**role, "position": 1, "decision_id": "decision-1", "time_us": 10}]
    if handover:
        decisions[1].update(actor_id="actor-b", identity_id="identity-b")
    events = [{"position": 1, "time_us": 10,
        "action": "HANDOVER" if handover else "CHECKPOINT",
        "taking": ["actor-b"] if handover else [], "leaving": ["actor-a"] if handover else []}]
    value = {"schema_version": closure.EVIDENCE_VERSION,
        "lifecycle_certificate": base64.b64encode(child_certificate).decode("ascii"),
        "events": events, "decisions": decisions}
    if mutate:
        mutate(value)
    evidence = canonical_bytes(value)
    policy = closure.role_closure_policy(trust_roots=["selected-declared-history"])
    request = closure.role_closure_request(subject_id=child_request["subject_id"],
        object_digest=child_request["object_digest"], collection_digest=child_request["collection_digest"],
        collective_id="team", clock_id="declared-test-clock", period_us=[0,20], endpoint_times_us=[0,10],
        lifecycle_request=child_request, lifecycle_policy=child_policy,
        lifecycle_certificate_digest=byte_digest(child_certificate), events_digest=digest(events),
        decisions_digest=digest(decisions), evidence_ref=byte_digest(evidence), policy=policy, limits=limits)
    return request, policy, evidence

def replay(request, policy, evidence):
    certificate = closure.build_role_closure_certificate(request, evidence, policy=policy)
    result = closure.recheck_role_closure_certificate(certificate, expected_request=request, policy=policy)
    return certificate, result

@pytest.mark.parametrize("options", [{}, {"handover": True}, {"multi": True}])
def test_genuine_selected_complete_history_and_attribution(options):
    request, policy, evidence = fixture(**options)
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["coordinate"] == "ROLE-4.1"
    assert result["authority"] == result["historical_occurrence"] == result["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert certificate == closure.build_role_closure_certificate(request, evidence, policy=policy)

def test_handover_instant_belongs_to_incoming_bearer():
    def mutate(value):
        value["decisions"][1].update(actor_id="actor-a", identity_id="identity-a")
    assert replay(*fixture(handover=True, mutate=mutate))[1]["status"] == "FAIL"

@pytest.mark.parametrize("mutation", [
    lambda v: v["decisions"][0].update(actor_id="actor-b"),
    lambda v: v["decisions"][0].update(identity_id="identity-b"),
    lambda v: v["decisions"][0].update(scope="unselected"),
    lambda v: v["decisions"][0].update(decision_class="unselected"),
    lambda v: v["decisions"][0].update(time_us=20),
    lambda v: v["decisions"][0].update(time_us=True),
    lambda v: v["decisions"][1].update(decision_id="decision-0"),
    lambda v: v["events"][0].update(action="HANDOVER"),
    lambda v: v["events"][0].update(time_us=11),
    lambda v: v["events"][0].update(position=True),
])
def test_reselected_present_contradictions_fail(mutation):
    assert replay(*fixture(mutate=mutation))[1]["status"] == "FAIL"

@pytest.mark.parametrize("component", ["lifecycle_certificate", "events", "decisions"])
def test_missing_retained_component_stays_unknown(component):
    assert replay(*fixture(mutate=lambda v: v.update({component: None})))[1]["status"] == "UNKNOWN"

def test_missing_lifecycle_does_not_hide_decidable_time_contradiction():
    def mutate(value):
        value["lifecycle_certificate"] = None
        value["decisions"][0]["time_us"] = 20
    assert replay(*fixture(mutate=mutate))[1]["status"] == "FAIL"

def test_missing_events_does_not_hide_decidable_bearer_contradiction():
    def mutate(value):
        value["events"] = None
        value["decisions"][0]["actor_id"] = "actor-b"
    assert replay(*fixture(mutate=mutate))[1]["status"] == "FAIL"

@pytest.mark.parametrize("child_status", ["UNKNOWN", "FAIL"])
def test_fresh_child_outcome_propagates(child_status):
    assert replay(*fixture(child_status=child_status))[1]["status"] == child_status

@pytest.mark.parametrize("limits", [{"max_operations": 1}, {"max_child_operations": 1}, {"max_evidence_bytes": 1}, {"max_decisions": 1}])
def test_resource_exhaustion_never_passes(limits):
    assert replay(*fixture(**limits))[1]["status"] == "UNKNOWN"

def test_rehashed_carried_pass_does_not_reproduce():
    request, policy, evidence = fixture(mutate=lambda v: v["decisions"][0].update(actor_id="actor-b"))
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    value = json.loads(certificate)
    value["result"]["status"] = "PASS"
    del value["digest"]
    value["digest"] = digest(value)
    with pytest.raises(closure.RoleClosureError):
        closure.recheck_role_closure_certificate(canonical_bytes(value), expected_request=request, policy=policy)

def test_independent_selection_cannot_be_replaced_by_carried_request():
    request, policy, evidence = fixture()
    certificate, _ = replay(request, policy, evidence)
    changed = deepcopy(request)
    changed["clock_id"] = "another-clock"
    with pytest.raises(closure.RoleClosureError):
        closure.recheck_role_closure_certificate(certificate, expected_request=changed, policy=policy)


def test_caller_lists_and_nested_child_selection_are_owned():
    request, policy, _ = fixture()
    captured = closure._request(request)
    expected = deepcopy(captured)
    request["period_us"][0] = 1
    request["endpoint_times_us"][0] = 1
    request["lifecycle_request"]["endpoint_selections"][0]["object_digest"] = "sha256:" + "0" * 64
    request["lifecycle_request"]["limits"]["max_operations"] = 1
    request["lifecycle_policy"]["trust_roots"].append("caller-mutation")
    assert captured == expected


def test_time_and_child_lists_are_captured_before_child_policy_callback(monkeypatch):
    request, _, _ = fixture()
    expected = deepcopy(request)
    original = lifecycle._policy
    def mutation(value):
        request["period_us"][0] = 1
        request["endpoint_times_us"][0] = 1
        request["limits"]["max_operations"] = 1
        request["lifecycle_request"]["endpoint_selections"][0]["object_digest"] = "sha256:" + "0" * 64
        request["lifecycle_policy"]["trust_roots"].append("caller-mutation")
        return original(value)
    monkeypatch.setattr(lifecycle, "_policy", mutation)
    assert closure._request(request) == expected


@pytest.mark.parametrize("failure", ["unavailable", "recursion", "overflow"])
def test_recheck_resource_failure_is_not_semantic_refutation(monkeypatch, failure):
    from verifier.domains.common import Unavailable
    request, policy, evidence = fixture()
    certificate, _ = replay(request, policy, evidence)
    error = {"unavailable":Unavailable, "recursion":RecursionError, "overflow":OverflowError}[failure]
    def fence(_):
        raise error("resource fence")
    monkeypatch.setattr(closure.role_constraints, "_preflight_depth", fence)
    with pytest.raises(closure.RoleClosureUnavailable):
        closure.recheck_role_closure_certificate(certificate, expected_request=request, policy=policy)


def test_public_constructor_captures_before_initial_parent_policy_source_callback(monkeypatch):
    request, policy, _ = fixture()
    expected = deepcopy(request)
    expected_policy = deepcopy(policy)
    original = closure.mechanism_digest
    def mutation():
        request["period_us"][0] = 1
        request["endpoint_times_us"][0] = 1
        request["limits"]["max_operations"] = 1
        request["lifecycle_request"]["endpoint_selections"][0]["object_digest"] = "sha256:" + "0" * 64
        policy["trust_roots"].append("caller-mutation")
        return original()
    monkeypatch.setattr(closure, "mechanism_digest", mutation)
    captured = closure.role_closure_request(**{key:expected[key] if key in ("subject_id", "object_digest", "collection_digest",
        "collective_id", "clock_id", "lifecycle_certificate_digest", "events_digest", "decisions_digest", "evidence_ref") else request[key]
        for key in ("subject_id", "object_digest", "collection_digest", "collective_id", "clock_id", "period_us",
        "endpoint_times_us", "lifecycle_request", "lifecycle_policy", "lifecycle_certificate_digest", "events_digest",
        "decisions_digest", "evidence_ref", "limits")}, policy=policy)
    assert captured == expected
    assert captured["policy_digest"] == digest(expected_policy)


@pytest.mark.parametrize("entrypoint", ["build", "recheck"])
def test_public_build_and_recheck_capture_parent_policy_before_child_callback(monkeypatch, entrypoint):
    request, policy, evidence = fixture()
    expected_request, expected_policy = deepcopy(request), deepcopy(policy)
    certificate, expected_result = replay(request, policy, evidence)
    original = lifecycle._policy
    def mutation(value):
        request["period_us"][0] = 1
        request["limits"]["max_operations"] = 1
        policy["trust_roots"].append("caller-mutation")
        return original(value)
    monkeypatch.setattr(lifecycle, "_policy", mutation)
    if entrypoint == "build":
        assert closure.build_role_closure_certificate(request, evidence, policy=policy) == certificate
    else:
        assert closure.recheck_role_closure_certificate(certificate, expected_request=request, policy=policy) == expected_result
    assert expected_request["period_us"] == [0,20]
    assert expected_policy["trust_roots"] == ["selected-declared-history"]


def test_missing_lifecycle_protocol_retains_unknown_without_false_attribution():
    assert replay(*fixture(child_status="LOCAL_UNKNOWN"))[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("field,value", [("actor_id", "actor-b"), ("scope", "unselected")])
def test_missing_lifecycle_protocol_cannot_hide_fresh_static_attribution_failure(field, value):
    assert replay(*fixture(child_status="LOCAL_UNKNOWN", mutate=lambda v:v["decisions"][0].update({field:value})))[1]["status"] == "FAIL"


@pytest.mark.parametrize("field,value", [("object_kind","OBJECT"), ("coordinate","ROLE-3.1"), ("scope","other"), ("authority","PASS"), ("status","REJECTED")])
def test_native_lifecycle_result_cannot_expand_selected_boundary(monkeypatch, field, value):
    request, policy, evidence = fixture()
    original = lifecycle.recheck_role_lifecycle_certificate
    def mutant(*args, **kwargs):
        result = original(*args, **kwargs)
        result[field] = value
        return result
    monkeypatch.setattr(lifecycle, "recheck_role_lifecycle_certificate", mutant)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


@pytest.mark.parametrize("payloads", [None, [], "not-a-map"])
def test_malformed_selected_child_payload_shape_is_semantic_fail(payloads):
    request, policy, evidence = fixture()
    retained = json.loads(evidence)
    child = json.loads(base64.b64decode(retained["lifecycle_certificate"]))
    child["evidence_payloads"] = payloads
    del child["digest"]
    child["digest"] = digest(child)
    encoded = canonical_bytes(child)
    retained["lifecycle_certificate"] = base64.b64encode(encoded).decode("ascii")
    request["lifecycle_certificate_digest"] = byte_digest(encoded)
    evidence = canonical_bytes(retained)
    request["evidence_ref"] = byte_digest(evidence)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_selected_input_byte_capacity_is_unavailable_not_semantic_failure():
    request, policy, evidence = fixture()
    certificate, _ = replay(request, policy, evidence)
    policy = deepcopy(policy)
    policy["max_certificate_bytes"] = 1
    request = deepcopy(request)
    request["policy_digest"] = digest(policy)
    with pytest.raises(closure.RoleClosureUnavailable):
        closure.recheck_role_closure_certificate(certificate, expected_request=request, policy=policy)


def test_public_route_and_inventory_preserve_finite_scope(tmp_path, capsys):
    from verifier.domains.inventory import get_slot
    from verifier.domains.contracts.current_object_routes import replay_current_object_certificate
    from verifier.runtime.public_cli import main
    request, policy, evidence = fixture(handover=True)
    certificate, result = replay(request, policy, evidence)
    public = replay_current_object_certificate(certificate, semantic_version=closure.SEMANTIC_VERSION,
        objective=closure.COORDINATE, represented_kind="ROLE", expected_request=request, policy=policy)
    assert public["computational_status"] == "PASS"
    assert public["native_result"] == result
    assert result["whole_tier_conformance"] == result["authority"] == "NOT_ESTABLISHED"
    slot = get_slot("ROLE", 4)
    assert slot.coordinate == "ROLE-4.1" and slot.mechanized and slot.status == "REPLAYABLE"
    for name, raw in (("certificate", certificate), ("request", canonical_bytes(request)), ("policy", canonical_bytes(policy))):
        (tmp_path/(name+".json")).write_bytes(raw)
    assert main(["current-object", "check", str(tmp_path/"certificate.json"), "--semantic-version", closure.SEMANTIC_VERSION,
        "--objective", closure.COORDINATE, "--represented-kind", "ROLE", "--request", str(tmp_path/"request.json"),
        "--policy", str(tmp_path/"policy.json"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
