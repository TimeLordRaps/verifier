"""Adversarial finite current COLLECTIVE membership-transition replay.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Selected events declare, rather than prove, history.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import collective_constraints as statics
from verifier.domains.contracts import collective_lifecycle as contract


def digest(value: Any) -> str:
    return "sha256:" + canonical_digest(value)


def bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def defaults() -> list[dict[str, Any]]:
    return [{"names": ["role-a", "role-b"]},
            {"names": ["role-a", "role-b", "role-c"]},
            {"names": ["role-a", "role-b"]}]


def endpoint(state: dict[str, Any], position: int, limits: dict[str, int] | None = None
             ) -> tuple[dict[str, Any], bytes]:
    charter = state.get("charter", b"Record decisions under the selected charter.")
    quorum = state.get("quorum", 2)
    roles = [NamespaceObject.create(name, "ROLE", state.get("role_payloads", {}).get(name, {"purpose": name}))
             for name in state["names"]]
    members = [{"role_id": role.object_id, "role_digest": role.digest} for role in roles]
    collective = NamespaceObject.create("collective", "COLLECTIVE", {
        "name": state.get("name", "selected-team"), "static_constraints": {
            "schema_version": statics.CONSTRAINTS_VERSION, "charter_digest": bytes_digest(charter),
            "membership_digest": digest(members), "quorum": quorum}},
        {"roles": [row["role_id"] for row in members]})
    other = NamespaceObject.create("unrelated", "HUMAN", {"marker": state.get("marker", 0)})
    objects = [collective, *roles, other, *state.get("extra", [])]
    policy = statics.collective_constraints_policy(trust_roots=["retained-declarations"],
        selected_members=members, charter_digest=bytes_digest(charter), quorum=quorum)
    evidence = canonical_bytes({"schema_version": statics.EVIDENCE_VERSION,
        "objects": [obj.to_dict() for obj in objects], "inputs": {
            "membership": members, "quorum": quorum,
            "charter": {"sha256": bytes_digest(charter),
                        "base64": base64.b64encode(charter).decode("ascii")}}})
    request = statics.collective_constraints_request(subject_id="collective", object_digest=collective.digest,
        collection_digest=composition_digest(objects), evidence_ref=bytes_digest(evidence), policy=policy, limits=limits)
    certificate = statics.build_collective_constraints_certificate(request, evidence, policy=policy)
    return {"time_us": position * 10, "certificate_ref": bytes_digest(certificate),
            "static_request": request, "static_policy": policy}, certificate


def specimen(*, states: list[dict[str, Any]] | None = None,
             selected_events: list[dict[str, Any]] | None = None,
             limits: dict[str, int] | None = None,
             child_limits: dict[int, dict[str, int]] | None = None
             ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    selected_states = defaults() if states is None else states
    pairs = [endpoint(state, position, (child_limits or {}).get(position))
             for position, state in enumerate(selected_states)]
    role = NamespaceObject.create("role-c", "ROLE", {"purpose": "role-c"})
    events = [{"position": 0, "event_id": "admit-c", "time_us": 10,
               "action": "ADMIT", "role_id": "role-c", "role_digest": role.digest},
              {"position": 1, "event_id": "depart-c", "time_us": 20,
               "action": "DEPART", "role_id": "role-c", "role_digest": role.digest}]
    if selected_events is not None:
        events = selected_events
    policy = contract.collective_lifecycle_policy(trust_roots=["selected-trace"],
        clock_id="declared-clock", selected_events=events)
    evidence = canonical_bytes({"schema_version": contract.EVIDENCE_VERSION,
        "clock_id": "declared-clock", "events": events,
        "endpoint_certificates": [base64.b64encode(pair[1]).decode("ascii") for pair in pairs]})
    terminal = pairs[-1][0]["static_request"]
    request = contract.collective_lifecycle_request(subject_id="collective",
        object_digest=terminal["object_digest"], collection_digest=terminal["collection_digest"],
        evidence_ref=bytes_digest(evidence), endpoints=[pair[0] for pair in pairs], policy=policy, limits=limits)
    return request, policy, evidence


def replay(request: dict[str, Any], policy: dict[str, Any], evidence: bytes | None) -> dict[str, Any]:
    certificate = contract.build_collective_lifecycle_certificate(request, evidence, policy=policy)
    return contract.recheck_collective_lifecycle_certificate(certificate, expected_request=request, policy=policy)


def rebound(request: dict[str, Any], policy: dict[str, Any], value: dict[str, Any], *,
            select_events: bool = False, select_refs: bool = False
            ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    selected, admitted = deepcopy(request), deepcopy(policy)
    if select_events:
        admitted = contract.collective_lifecycle_policy(trust_roots=policy["trust_roots"],
            clock_id=policy["clock_id"], selected_events=value["events"])
        selected["policy_digest"] = digest(admitted)
    if select_refs:
        for index, encoded in enumerate(value["endpoint_certificates"]):
            if encoded is not None:
                selected["endpoints"][index]["certificate_ref"] = bytes_digest(base64.b64decode(encoded))
    evidence = canonical_bytes(value)
    selected["evidence_ref"] = bytes_digest(evidence)
    return selected, admitted, evidence


def fixture_for_integration(status: str) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    """Return native evidence for a selected actual PASS, FAIL or UNKNOWN case."""
    request, policy, evidence = specimen()
    if status == "FAIL":
        value = json.loads(evidence)
        value["events"][0]["role_id"] = "role-a"
        value["events"][0]["role_digest"] = NamespaceObject.create("role-a", "ROLE", {"purpose": "role-a"}).digest
        request, policy, evidence = rebound(request, policy, value, select_events=True)
    elif status == "UNKNOWN":
        evidence = None
    elif status != "PASS":
        raise ValueError("unsupported integration specimen status")
    certificate = contract.build_collective_lifecycle_certificate(request, evidence, policy=policy)
    return certificate, request, policy


@pytest.mark.parametrize("status", ["PASS", "FAIL", "UNKNOWN"])
def test_integration_fixture_uses_real_native_outcomes(status: str) -> None:
    certificate, request, policy = fixture_for_integration(status)
    assert contract.recheck_collective_lifecycle_certificate(certificate,
        expected_request=request, policy=policy)["status"] == status


def test_selected_admission_departure_replays_real_static_children_and_exact_frame() -> None:
    request, policy, evidence = specimen()
    result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["coordinate"] == "COLLECTIVE-2.1" and result["object_kind"] == "COLLECTIVE"
    facts = result["evaluation"]["observations"]
    assert facts["events_replayed"] == 2 and facts["endpoints_rechecked"] == 3
    assert facts["child_operation_bound_reserved"] == 300000
    assert facts["child_composition_bound_reserved"] == 300000
    assert facts["clock_id"] == "declared-clock" and facts["time_unit"] == "microsecond"
    for field in ("object_profile_conformance", "whole_tier_conformance", "authority",
                  "actual_execution", "real_event_completeness", "physical_clock", "actual_quorum_decision"):
        assert result[field] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("case", ["charter", "quorum", "name", "persistent-role", "unrelated", "extra-record"])
def test_genuine_passing_static_endpoints_cannot_authorize_undeclared_frame_changes(case: str) -> None:
    states = defaults()
    middle = states[1]
    if case == "charter":
        middle["charter"] = b"Different retained charter."
    elif case == "quorum":
        middle["quorum"] = 1
    elif case == "name":
        middle["name"] = "different-team"
    elif case == "persistent-role":
        middle["role_payloads"] = {"role-a": {"purpose": "changed"}}
    elif case == "unrelated":
        middle["marker"] = "changed"
    else:
        middle["extra"] = [NamespaceObject.create("extra", "HUMAN", {})]
    request, policy, evidence = specimen(states=states)
    for index, encoded in enumerate(json.loads(evidence)["endpoint_certificates"]):
        child = request["endpoints"][index]
        assert statics.recheck_collective_constraints_certificate(base64.b64decode(encoded),
            expected_request=child["static_request"], policy=child["static_policy"])["status"] == "PASS"
    assert replay(request, policy, evidence)["status"] == "FAIL"


@pytest.mark.parametrize("before,after", [(0, False), (1, True), (1, 1.0)])
@pytest.mark.parametrize("kind", ["unrelated", "persistent-role"])
def test_python_equal_numeric_or_boolean_payloads_still_change_canonical_frame(
        before: Any, after: Any, kind: str) -> None:
    assert before == after and canonical_bytes(before) != canonical_bytes(after)
    states = defaults()
    if kind == "unrelated":
        for state in states:
            state["marker"] = before
        states[1]["marker"] = after
    else:
        for state in states:
            state["role_payloads"] = {"role-a": {"marker": before}}
        states[1]["role_payloads"] = {"role-a": {"marker": after}}
    assert replay(*specimen(states=states))["status"] == "FAIL"


@pytest.mark.parametrize("case", ["wrong-position", "duplicate-id", "backward-time", "wrong-endpoint-time",
    "wrong-role-digest", "admit-existing", "depart-absent", "wrong-added-role"])
def test_fully_external_selected_false_transition_inventory_is_refuted(case: str) -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    events = value["events"]
    if case == "wrong-position":
        events[0]["position"] = 1
    elif case == "duplicate-id":
        events[1]["event_id"] = events[0]["event_id"]
    elif case == "backward-time":
        events[1]["time_us"] = 5
        request["endpoints"][2]["time_us"] = 5
    elif case == "wrong-endpoint-time":
        events[0]["time_us"] = 11
    elif case == "wrong-role-digest":
        events[0]["role_digest"] = "sha256:" + "0" * 64
    elif case == "admit-existing":
        events[0]["role_id"] = "role-a"
    elif case == "depart-absent":
        events[1]["role_id"] = "outside"
    else:
        events[0]["role_id"] = "role-d"
    assert replay(*rebound(request, policy, value, select_events=True))["status"] == "FAIL"


def test_selected_endpoint_inventory_cannot_omit_a_transition() -> None:
    request, policy, evidence = specimen()
    request["endpoints"] = [request["endpoints"][0], request["endpoints"][-1]]
    assert replay(request, policy, evidence)["status"] == "FAIL"


@pytest.mark.parametrize("field", ["clock_id", "events", "endpoint_certificates"])
@pytest.mark.parametrize("omit", [False, True])
def test_absent_retained_lifecycle_inputs_remain_unknown(field: str, omit: bool) -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    if omit:
        del value[field]
    else:
        value[field] = None
    assert replay(*rebound(request, policy, value))["status"] == "UNKNOWN"


@pytest.mark.parametrize("index", [0, 1, 2])
def test_absent_retained_child_certificate_remains_unknown(index: int) -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    value["endpoint_certificates"][index] = None
    assert replay(*rebound(request, policy, value))["status"] == "UNKNOWN"


def test_omitted_tail_certificates_remain_unknown() -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    value["endpoint_certificates"] = value["endpoint_certificates"][:1]
    assert replay(*rebound(request, policy, value))["status"] == "UNKNOWN"


def test_missing_bundle_remains_unknown() -> None:
    request, policy, _ = specimen()
    assert replay(request, policy, None)["status"] == "UNKNOWN"


def test_missing_child_does_not_mask_an_available_forbidden_transition() -> None:
    states = defaults()
    states[1]["marker"] = False
    request, policy, evidence = specimen(states=states)
    value = json.loads(evidence)
    value["endpoint_certificates"][2] = None
    assert replay(*rebound(request, policy, value))["status"] == "FAIL"


def test_missing_clock_does_not_mask_present_event_substitution() -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    del value["clock_id"]
    value["events"][0]["role_digest"] = "sha256:" + "0" * 64
    assert replay(*rebound(request, policy, value))["status"] == "FAIL"


def test_missing_child_does_not_mask_another_child_commitment_forgery() -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    value["endpoint_certificates"][0] = None
    value["endpoint_certificates"][1] = base64.b64encode(b"forged").decode("ascii")
    assert replay(*rebound(request, policy, value))["status"] == "FAIL"


def test_unknown_static_child_is_rechecked_and_remains_unknown() -> None:
    assert replay(*specimen(child_limits={1: {"max_evidence_bytes": 1}}))["status"] == "UNKNOWN"


def test_rehashed_unknown_static_child_cannot_supply_an_embedded_pass() -> None:
    request, policy, evidence = specimen(child_limits={1: {"max_evidence_bytes": 1}})
    value = json.loads(evidence)
    child = json.loads(base64.b64decode(value["endpoint_certificates"][1]))
    assert child["result"]["status"] == "UNKNOWN"
    child["result"]["status"] = "PASS"
    child["digest"] = digest({key: item for key, item in child.items() if key != "digest"})
    value["endpoint_certificates"][1] = base64.b64encode(canonical_bytes(child)).decode("ascii")
    assert replay(*rebound(request, policy, value, select_refs=True))["status"] == "FAIL"


def test_false_static_child_is_refuted_before_dynamic_promotion() -> None:
    states = defaults()
    states[1]["quorum"] = 4
    assert replay(*specimen(states=states))["status"] == "FAIL"


@pytest.mark.parametrize("select_ref", [False, True])
def test_genuine_child_bytes_cannot_substitute_independent_endpoint_selection(select_ref: bool) -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    value["endpoint_certificates"][0] = value["endpoint_certificates"][1]
    assert replay(*rebound(request, policy, value, select_refs=select_ref))["status"] == "FAIL"


@pytest.mark.parametrize("field", ["status", "object_profile_conformance", "authority"])
def test_rehashed_embedded_child_result_is_never_trusted(field: str) -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    child = json.loads(base64.b64decode(value["endpoint_certificates"][1]))
    child["result"][field] = "FAIL" if field == "status" else "PASS"
    child["digest"] = digest({key: item for key, item in child.items() if key != "digest"})
    value["endpoint_certificates"][1] = base64.b64encode(canonical_bytes(child)).decode("ascii")
    assert replay(*rebound(request, policy, value, select_refs=True))["status"] == "FAIL"


@pytest.mark.parametrize("field", ["subject_id", "object_digest", "collection_digest", "policy_digest"])
def test_parent_cannot_substitute_terminal_or_child_authoritative_selection(field: str) -> None:
    request, policy, evidence = specimen()
    if field == "policy_digest":
        request["endpoints"][0]["static_request"][field] = "sha256:" + "0" * 64
    else:
        request[field] = "other" if field == "subject_id" else "sha256:" + "0" * 64
    with pytest.raises(contract.CollectiveLifecycleError):
        contract.build_collective_lifecycle_certificate(request, evidence, policy=policy)


@pytest.mark.parametrize("bound", ["max_operations", "max_items", "max_events", "max_evidence_bytes",
    "max_depth", "max_child_certificate_bytes", "max_child_operations", "max_child_composition_operations"])
def test_every_selected_parent_or_aggregate_budget_is_enforced(bound: str) -> None:
    assert replay(*specimen(limits={bound: 1}))["status"] == "UNKNOWN"


def test_exact_selected_boundaries_are_inclusive_and_one_less_is_unknown() -> None:
    request, policy, evidence = specimen()
    facts = replay(request, policy, evidence)["evaluation"]["observations"]
    largest_child = max(len(base64.b64decode(encoded))
                        for encoded in json.loads(evidence)["endpoint_certificates"])
    thresholds = {"max_operations": facts["operations"], "max_evidence_bytes": len(evidence),
        "max_events": 2, "max_items": 6, "max_depth": 3, "max_child_certificate_bytes": largest_child,
        "max_child_operations": 300000, "max_child_composition_operations": 300000}
    for bound, threshold in thresholds.items():
        assert replay(*specimen(limits={bound: threshold}))["status"] == "PASS", bound
        assert replay(*specimen(limits={bound: threshold - 1}))["status"] == "UNKNOWN", bound


def test_unsupported_action_and_empty_external_trace_are_not_passing_replays() -> None:
    request, policy, evidence = specimen()
    value = json.loads(evidence)
    value["events"][0]["action"] = "UPDATE"
    assert replay(*rebound(request, policy, value, select_events=True))["status"] == "UNKNOWN"
    assert replay(*specimen(selected_events=[]))["status"] == "UNKNOWN"


@pytest.mark.parametrize("raw", [b"{", b'{"schema_version":"x","schema_version":"y"}', b"{}\n"])
def test_malformed_duplicate_key_or_noncanonical_parent_evidence_is_refuted(raw: bytes) -> None:
    request, policy, _ = specimen()
    request["evidence_ref"] = bytes_digest(raw)
    assert replay(request, policy, raw)["status"] == "FAIL"


def test_parser_depth_exhaustion_precedes_recursive_loading() -> None:
    request, policy, _ = specimen()
    evidence = b"[" * 2000 + b"0" + b"]" * 2000
    request["evidence_ref"] = bytes_digest(evidence)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"


@pytest.mark.parametrize("field", ["status", "authority", "whole_tier_conformance", "actual_execution"])
def test_rehashed_parent_certificate_cannot_promote_or_replace_its_result(field: str) -> None:
    request, policy, evidence = specimen()
    value = json.loads(contract.build_collective_lifecycle_certificate(request, evidence, policy=policy))
    value["result"][field] = "FAIL" if field == "status" else "PASS"
    value["digest"] = digest({key: item for key, item in value.items() if key != "digest"})
    with pytest.raises(contract.CollectiveLifecycleError):
        contract.recheck_collective_lifecycle_certificate(canonical_bytes(value), expected_request=request, policy=policy)


@pytest.mark.parametrize("relative", ["core/namespace.py", "domains/contracts/collective_constraints.py",
    "domains/contracts/collective_lifecycle.py", "standard/CURRENT_COLLECTIVE_CONSTRAINTS.md",
    "standard/CURRENT_COLLECTIVE_LIFECYCLE.md", "standard/NAMESPACE_OBJECTS.md"])
def test_changed_shared_contract_or_specification_bytes_invalidate_selected_policy(relative: str,
                                                                                   monkeypatch: Any) -> None:
    request, policy, evidence = specimen()
    original = Path.read_bytes
    target = Path(statics.namespace_module.__file__).parents[1] / relative
    if relative.startswith("domains/contracts/") or relative.endswith("CURRENT_COLLECTIVE_CONSTRAINTS.md"):
        target = Path(statics.__file__).parents[2] / relative
    if relative.endswith("CURRENT_COLLECTIVE_LIFECYCLE.md"):
        target = Path(contract.__file__).parents[2] / relative
    def changed(path: Path) -> bytes:
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(contract.CollectiveLifecycleError):
        contract.build_collective_lifecycle_certificate(request, evidence, policy=policy)
