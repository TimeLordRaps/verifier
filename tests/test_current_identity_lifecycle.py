"""Native identity lifecycle dependency and transport regressions.

JavaScript Object Notation (JSON).
"""
from __future__ import annotations
import copy
from asyncio import CancelledError
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.evidence import EvidenceStore
from verifier.core.namespace import NamespaceObject
from verifier.domains.common import digest
from verifier.domains.contracts import identity_lifecycle as native
from test_current_identity_scope import inputs as child_inputs
from test_identity_lifecycle_replay import binding, history, presentation, present_event, revoke


def selected(kind="HUMAN", *, tail=None, rows=None, absent_child=False, child_limit=None, **request_overrides):
    child, child_request, child_policy, child_evidence = child_inputs(kind, **(child_limit or {}))
    child_bytes = child.build_identity_scope_certificate(child_request, child_evidence, policy=child_policy)
    evidence_map = json.loads(child_evidence)
    declaration = evidence_map["declaration"]
    b = binding(kind)
    b.update(identity_id=child_request["subject_id"], identity_record_digest=child_request["object_digest"][7:],
             actor_id=declaration["actor_id"], representation_id=declaration["representation_id"],
             root_human_id=declaration["root_human_id"], role_id=declaration["role_id"],
             collective_id=declaration["collective_id"], scope=declaration["scope"])
    if kind == "BOT":
        b["simulation_id"] = declaration["scope"].split(":", 1)[1]
        sim = next(row for row in evidence_map["objects"] if row["object_id"] == b["simulation_id"])
        b["simulation_record_digest"] = NamespaceObject.create(**sim).digest[7:]
    if callable(tail):
        tail, rows = tail(b)
    events = history(b, tail or [])
    rows = rows or []
    value = {"schema_version": native.EVIDENCE_VERSION, "binding": b, "events": events,
             "presentations": rows, "identity_scope_certificate": None if absent_child else json.loads(child_bytes)}
    policy = native.identity_lifecycle_policy(trust_roots=["synthetic-selected-declared-history"], identity_scope_policy=child_policy)
    kwargs = dict(identity_scope_request=child_request, identity_scope_certificate_ref=EvidenceStore().add(child_bytes),
                  binding_digest=digest(b), events_digest=digest(events), presentation_inventory_digest=digest(rows),
                  initial_event_anchor="sha256:" + "0" * 64, selected_head_digest=digest(events[-1]),
                  selected_event_count=len(events), clock_id=b["clock_id"], evaluation_at=50, renewal_ceiling=200,
                  evidence_ref=digest(value), policy=policy)
    kwargs.update(request_overrides)
    request = native.identity_lifecycle_request(**kwargs)
    return request, policy, canonical_bytes(value)


def replay(request, policy, data):
    certificate = native.build_identity_lifecycle_certificate(request, data, policy=policy)
    return native.recheck_identity_lifecycle_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("kind", ["HUMAN", "AGENT", "BOT"])
def test_actual_child_and_selected_finite_declared_history_can_pass_without_authority(kind):
    request, policy, data = selected(kind)
    result = replay(request, policy, data)
    assert result["status"] == "PASS"
    assert result["evaluation"]["observations"]["identity_scope"]["status"] == "PASS"
    for field in ("authority", "occupancy_liveness", "actual_log_completeness", "public_checkability",
                  "whole_identity_closure", "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"


def test_valid_terminal_history_pass_is_independent_of_live_eligibility():
    def retained(b):
        row = presentation(b, 20)
        return [present_event(row), revoke(30)], [row]
    request, policy, data = selected(tail=retained, evaluation_at=40)
    result = replay(request, policy, data)
    assert result["status"] == "PASS"
    facts = result["evaluation"]["observations"]["declared_lifecycle"]
    assert facts["presentation_results"][0]["declared_binding_eligibility"] == "PASS"
    assert facts["declared_reliance_eligibility"] == "FAIL"


@pytest.mark.parametrize("field", ["initial_event_anchor", "selected_head_digest", "selected_event_count", "clock_id"])
def test_missing_required_external_history_selections_stay_unknown(field):
    request, policy, data = selected(**{field: None})
    assert replay(request, policy, data)["status"] == "UNKNOWN"


def test_missing_outer_or_child_support_and_child_bound_exhaustion_stay_unknown():
    request, policy, data = selected()
    assert replay(request, policy, None)["status"] == "UNKNOWN"
    request, policy, data = selected(absent_child=True)
    assert replay(request, policy, data)["status"] == "UNKNOWN"
    request, policy, data = selected(child_limit={"max_relation_steps": 1})
    assert replay(request, policy, data)["status"] == "UNKNOWN"


def test_evaluated_lifecycle_refutation_dominates_missing_child_and_head():
    def retained(b):
        row = presentation(b, 30)
        return [present_event(row), revoke(30)], [row]
    request, policy, data = selected(tail=retained, absent_child=True, selected_head_digest=None)
    assert replay(request, policy, data)["status"] == "FAIL"


@pytest.mark.parametrize("field", ["selected_head_digest", "events_digest", "binding_digest", "identity_scope_certificate_ref"])
def test_external_pins_are_not_recovered_from_candidate_bytes(field):
    request, policy, data = selected(**{field: "sha256:" + "9" * 64})
    assert replay(request, policy, data)["status"] == "FAIL"


def test_child_native_refuses_rehashed_authority_upgrade():
    request, policy, data = selected()
    value = json.loads(data)
    child = value["identity_scope_certificate"]
    child["result"]["authority"] = "PASS"
    child["digest"] = digest({k: v for k, v in child.items() if k != "digest"})
    request["identity_scope_certificate_ref"] = digest(child)
    request["evidence_ref"] = digest(value)
    assert replay(request, policy, canonical_bytes(value))["status"] == "FAIL"


def test_declared_binding_cannot_change_relation_after_native_child_pass():
    request, policy, data = selected()
    value = json.loads(data)
    value["binding"]["root_human_id"] = "another-root"
    value["events"] = history(value["binding"], [])
    request.update(binding_digest=digest(value["binding"]), events_digest=digest(value["events"]),
                   selected_head_digest=digest(value["events"][-1]), evidence_ref=digest(value))
    assert replay(request, policy, canonical_bytes(value))["status"] == "FAIL"


def test_exact_bot_sim_record_cannot_be_rehashed_to_another_record():
    request, policy, data = selected("BOT")
    value = json.loads(data)
    value["binding"]["simulation_record_digest"] = "9" * 64
    value["events"] = history(value["binding"], [])
    request.update(binding_digest=digest(value["binding"]), events_digest=digest(value["events"]),
                   selected_head_digest=digest(value["events"][-1]), evidence_ref=digest(value))
    assert replay(request, policy, canonical_bytes(value))["status"] == "FAIL"


@pytest.mark.parametrize("field", ["status", "authority", "whole_identity_closure", "object_profile_conformance"])
def test_rehashed_outer_result_or_retained_evidence_omission_refuses_transport(field):
    request, policy, data = selected()
    certificate = native.build_identity_lifecycle_certificate(request, data, policy=policy)
    value = json.loads(certificate)
    value["result"][field] = "FAIL" if field == "status" else "PASS"
    value["digest"] = digest({k: v for k, v in value.items() if k != "digest"})
    with pytest.raises(ValueError):
        native.recheck_identity_lifecycle_certificate(canonical_bytes(value), expected_request=request, policy=policy)
    value = json.loads(certificate)
    value["evidence_payloads"] = {}
    value["digest"] = digest({k: v for k, v in value.items() if k != "digest"})
    with pytest.raises(ValueError):
        native.recheck_identity_lifecycle_certificate(canonical_bytes(value), expected_request=request, policy=policy)


@pytest.mark.parametrize("field", ["max_steps", "max_events", "max_evidence_bytes"])
def test_selected_work_or_evidence_bounds_do_not_become_pass(field):
    request, policy, data = selected(tail=[revoke(30)], limits={field: 1})
    assert replay(request, policy, data)["status"] == "UNKNOWN"


@pytest.mark.parametrize("relative", ["domains/contracts/identity_lifecycle.py", "domains/contracts/identity_lifecycle_replay.py",
    "domains/contracts/identity_scope.py", "domains/contracts/identity_occupancy.py",
    "standard/CURRENT_IDENTITY_LIFECYCLE.md", "standard/CURRENT_IDENTITY_SCOPE.md", "core/evidence.py",
    "schemas/identity_lifecycle_evidence.json"])
def test_direct_and_recursive_child_source_drift_invalidates_old_policy(relative, monkeypatch):
    request, policy, data = selected()
    certificate = native.build_identity_lifecycle_certificate(request, data, policy=policy)
    target = Path(native.__file__).parents[2] / relative
    original = Path.read_bytes
    def changed(path):
        value = original(path)
        return value + b"\nchanged selected lifecycle dependency\n" if path == target else value
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        native.recheck_identity_lifecycle_certificate(certificate, expected_request=request, policy=policy)


def _request_kwargs(request, policy):
    excluded = {"schema_version", "semantic_version", "coordinate", "proposition_digest",
                "object_kind", "subject_id", "object_digest", "collection_digest", "protocol_id", "policy_digest"}
    return {**{key: value for key, value in request.items() if key not in excluded}, "policy": policy}


@pytest.mark.parametrize("entry", ["policy", "request", "build", "recheck"])
def test_every_public_entry_owns_all_nested_selections_before_source_callbacks(entry, monkeypatch):
    request, policy, data = selected()
    certificate = native.build_identity_lifecycle_certificate(request, data, policy=policy)
    expected_result = native.recheck_identity_lifecycle_certificate(certificate, expected_request=request, policy=policy)
    incoming_request, incoming_policy = copy.deepcopy(request), copy.deepcopy(policy)
    original = native.mechanism_digest
    def mutate_then_read():
        incoming_policy["trust_roots"].append("caller-mutated-root")
        incoming_policy["identity_scope_policy"]["trust_roots"].append("caller-mutated-child-root")
        incoming_request["identity_scope_request"]["subject_id"] = "caller-mutated-child"
        incoming_request["identity_scope_request"]["limits"]["max_relation_steps"] = 1
        incoming_request["limits"]["max_steps"] = 1
        incoming_request["subject_id"] = "caller-mutated-parent"
        return original()
    monkeypatch.setattr(native, "mechanism_digest", mutate_then_read)
    if entry == "policy":
        result = native.identity_lifecycle_policy(trust_roots=incoming_policy["trust_roots"],
            identity_scope_policy=incoming_policy["identity_scope_policy"],
            max_certificate_bytes=incoming_policy["max_certificate_bytes"])
        assert result == policy
    elif entry == "request":
        assert native.identity_lifecycle_request(**_request_kwargs(incoming_request, incoming_policy)) == request
    elif entry == "build":
        assert native.build_identity_lifecycle_certificate(incoming_request, data, policy=incoming_policy) == certificate
    else:
        assert native.recheck_identity_lifecycle_certificate(certificate,
            expected_request=incoming_request, policy=incoming_policy) == expected_result


@pytest.mark.parametrize("entry", ["policy", "request", "build", "recheck"])
def test_every_public_entry_refuses_foreign_nested_mapping_before_any_source_call(entry, monkeypatch):
    request, policy, data = selected()
    certificate = native.build_identity_lifecycle_certificate(request, data, policy=policy)
    touched = []
    class Foreign(dict):
        def items(self):
            touched.append("foreign")
            raise AssertionError("foreign mapping callback")
    def source():
        touched.append("source")
        raise AssertionError("source read before plain capture")
    monkeypatch.setattr(native, "mechanism_digest", source)
    with pytest.raises(native.IdentityLifecycleError, match="plain bounded JSON"):
        if entry == "policy":
            native.identity_lifecycle_policy(trust_roots=policy["trust_roots"], identity_scope_policy=Foreign(policy["identity_scope_policy"]))
        elif entry == "request":
            kwargs = _request_kwargs(request, policy)
            kwargs["limits"] = Foreign(request["limits"])
            native.identity_lifecycle_request(**kwargs)
        elif entry == "build":
            request["identity_scope_request"]["limits"] = Foreign(request["identity_scope_request"]["limits"])
            native.build_identity_lifecycle_certificate(request, data, policy=policy)
        else:
            policy["identity_scope_policy"] = Foreign(policy["identity_scope_policy"])
            native.recheck_identity_lifecycle_certificate(certificate, expected_request=request, policy=policy)
    assert touched == []


def test_registration_returns_owned_proposition():
    first = native.registration()
    first["prerequisites"].append("caller-owned mutation")
    assert native.registration() == native.PROPOSITION
    assert first != native.PROPOSITION


@pytest.mark.parametrize("error", [RecursionError, OverflowError])
def test_actual_parent_decode_resource_error_is_unknown_and_public_recheck_is_typed_unavailable(error, monkeypatch):
    request, policy, data = selected()
    certificate = native.build_identity_lifecycle_certificate(request, data, policy=policy)
    def unavailable(_):
        raise error("injected exact retained reader exhaustion")
    monkeypatch.setattr(native, "strict_json_loads", unavailable)
    assert native._evaluate(data, request, policy).outcome.value == "UNKNOWN"
    with pytest.raises(native.IdentityLifecycleUnavailable):
        native.recheck_identity_lifecycle_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("error", [RecursionError, OverflowError])
@pytest.mark.parametrize("reader_call", [1, 2])
def test_exact_child_certificate_and_evidence_reader_resource_sites_remain_unknown(error, reader_call, monkeypatch):
    # Call 1 is the native3 retained certificate reader; call 2 is its actual
    # evidence reader during _build. ROOT must retain typed unavailability across
    # the latter UNKNOWN rebuild mismatch. No blanket ValueError downgrade.
    request, policy, data = selected()
    original = native.identity_scope.strict_json_loads
    calls = 0
    def reader(text):
        nonlocal calls
        calls += 1
        if calls == reader_call:
            raise error("injected exact child internal reader exhaustion")
        return original(text)
    monkeypatch.setattr(native.identity_scope, "strict_json_loads", reader)
    decision = native._evaluate(data, request, policy)
    assert decision.outcome.value == "UNKNOWN"
    assert decision.observations["identity_scope"]["status"] == "UNKNOWN"


def test_retained_depth_fence_precedes_any_recursive_decoder_and_hash(monkeypatch):
    request, policy, _ = selected()
    deep = b"[" * 65 + b"0" + b"]" * 65
    def forbidden(_):
        raise AssertionError("recursive work before depth fence")
    monkeypatch.setattr(native, "strict_json_loads", forbidden)
    monkeypatch.setattr(native, "canonical_digest", forbidden)
    assert native._evaluate(deep, request, policy).outcome.value == "UNKNOWN"
    # _policy needs the canonical digest: restore it before public admission.
    monkeypatch.undo()
    monkeypatch.setattr(native, "strict_json_loads", forbidden)
    with pytest.raises(native.IdentityLifecycleUnavailable, match="depth"):
        native.recheck_identity_lifecycle_certificate(deep, expected_request=request, policy=policy)


def test_retained_scanner_does_not_count_escaped_string_punctuation_as_depth():
    native._retained_preflight(canonical_bytes({"text": "[" * 1000 + '\\"' + "]" * 1000}), 8192)


@pytest.mark.parametrize("failure", ["subject", "clock", "head", "count"])
@pytest.mark.parametrize("error", [OSError, ImportError, CancelledError, RecursionError, OverflowError])
def test_known_local_refutations_survive_unavailable_child(failure, error, monkeypatch):
    request, policy, data = selected()
    value = json.loads(data)
    if failure == "subject":
        value["binding"]["identity_id"] = "independently-selected-false-subject"
        value["events"] = history(value["binding"], [])
        request.update(binding_digest=digest(value["binding"]), events_digest=digest(value["events"]),
                       selected_head_digest=digest(value["events"][-1]))
    elif failure == "clock":
        request["clock_id"] = "independently-selected-other-clock"
    elif failure == "head":
        request["selected_head_digest"] = "sha256:" + "9" * 64
    else:
        request["selected_event_count"] = len(value["events"]) + 1
    request["evidence_ref"] = digest(value)
    def unavailable(*args, **kwargs):
        raise error("native child unavailable")
    monkeypatch.setattr(native.identity_scope, "recheck_identity_scope_certificate", unavailable)
    decision = native._evaluate(canonical_bytes(value), request, policy)
    assert decision.outcome.value == "FAIL"
    assert decision.observations["identity_scope"]["status"] == "UNKNOWN"


def test_semantic_child_valueerror_is_not_downgraded_to_unavailability(monkeypatch):
    request, policy, data = selected()
    def refused(*args, **kwargs):
        raise ValueError("genuine child substitution")
    monkeypatch.setattr(native.identity_scope, "recheck_identity_scope_certificate", refused)
    assert native._evaluate(data, request, policy).outcome.value == "FAIL"


@pytest.mark.parametrize("missing, malformed", [("binding", "events"), ("presentations", "binding"),
                                                ("events", "presentations")])
def test_missing_companion_or_anchor_does_not_mask_present_independent_grammar(missing, malformed):
    request, policy, data = selected(absent_child=True, initial_event_anchor=None)
    value = json.loads(data)
    if malformed == "binding":
        value["binding"]["valid_from"] = True
        value["events"] = history(value["binding"], [])
    elif malformed == "events":
        value["events"][0]["position"] = True
    else:
        value["presentations"] = [presentation(value["binding"], True)]
    value[missing] = None
    for item, pin in (("binding", "binding_digest"), ("events", "events_digest"),
                      ("presentations", "presentation_inventory_digest")):
        if value[item] is not None:
            request[pin] = digest(value[item])
    if type(value["events"]) is list and value["events"]:
        request["selected_head_digest"] = digest(value["events"][-1])
        request["selected_event_count"] = len(value["events"])
    request["evidence_ref"] = digest(value)
    assert replay(request, policy, canonical_bytes(value))["status"] == "FAIL"


def test_outer_bundle_version_is_semantic_fail_while_protocol_version_is_unknown():
    request, policy, data = selected()
    value = json.loads(data)
    value["schema_version"] = "unsupported-outer-version"
    request["evidence_ref"] = digest(value)
    assert replay(request, policy, canonical_bytes(value))["status"] == "FAIL"
    request, policy, data = selected(absent_child=True)
    value = json.loads(data)
    value["binding"]["schema_version"] = "unsupported-binding-version"
    value["events"] = history(value["binding"], [])
    request.update(binding_digest=digest(value["binding"]), events_digest=digest(value["events"]),
                   selected_head_digest=digest(value["events"][-1]), evidence_ref=digest(value))
    assert replay(request, policy, canonical_bytes(value))["status"] == "UNKNOWN"


@pytest.mark.parametrize("field", ["authority", "scope", "policy_digest", "evaluation_outcome", "result_shape"])
def test_independently_malformed_carried_claims_refuse_before_unavailable_child(field, monkeypatch):
    request, policy, data = selected()
    value = json.loads(native.build_identity_lifecycle_certificate(request, data, policy=policy))
    if field == "policy_digest":
        value[field] = "sha256:" + "9" * 64
    elif field == "evaluation_outcome":
        value["result"]["evaluation"]["outcome"] = "UNKNOWN"
    elif field == "result_shape":
        del value["result"]["whole_identity_closure"]
    else:
        value["result"][field] = "PASS" if field == "authority" else "unselected-broader-scope"
    value["digest"] = digest({key: item for key, item in value.items() if key != "digest"})
    calls = []
    def unavailable(*args, **kwargs):
        calls.append(True)
        raise OSError("child reader unavailable")
    monkeypatch.setattr(native.identity_scope, "recheck_identity_scope_certificate", unavailable)
    with pytest.raises(native.IdentityLifecycleError):
        native.recheck_identity_lifecycle_certificate(canonical_bytes(value), expected_request=request, policy=policy)
    assert calls == []


def test_recheck_does_not_return_carried_pass_when_native_child_is_unavailable(monkeypatch):
    request, policy, data = selected()
    certificate = native.build_identity_lifecycle_certificate(request, data, policy=policy)
    def unavailable(*args, **kwargs):
        raise native.identity_scope.IdentityScopeUnavailable("actual selected native3 reader unavailable")
    monkeypatch.setattr(native.identity_scope, "recheck_identity_scope_certificate", unavailable)
    with pytest.raises(native.IdentityLifecycleUnavailable):
        native.recheck_identity_lifecycle_certificate(certificate, expected_request=request, policy=policy)


def test_child_claim_promotion_refuses_before_actual_child_evidence_reader_unavailability(monkeypatch):
    request, policy, data = selected()
    value = json.loads(data)
    child = value["identity_scope_certificate"]
    child["result"]["authority"] = "PASS"
    child["digest"] = digest({key: item for key, item in child.items() if key != "digest"})
    request["identity_scope_certificate_ref"] = digest(child)
    request["evidence_ref"] = digest(value)
    original, calls = native.identity_scope.strict_json_loads, 0
    def reader(text):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RecursionError("actual selected child evidence reader unavailable")
        return original(text)
    monkeypatch.setattr(native.identity_scope, "strict_json_loads", reader)
    assert native._evaluate(canonical_bytes(value), request, policy).outcome.value == "FAIL"
    assert calls == 1  # ROOT's independent child claim guard runs before _build.


@pytest.mark.parametrize("field, false_value", [("binding_digest", "9" * 64), ("clock_id", "other-clock"),
                                               ("scope", "other-scope"), ("simulation_id", "other-sim")])
@pytest.mark.parametrize("absent_child", [False, True])
def test_missing_events_do_not_mask_supported_present_row_binding_refutation(field, false_value, absent_child):
    request, policy, data = selected(absent_child=absent_child)
    value = json.loads(data)
    row = presentation(value["binding"], 20)
    row[field] = false_value
    value.update(events=None, presentations=[row])
    request.update(presentation_inventory_digest=digest([row]), evidence_ref=digest(value))
    assert replay(request, policy, canonical_bytes(value))["status"] == "FAIL"


def _honest_local_fail():
    def retained(b):
        row = presentation(b, 30)
        return [present_event(row), revoke(30)], [row]
    request, policy, data = selected(tail=retained)
    certificate = native.build_identity_lifecycle_certificate(request, data, policy=policy)
    assert json.loads(certificate)["result"]["status"] == "FAIL"
    return request, policy, data, certificate


@pytest.mark.parametrize("error", [RecursionError, OverflowError])
@pytest.mark.parametrize("reader_call", [1, 2])
def test_unchanged_honest_fail_with_actual_child_reader_capacity_loss_is_typed_unavailable(error, reader_call, monkeypatch):
    request, policy, data, certificate = _honest_local_fail()
    original, calls = native.identity_scope.strict_json_loads, 0
    def reader(text):
        nonlocal calls
        calls += 1
        if calls == reader_call:
            raise error("actual native3 reader capacity unavailable")
        return original(text)
    monkeypatch.setattr(native.identity_scope, "strict_json_loads", reader)
    decision = native._evaluate(data, request, policy)
    assert decision.outcome.value == "FAIL"
    assert decision.observations["declared_lifecycle"]["consistency_status"] == "FAIL"
    assert decision.observations["unavailable_execution"]
    calls = 0
    with pytest.raises(native.IdentityLifecycleUnavailable, match="evaluated FAIL retained"):
        native.recheck_identity_lifecycle_certificate(certificate, expected_request=request, policy=policy)


def test_unchanged_honest_fail_with_child_oserror_is_typed_unavailable(monkeypatch):
    request, policy, data, certificate = _honest_local_fail()
    def unavailable(*args, **kwargs):
        raise OSError("installed child unavailable")
    monkeypatch.setattr(native.identity_scope, "recheck_identity_scope_certificate", unavailable)
    decision = native._evaluate(data, request, policy)
    assert decision.outcome.value == "FAIL"
    assert decision.observations["unavailable_execution"]
    with pytest.raises(native.IdentityLifecycleUnavailable, match="evaluated FAIL retained"):
        native.recheck_identity_lifecycle_certificate(certificate, expected_request=request, policy=policy)


def test_carried_pass_contradicted_by_local_fail_refuses_even_with_unavailable_child(monkeypatch):
    request, policy, _, certificate = _honest_local_fail()
    value = json.loads(certificate)
    value["result"]["status"] = value["result"]["evaluation"]["outcome"] = "PASS"
    value["digest"] = digest({key: item for key, item in value.items() if key != "digest"})
    def unavailable(*args, **kwargs):
        raise OSError("installed child unavailable")
    monkeypatch.setattr(native.identity_scope, "recheck_identity_scope_certificate", unavailable)
    with pytest.raises(native.IdentityLifecycleError):
        native.recheck_identity_lifecycle_certificate(canonical_bytes(value), expected_request=request, policy=policy)


def test_genuine_child_valueerror_refuses_despite_earlier_helper_resource_loss_and_carried_fail(monkeypatch):
    request, policy, _, certificate = _honest_local_fail()
    helper = native.identity_lifecycle_replay
    original, calls = helper._digest, 0
    def retained_hash(value):
        nonlocal calls
        if type(value) is dict and value.get("schema_version") == helper.PRESENTATION_VERSION:
            calls += 1
            if calls == 2:
                raise RecursionError("actual presentation hash unavailable")
        return original(value)
    def refused(*args, **kwargs):
        raise ValueError("genuine native child substitution")
    monkeypatch.setattr(helper, "_digest", retained_hash)
    monkeypatch.setattr(native.identity_scope, "recheck_identity_scope_certificate", refused)
    with pytest.raises(native.IdentityLifecycleError):
        native.recheck_identity_lifecycle_certificate(certificate, expected_request=request, policy=policy)


def test_selected_certificate_byte_checking_capacity_is_typed_unavailable():
    request, policy, data = selected()
    certificate = native.build_identity_lifecycle_certificate(request, data, policy=policy)
    policy = copy.deepcopy(policy)
    policy["max_certificate_bytes"] = 1
    request = copy.deepcopy(request)
    request["policy_digest"] = digest(policy)
    with pytest.raises(native.IdentityLifecycleUnavailable):
        native.recheck_identity_lifecycle_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("absent", [False, True])
def test_public_route_cli_and_inventory_preserve_declared_lifecycle_boundary(absent, tmp_path, capsys):
    from verifier.domains.inventory import get_slot
    from verifier.domains.contracts.current_object_routes import replay_current_object_certificate
    from verifier.runtime.public_cli import main
    request, policy, data = selected(absent_child=absent)
    certificate = native.build_identity_lifecycle_certificate(request, data, policy=policy)
    report = replay_current_object_certificate(certificate, semantic_version=native.SEMANTIC_VERSION,
        objective=native.COORDINATE, represented_kind="IDENTITY", expected_request=request, policy=policy)
    expected = "UNKNOWN" if absent else "PASS"
    assert report["computational_status"] == expected
    assert report["native_result"]["occupancy_liveness"] == "NOT_ESTABLISHED"
    assert report["native_result"]["whole_identity_closure"] == "NOT_ESTABLISHED"
    slot = get_slot("IDENTITY", 2)
    assert slot.mechanized and slot.coordinate == "IDENTITY-2.1" and slot.status == "REPLAYABLE"
    for name, raw in (("certificate",certificate),("request",canonical_bytes(request)),("policy",canonical_bytes(policy))):
        (tmp_path/(name+".json")).write_bytes(raw)
    assert main(["current-object","check",str(tmp_path/"certificate.json"),"--semantic-version",native.SEMANTIC_VERSION,
        "--objective",native.COORDINATE,"--represented-kind","IDENTITY","--request",str(tmp_path/"request.json"),
        "--policy",str(tmp_path/"policy.json"),"--json"]) == (2 if absent else 0)
    assert json.loads(capsys.readouterr().out)["computational_status"] == expected
