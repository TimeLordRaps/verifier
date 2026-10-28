"""Portable Simulation (SIM) and HYPER current-certificate emission tests."""
from __future__ import annotations

from copy import deepcopy
import base64
import hashlib
import json

import pytest
import test_current_arch_shapes as arch_shapes_fixture
import test_current_event_prerequisites as event_prerequisites_fixture
import test_current_hardware_inventory as hardware_inventory_fixture
import test_current_owner_eligibility as owner_eligibility_fixture
import test_current_sim_dynamics as sim_dynamics_fixture
import test_current_sim_external_law as sim_external_law_fixture
import test_current_sim_internal_state as sim_internal_state_fixture
import test_current_sim_perspective as sim_perspective_fixture
import test_current_sim_response as sim_response_fixture
import test_current_space_layout as space_layout_fixture
import test_current_time_order as time_order_fixture

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import EvidenceStore
from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import hyper_closure, object_grounding
from verifier.privacy.current_certificate_emission import (
    CurrentCertificateEmissionRefusal, evaluate_current_certificate_emission,
    recheck_current_certificate_emission,
)
from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
from verifier.privacy.models import (
    DisclosureBound, DisclosureSurface, EmissionContext, EmissionResult, ObserverParty,
)


REDACTION_FIXTURES = {
    "hardware_inventory": hardware_inventory_fixture,
    "time_order": time_order_fixture,
    "space_layout": space_layout_fixture,
    "event_prerequisites": event_prerequisites_fixture,
    "arch_shapes": arch_shapes_fixture,
    "sim_dynamics": sim_dynamics_fixture,
    "sim_response": sim_response_fixture,
    "sim_internal_state": sim_internal_state_fixture,
    "sim_perspective": sim_perspective_fixture,
    "sim_external_law": sim_external_law_fixture,
    "owner_eligibility": owner_eligibility_fixture,
}


def _sim_model():
    return {
        "schema_version": "verifier-sim-isolation-evidence-1", "sim_id": "sim",
        "initial_state": "idle",
        "virtual_hardware": [{"id": "cpu", "kind": "compute"}],
        "states": [{"id": "idle", "partition": "inside", "capabilities": ["cpu"]}],
        "actions": ["step"],
        "transitions": [{"source": "idle", "action": "step", "outcomes": [
            {"target": "idle", "effects": [{"kind": "internal_write", "target": "cpu"}]},
        ]}],
    }


def _sim_objects(isolation):
    make = NamespaceObject.create
    objects = [make("data", "DATA", {}), make("verifier", "VERIFIER", {}),
               make("room", "OBJECT", {}), make("env", "ENV", {})]
    objects.append(make("sim", "SIM", {
        "isolation_evidence_digest": "sha256:" + hashlib.sha256(isolation).hexdigest(),
    }, {"data": ["data"], "verifier": ["verifier"],
        "objects": ["room"], "env": ["env"]}))
    return objects


def _sim_inputs():
    module = object_grounding
    isolation = canonical_bytes(_sim_model())
    objects = _sim_objects(isolation)
    policy = module.current_object_policy(trust_roots=("local-independent-selection",))
    request = module.current_object_request(
        objects, sim_id="sim", isolation_evidence_bytes=isolation, policy=policy)
    return module, request, objects, isolation, policy


def _hyper_inputs():
    module = hyper_closure
    make = NamespaceObject.create
    objects = [make("t", "TIME", {}), make("s", "SPACE", {}),
               make("meaning", "OBJECT", {}), make("d", "DATA", {}),
               make("e", "EVENT", {}, {"time": ["t"], "space": ["s"],
                                        "meaning": ["meaning"]}),
               make("h", "HYPER", {}, {"event": ["e"], "input": ["d"]})]
    policy = module.hyper_closure_policy(trust_roots=["local-independent-selection"])
    request = module.hyper_closure_request(objects, hyper_id="h", policy=policy)
    return module, objects, request, policy


def _current(kind):
    if kind == "SIM":
        module, request, objects, isolation, policy = _sim_inputs()
        encoded = module.build_current_object_certificate(
            request, objects, isolation, policy=policy)
    else:
        module, objects, request, policy = _hyper_inputs()
        encoded = module.build_hyper_closure_certificate(request, objects, policy=policy)
    return module, request, policy, encoded


def _disclosure(kind, encoded, *, omit=(), observer="local-reader"):
    fields = tuple(json.loads(encoded))
    surface = DisclosureSurface(kind, tuple(key for key in fields if key not in omit), tuple(omit))
    bounds = tuple(DisclosureBound("bound:" + key, key, admitted_observers=(observer,))
                   for key in surface.disclosed_fields)
    context = EmissionContext(
        ObserverParty("local-reader", "reviewer", "local-evaluation"),
        "2026-09-27T00:00:00Z",
    )
    return surface, bounds, context


def _evaluate(kind, request, policy, encoded, disclosure):
    surface, bounds, context = disclosure
    return evaluate_current_certificate_emission(
        encoded, kind=kind, expected_request=request, policy=policy,
        surface=surface, bounds=bounds, context=context,
    )


@pytest.mark.parametrize("kind", ["SIM", "HYPER"])
def test_full_certificate_replays_exact_bytes_without_authority_promotion(kind):
    _module, request, policy, encoded = _current(kind)
    disclosure = _disclosure(kind, encoded)
    admitted = _evaluate(kind, request, policy, encoded, disclosure)
    assert admitted.emitted_certificate_bytes == encoded
    assert admitted.replay_status == "REPRODUCED"
    assert admitted.computational_status == "PASS"
    assert admitted.native_result["status"] == "PASS"
    assert admitted.privacy_result.receipt["certificate_validation"] == "NOT_CHECKED"
    assert admitted.privacy_result.receipt["observer_authentication"] == "NOT_CHECKED"
    assert not admitted.privacy_result.redacted_fields
    assert recheck_current_certificate_emission(
        admitted, encoded, kind=kind, expected_request=request, policy=policy,
        surface=disclosure[0], bounds=disclosure[1], context=disclosure[2])


@pytest.mark.parametrize("kind", ["SIM", "HYPER"])
def test_every_canonical_field_requires_full_disclosure(kind):
    _module, request, policy, encoded = _current(kind)
    for field in json.loads(encoded):
        with pytest.raises(CurrentCertificateEmissionRefusal):
            _evaluate(kind, request, policy, encoded, _disclosure(kind, encoded, omit=(field,)))
        certificate = json.loads(encoded)
        surface, bounds, context = _disclosure(kind, encoded, omit=(field,))
        with pytest.raises(EmissionRefusalError, match="canonical certificate"):
            EmissionEvaluator().evaluate_emission(certificate, surface, bounds, context)


def test_generic_object_facets_certificate_cannot_lose_replay_evidence():
    # This is a schema guard, not native OBJECT route admission. The represented
    # kind SIM is distinct from the generic OBJECT-1.1 objective identifier.
    certificate = {
        "schema_version": "verifier-current-object-facets-certificate-1",
        "request": {"coordinate": "OBJECT-1.1", "object_kind": "SIM"},
        "evidence_payloads": {"sha256:example": "private"},
        "result": {"status": "PASS"},
    }
    surface = DisclosureSurface(
        "SIM", ("schema_version", "request", "result"), ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("local-reader",))
                   for field in surface.disclosed_fields)
    context = EmissionContext(
        ObserverParty("local-reader", "reviewer", "local-evaluation"),
        "2026-09-27T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(certificate, surface, bounds, context)


@pytest.mark.parametrize("kind", ["SIM", "HYPER"])
def test_missing_or_false_bound_refuses_full_current_certificate(kind):
    _module, request, policy, encoded = _current(kind)
    surface, bounds, context = _disclosure(kind, encoded)
    with pytest.raises(CurrentCertificateEmissionRefusal):
        _evaluate(kind, request, policy, encoded, (surface, bounds[1:], context))
    denied = (DisclosureBound("false", bounds[0].field_name,
                              admitted_observers=("another-observer",)),) + bounds[1:]
    with pytest.raises(CurrentCertificateEmissionRefusal):
        _evaluate(kind, request, policy, encoded, (surface, denied, context))


@pytest.mark.parametrize("kind", ["SIM", "HYPER"])
def test_external_selection_and_rehashed_result_forgery_refuse(kind):
    _module, request, policy, encoded = _current(kind)
    disclosure = _disclosure(kind, encoded)
    wrong_request = deepcopy(request)
    wrong_request["subject_id"] = "other-selected-subject"
    with pytest.raises(CurrentCertificateEmissionRefusal):
        _evaluate(kind, wrong_request, policy, encoded, disclosure)
    wrong_policy = deepcopy(policy)
    wrong_policy["trust_roots"] = ["other-selected-root"]
    with pytest.raises(CurrentCertificateEmissionRefusal):
        _evaluate(kind, request, wrong_policy, encoded, disclosure)
    wrong_kind = "HYPER" if kind == "SIM" else "SIM"
    with pytest.raises(CurrentCertificateEmissionRefusal):
        _evaluate(wrong_kind, request, policy, encoded, disclosure)
    forged = json.loads(encoded)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = "sha256:" + canonical_digest(forged)
    with pytest.raises(CurrentCertificateEmissionRefusal):
        _evaluate(kind, request, policy, canonical_bytes(forged),
                  _disclosure(kind, canonical_bytes(forged)))


def test_honest_fail_and_unknown_are_reproduced_without_pass_promotion():
    module, _request, _objects, _isolation, policy = _sim_inputs()
    escape = _sim_model()
    escape["transitions"][0]["outcomes"][0]["effects"] = [
        {"kind": "external_export", "target": "host:network"}]
    isolation = canonical_bytes(escape)
    objects = _sim_objects(isolation)
    fail_request = module.current_object_request(
        objects, sim_id="sim", isolation_evidence_bytes=isolation, policy=policy)
    fail_bytes = module.build_current_object_certificate(
        fail_request, objects, isolation, policy=policy)
    failed = _evaluate("SIM", fail_request, policy, fail_bytes,
                       _disclosure("SIM", fail_bytes))
    assert failed.replay_status == "REPRODUCED"
    assert failed.computational_status == failed.native_result["status"] == "FAIL"

    normal_module, normal_request, normal_objects, _iso, normal_policy = _sim_inputs()
    unknown_bytes = normal_module.build_current_object_certificate(
        normal_request, normal_objects, None, policy=normal_policy)
    unknown = _evaluate("SIM", normal_request, normal_policy, unknown_bytes,
                        _disclosure("SIM", unknown_bytes))
    assert unknown.replay_status == "REPRODUCED"
    assert unknown.computational_status == unknown.native_result["status"] == "UNKNOWN"

    hyper, _objects, request, policy = _hyper_inputs()
    hyper_unknown_bytes = hyper._build(request, policy, EvidenceStore())
    hyper_unknown = _evaluate("HYPER", request, policy, hyper_unknown_bytes,
                              _disclosure("HYPER", hyper_unknown_bytes))
    assert hyper_unknown.replay_status == "REPRODUCED"
    assert hyper_unknown.computational_status == "UNKNOWN"


def test_full_hyper_canary_is_retained_and_not_authorized_for_transmission():
    module = hyper_closure
    objects = [NamespaceObject.create("sensitive", "OBJECT", {"private": "canary-secret"}),
               NamespaceObject.create("h", "HYPER", {}, {"subject": ["sensitive"]})]
    policy = module.hyper_closure_policy(trust_roots=["independent-local-policy"])
    request = module.hyper_closure_request(objects, hyper_id="h", policy=policy)
    encoded = module.build_hyper_closure_certificate(request, objects, policy=policy)
    admitted = _evaluate("HYPER", request, policy, encoded, _disclosure("HYPER", encoded))
    payload = json.loads(admitted.emitted_certificate_bytes)["evidence_payloads"][request["evidence_ref"]]
    assert b"canary-secret" in base64.b64decode(payload)
    assert admitted.privacy_result.receipt["observer_authentication"] == "NOT_CHECKED"
    assert admitted.native_result["privacy"] == "NOT_ESTABLISHED"


def test_caller_mutation_after_one_snapshot_cannot_change_external_selection(monkeypatch):
    import verifier.privacy.current_certificate_emission as bridge

    _module, request, policy, encoded = _current("SIM")
    disclosure = _disclosure("SIM", encoded)
    original = bridge._ROUTES["SIM"][1]
    calls = 0

    def mutate_caller_then_replay(payload, *, expected_request, policy: dict):
        nonlocal calls
        calls += 1
        if calls == 1:
            request["subject_id"] = "later-caller-mutation"
        return original(payload, expected_request=expected_request, policy=policy)

    monkeypatch.setitem(bridge._ROUTES, "SIM", (bridge._ROUTES["SIM"][0], mutate_caller_then_replay))
    admitted = _evaluate("SIM", request, policy, encoded, disclosure)
    assert calls == 2
    assert admitted.replay_status == "REPRODUCED"
    assert admitted.native_result["subject_id"] == "sim"


def test_changed_native_source_replay_rejects_stale_result(monkeypatch):
    import verifier.domains.contracts.object_grounding as grounding

    _module, request, policy, encoded = _current("SIM")
    disclosure = _disclosure("SIM", encoded)
    admitted = _evaluate("SIM", request, policy, encoded, disclosure)
    monkeypatch.setattr(grounding, "mechanism_digest", lambda: "sha256:" + "0" * 64)
    assert not recheck_current_certificate_emission(
        admitted, encoded, kind="SIM", expected_request=request, policy=policy,
        surface=disclosure[0], bounds=disclosure[1], context=disclosure[2])


@pytest.mark.parametrize("changed_source", ["privacy", "bridge"])
def test_changed_helper_source_replay_rejects_stale_result(monkeypatch, changed_source):
    import verifier.privacy.current_certificate_emission as bridge
    import verifier.privacy.engine as engine

    _module, request, policy, encoded = _current("SIM")
    disclosure = _disclosure("SIM", encoded)
    admitted = _evaluate("SIM", request, policy, encoded, disclosure)
    if changed_source == "privacy":
        monkeypatch.setattr(engine, "_mechanism_digest", lambda: "0" * 64)
    else:
        monkeypatch.setattr(bridge, "_bridge_source_digest", lambda: "sha256:" + "0" * 64)
    assert not recheck_current_certificate_emission(
        admitted, encoded, kind="SIM", expected_request=request, policy=policy,
        surface=disclosure[0], bounds=disclosure[1], context=disclosure[2])


def test_capture_refuses_hostile_or_unbounded_selection_before_native_replay(monkeypatch):
    import verifier.privacy.current_certificate_emission as bridge

    _module, request, policy, encoded = _current("SIM")
    surface, bounds, context = _disclosure("SIM", encoded)
    original = bridge._ROUTES["SIM"]

    def forbidden_recheck(*_args, **_kwargs):
        raise AssertionError("selection reached native recheck before bounded capture")

    monkeypatch.setitem(bridge._ROUTES, "SIM", (original[0], forbidden_recheck))

    class HostileText(str):
        def __str__(self):
            raise AssertionError("caller string hook invoked")

    hostile_context = EmissionContext(
        ObserverParty("local-reader", "reviewer", HostileText("local-evaluation")),
        context.timestamp)
    with pytest.raises(CurrentCertificateEmissionRefusal):
        _evaluate("SIM", request, policy, encoded, (surface, bounds, hostile_context))

    huge_context = EmissionContext(
        ObserverParty("local-reader", "reviewer", "x" * (1024 * 1024 + 1)),
        context.timestamp)
    with pytest.raises(CurrentCertificateEmissionRefusal):
        _evaluate("SIM", request, policy, encoded, (surface, bounds, huge_context))

    nested = {}
    for _ in range(70):
        nested = {"n": nested}
    deep_context = EmissionContext(context.observer, context.timestamp, (nested,))
    with pytest.raises(CurrentCertificateEmissionRefusal):
        _evaluate("SIM", request, policy, encoded, (surface, bounds, deep_context))


def test_recheck_rejects_tampered_replay_and_privacy_records():
    _module, request, policy, encoded = _current("SIM")
    disclosure = _disclosure("SIM", encoded)
    admitted = _evaluate("SIM", request, policy, encoded, disclosure)
    tampered = deepcopy(admitted)
    tampered.native_result["status"] = "FAIL"
    assert not recheck_current_certificate_emission(
        tampered, encoded, kind="SIM", expected_request=request, policy=policy,
        surface=disclosure[0], bounds=disclosure[1], context=disclosure[2])


@pytest.mark.parametrize("field,forgery", [
    ("kind", "FOREIGN"),
    ("replay_status", "NOT_REPRODUCED"),
    ("computational_status", "FORGED"),
])
def test_carried_status_subclass_cannot_make_forgery_compare_equal(field, forgery):
    _module, request, policy, encoded = _current("SIM")
    disclosure = _disclosure("SIM", encoded)
    admitted = _evaluate("SIM", request, policy, encoded, disclosure)

    class PermissiveText(str):
        def __eq__(self, _other):
            return True

    tampered = deepcopy(admitted)
    object.__setattr__(tampered, field, PermissiveText(forgery))
    assert not recheck_current_certificate_emission(
        tampered, encoded, kind="SIM", expected_request=request, policy=policy,
        surface=disclosure[0], bounds=disclosure[1], context=disclosure[2])


def test_nested_emission_result_subclass_cannot_hide_forged_fields():
    _module, request, policy, encoded = _current("SIM")
    disclosure = _disclosure("SIM", encoded)
    admitted = _evaluate("SIM", request, policy, encoded, disclosure)

    class ForgedEmissionResult(EmissionResult):
        def to_dict(self):
            return admitted.privacy_result.to_dict()

    tampered = deepcopy(admitted)
    forged = ForgedEmissionResult({"forged": True}, (), (), {"observer_authentication": "PASS"})
    object.__setattr__(tampered, "privacy_result", forged)
    assert not recheck_current_certificate_emission(
        tampered, encoded, kind="SIM", expected_request=request, policy=policy,
        surface=disclosure[0], bounds=disclosure[1], context=disclosure[2])


def test_later_caller_result_mutation_does_not_change_captured_recheck(monkeypatch):
    import verifier.privacy.current_certificate_emission as bridge

    _module, request, policy, encoded = _current("SIM")
    disclosure = _disclosure("SIM", encoded)
    admitted = _evaluate("SIM", request, policy, encoded, disclosure)
    original = bridge._ROUTES["SIM"][1]
    calls = 0

    def mutate_carried_then_replay(payload, *, expected_request, policy):
        nonlocal calls
        calls += 1
        if calls == 1:
            object.__setattr__(admitted, "kind", "later-caller-mutation")
        return original(payload, expected_request=expected_request, policy=policy)

    monkeypatch.setitem(bridge._ROUTES, "SIM", (bridge._ROUTES["SIM"][0], mutate_carried_then_replay))
    assert recheck_current_certificate_emission(
        admitted, encoded, kind="SIM", expected_request=request, policy=policy,
        surface=disclosure[0], bounds=disclosure[1], context=disclosure[2])
    assert calls == 2


@pytest.mark.parametrize("location", ["native", "privacy"])
def test_plain_numeric_type_substitution_cannot_pass_replay(location):
    _module, request, policy, encoded = _current("SIM")
    disclosure = _disclosure("SIM", encoded)
    admitted = _evaluate("SIM", request, policy, encoded, disclosure)
    tampered = deepcopy(admitted)
    if location == "native":
        evaluation = tampered.native_result["evaluation"]
        evaluation["observed_evidence_bytes"] = float(evaluation["observed_evidence_bytes"])
    else:
        receipt = tampered.privacy_result.receipt
        receipt["disclosed_fields_count"] = float(receipt["disclosed_fields_count"])
    assert not recheck_current_certificate_emission(
        tampered, encoded, kind="SIM", expected_request=request, policy=policy,
        surface=disclosure[0], bounds=disclosure[1], context=disclosure[2])
    tampered = deepcopy(admitted)
    tampered.privacy_result.receipt["observer_authentication"] = "PASS"
    assert not recheck_current_certificate_emission(
        tampered, encoded, kind="SIM", expected_request=request, policy=policy,
        surface=disclosure[0], bounds=disclosure[1], context=disclosure[2])


def test_selected_sim_kind_cannot_hide_model_sim_composition_risk():
    _module, request, policy, encoded = _current("SIM")
    surface, bounds, context = _disclosure("SIM", encoded)
    co_emitted = ({"object_name": "MODEL"},)
    context = EmissionContext(context.observer, context.timestamp, co_emitted)
    with pytest.raises(CurrentCertificateEmissionRefusal, match="composition"):
        _evaluate("SIM", request, policy, encoded, (surface, bounds, context))
    unknown_other = EmissionContext(
        context.observer, context.timestamp,
        ({"schema_version": "verifier-current-hyper-closure-certificate-1"},))
    with pytest.raises(CurrentCertificateEmissionRefusal, match="composition object scope"):
        _evaluate("SIM", request, policy, encoded, (surface, bounds, unknown_other))


def test_nontext_timestamp_does_not_enter_local_emission_receipt():
    _module, request, policy, encoded = _current("SIM")
    surface, bounds, context = _disclosure("SIM", encoded)
    malformed = EmissionContext(context.observer, 123)
    with pytest.raises(CurrentCertificateEmissionRefusal, match="timestamp"):
        _evaluate("SIM", request, policy, encoded, (surface, bounds, malformed))


def test_noncanonical_disclosure_and_legacy_canonical_boundary_remain_compatible():
    observer = ObserverParty("local-reader", "reviewer", "local-evaluation")
    context = EmissionContext(observer, "2026-09-27T00:00:00Z")
    ordinary = {"object_name": "DATA", "public": 1, "secret": "canary"}
    surface = DisclosureSurface("DATA", ("object_name", "public"), ("secret",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("local-reader",))
                   for field in surface.disclosed_fields)
    output = EmissionEvaluator().evaluate_emission(ordinary, surface, bounds, context)
    assert output.emitted_certificate == {"object_name": "DATA", "public": 1}
    assert output.redacted_fields == ("secret",)
    legacy = {"schema_version": "verifier-domain-certification-1", "public": 1,
              "evidence": "private"}
    legacy_surface = DisclosureSurface("DATA", ("schema_version", "public"), ("evidence",))
    legacy_bounds = tuple(DisclosureBound(field, field, admitted_observers=("local-reader",))
                          for field in legacy_surface.disclosed_fields)
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(legacy, legacy_surface, legacy_bounds, context)


@pytest.mark.parametrize('module_name',['hardware_inventory','time_order','space_layout','event_prerequisites','arch_shapes','sim_dynamics','sim_response','sim_internal_state','sim_perspective','sim_external_law','owner_eligibility'])
def test_actual_retained_certificate_refuses_evidence_redaction(module_name):
    fixture=REDACTION_FIXTURES[module_name]
    module=fixture.native if module_name=="owner_eligibility" else getattr(fixture,module_name)
    request,policy,evidence=fixture.selected()
    encoded=getattr(module,'build_'+module_name+'_certificate')(request,evidence,policy=policy)
    assert getattr(module,'recheck_'+module_name+'_certificate')(encoded,expected_request=request,policy=policy)['status']=='PASS'
    value=json.loads(encoded)
    from verifier.privacy import DisclosureSurface,DisclosureBound,ObserverParty,EmissionContext,EmissionEvaluator,EmissionRefusalError
    assert 'evidence_payloads' in value
    fields=tuple(key for key in value if key!='evidence_payloads')
    surface=DisclosureSurface(request['object_kind'],fields,('evidence_payloads',))
    bounds=tuple(DisclosureBound(key,key,admitted_observers=('reader',)) for key in fields)
    context=EmissionContext(ObserverParty('reader','auditor','inspect'),'test-time')
    with pytest.raises(EmissionRefusalError):EmissionEvaluator().evaluate_emission(value,surface,bounds,context)


def test_every_registered_canonical_schema_has_a_disclosure_guard():
    from verifier.domains.contracts.current_object_routes import current_object_route_catalog
    from verifier.privacy.engine import _CANONICAL_CERTIFICATE_SCHEMAS
    schemas={row['certificate_schema_version'] for row in current_object_route_catalog()}
    assert schemas <= set(_CANONICAL_CERTIFICATE_SCHEMAS)
