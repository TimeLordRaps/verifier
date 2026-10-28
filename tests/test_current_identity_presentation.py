"""Bounded native identity presentation and cryptographic/controller tests.

Public deterministic insecure test keys only; no operational trust/personhood.
Edwards-curve digital signature algorithm with a 255-bit field (Ed25519).
Positive tests execute the actual optional backend when available; absent extras
are classified separately from executed signature qualification.
"""
from __future__ import annotations
from asyncio import CancelledError
import copy
import base64
import json
from pathlib import Path
import sys

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.domains.common import digest, Refuted, Unavailable
from verifier.domains.contracts import identity_lifecycle, identity_presentation as native
from test_current_identity_lifecycle import selected as lifecycle_inputs
from test_identity_lifecycle_replay import history, presentation, present_event


def keys():
    pytest.importorskip("cryptography", reason="OPTIONAL_DEPENDENCY_ABSENT: signature fixtures require the seal extra (cryptography); the platform-python-contracts workflow job installs it")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    # Deterministic public test seeds, never protected/production credentials.
    result = {}
    for name, octet in (("a", 17), ("b", 34), ("holder", 51)):
        secret = Ed25519PrivateKey.from_private_bytes(bytes([octet]) * 32)
        public = secret.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        result[name] = (secret, public)
    return result


def fixture(kind="HUMAN", *, limits=None, mutate_policy=None):
    child_request, child_policy, child_data = lifecycle_inputs(kind)
    lc = json.loads(child_data)
    b = lc["binding"]
    b["relied_attribute_ids"] = ["eligibility"]
    row = presentation(b, 20)
    lc["presentations"] = [row]
    lc["events"] = history(b, [present_event(row)])
    child_request.update(binding_digest=digest(b), events_digest=digest(lc["events"]),
        presentation_inventory_digest=digest(lc["presentations"]), selected_head_digest=digest(lc["events"][-1]),
        selected_event_count=len(lc["events"]), evidence_ref=digest(lc))
    child_bytes = identity_lifecycle.build_identity_lifecycle_certificate(child_request, canonical_bytes(lc), policy=child_policy)
    k = keys()
    holder = b["representation_id"] if kind == "HUMAN" else b["root_human_id"]
    purposes = ["assurance", "enrollment_authority", "exit_grant", "status"] + (["simulation_scope"] if kind == "BOT" else [])
    sources = [{"source_id": "configured-source-a", "key_id": "key-a", "public_key": k["a"][1],
                "purposes": sorted(purposes), "scopes": [b["scope"]], "clock_id": b["clock_id"], "valid_from": 10, "valid_until": 200},
               {"source_id": "configured-source-b", "key_id": "key-b", "public_key": k["b"][1],
                "purposes": ["attribute"], "scopes": [b["scope"]], "clock_id": b["clock_id"], "valid_from": 10, "valid_until": 200}]
    requirements = [{"requirement_id": "assurance", "purpose": "assurance", "source_id": "configured-source-a", "claim_id": b["assurance_requirement_id"], "expected_value": native.ASSURANCE},
                    {"requirement_id": "attribute", "purpose": "attribute", "source_id": "configured-source-b", "claim_id": "eligibility", "expected_value": "selected-eligible"},
                    {"requirement_id": "enrollment", "purpose": "enrollment_authority", "source_id": "configured-source-a", "claim_id": "enrollment", "expected_value": "ENROLL_IDENTITY"},
                    {"requirement_id": "exit", "purpose": "exit_grant", "source_id": "configured-source-a", "claim_id": "exit", "expected_value": native.CONTROL},
                    {"requirement_id": "status", "purpose": "status", "source_id": "configured-source-a", "claim_id": "current-status", "expected_value": "ACTIVE"}]
    if kind == "BOT":
        requirements.append({"requirement_id": "simulation", "purpose": "simulation_scope", "source_id": "configured-source-a", "claim_id": b["simulation_id"], "expected_value": "ACTIVE"})
    requirements.sort(key=lambda x: x["requirement_id"])
    settings = dict(trust_roots=["insecure-synthetic-configured-source-test"], identity_scope_policy=child_policy["identity_scope_policy"],
        identity_lifecycle_policy=child_policy, sources=sources, requirements=requirements, holder_id=holder,
        holder_public_key=k["holder"][1], max_support_age=100)
    if mutate_policy:
        mutate_policy(settings, k, b)
    policy = native.identity_presentation_policy(**settings)
    zero = "sha256:" + "0" * 64
    request = native.identity_presentation_request(identity_lifecycle_request=child_request,
        identity_lifecycle_certificate_ref=digest(json.loads(child_bytes)), exit_probe_at=60,
        exit_challenge_digest=digest("public-insecure-test-probe-challenge"), exit_probe_ref=zero,
        support_refs={}, evidence_ref=zero, policy=policy, limits=limits)
    selection = native.claim_selection_digest(request)
    probe = {"schema_version": native.PROBE_VERSION, "selection_digest": selection, "binding_digest": request["binding_digest"],
        "head_digest": child_request["selected_head_digest"], "holder_id": holder, "clock_id": b["clock_id"], "at": 60,
        "challenge_digest": request["exit_challenge_digest"], "controller_id": native.CONTROL}
    probe["signature"] = k["holder"][0].sign(native.probe_signing_bytes(probe)).hex()
    probe_ref = digest(probe)
    witnesses = {
        "assurance": {"assurance_id": b["assurance_requirement_id"], "method": native.ASSURANCE, "native_identity_scope_certificate_ref": request["identity_scope_certificate_ref"]},
        "attribute": {"attribute_id": "eligibility", "subject_id": b["representation_id"], "value": "selected-eligible"},
        "enrollment": {"action": "ENROLL_IDENTITY", "actor_id": b["actor_id"], "role_id": b["role_id"], "enrollment_id": "enrollment"},
        "exit": {"controller_id": native.CONTROL, "holder_id": holder, "holder_public_key": policy["holder_public_key"], "probe_ref": probe_ref},
        "status": {"state": "ACTIVE", "head_digest": child_request["selected_head_digest"], "event_count": child_request["selected_event_count"]},
        "simulation": {"state": "ACTIVE", "simulation_id": b["simulation_id"], "simulation_record_digest": b["simulation_record_digest"], "scope": b["scope"]},
    }
    supports = {}
    for rule in policy["requirements"]:
        sid = rule["source_id"]
        source = next(x for x in policy["sources"] if x["source_id"] == sid)
        signing_key = k["b"][0] if rule["purpose"] == "attribute" else k["a"][0]
        payload = {"schema_version": native.SUPPORT_VERSION, "selection_digest": selection, "requirement_id": rule["requirement_id"],
            "purpose": rule["purpose"], "source_id": sid, "subject_id": request["subject_id"], "object_digest": request["object_digest"],
            "binding_digest": request["binding_digest"], "scope": b["scope"], "clock_id": b["clock_id"],
            "valid_from": 10, "valid_until": 200, "issued_at": 10, "witness": witnesses[rule["requirement_id"]]}
        supports[rule["requirement_id"]] = {"schema_version": native.ENVELOPE_VERSION, "source_id": sid,
            "key_id": source["key_id"], "payload": payload,
            "signature": signing_key.sign(native.support_signing_bytes(sid, source["key_id"], payload)).hex()}
    evidence = {"schema_version": native.EVIDENCE_VERSION, "identity_scope_certificate": lc["identity_scope_certificate"],
        "identity_lifecycle_certificate": json.loads(child_bytes), "supports": supports, "exit_probe": probe}
    request.update(exit_probe_ref=probe_ref, support_refs={rid: digest(value) for rid, value in supports.items()}, evidence_ref=digest(evidence))
    assert native.claim_selection_digest(request) == selection  # signature artifact refs are acyclic
    return request, policy, evidence, k


def replay(request, policy, evidence):
    raw = None if evidence is None else canonical_bytes(evidence)
    certificate = native.build_identity_presentation_certificate(request, raw, policy=policy)
    return native.recheck_identity_presentation_certificate(certificate, expected_request=request, policy=policy)


def repin(request, evidence):
    request.update(support_refs={rid: digest(x) for rid, x in evidence["supports"].items()},
                   exit_probe_ref=digest(evidence["exit_probe"]) if evidence["exit_probe"] is not None else request["exit_probe_ref"], evidence_ref=digest(evidence))


def resign(evidence, rid, secret):
    envelope = evidence["supports"][rid]
    envelope["signature"] = secret.sign(native.support_signing_bytes(envelope["source_id"], envelope["key_id"], envelope["payload"])).hex()


@pytest.mark.parametrize("kind", ["HUMAN", "AGENT", "BOT"])
def test_actual_native_crypto_and_terminal_controller_positive_is_scoped(kind):
    request, policy, evidence, _ = fixture(kind)
    original = copy.deepcopy((request, policy, evidence))
    result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    controller = result["evaluation"]["observations"]["terminal_controller"]
    assert controller["terminated"] is True
    assert controller["replay"]["consistency_status"] == "PASS"
    assert controller["replay"]["declared_reliance_eligibility"] == "FAIL"
    assert all(row["status"] == "PASS" for row in result["evaluation"]["observations"]["components"])
    for field in ("real_issuer_authority", "human_authenticity", "actor_independence", "live_clock",
                  "physical_exit_enforcement", "global_public_availability", "whole_identity_closure", "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"
    assert (request, policy, evidence) == original


@pytest.mark.parametrize("case", ["outer", "child2", "child3", "assurance", "attribute", "status", "exit-grant", "probe"])
def test_missing_required_evidence_is_unknown_never_empty_set_pass(case):
    request, policy, evidence, _ = fixture()
    if case == "outer":
        assert replay(request, policy, None)["status"] == "UNKNOWN"
        return
    if case in ("child2", "child3"):
        evidence["identity_lifecycle_certificate" if case == "child2" else "identity_scope_certificate"] = None
    elif case == "probe":
        evidence["exit_probe"] = None
    else:
        evidence["supports"].pop("exit" if case == "exit-grant" else case)
    repin(request, evidence)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"


@pytest.mark.parametrize("case", ["signature", "wrong-attribute", "wrong-scope", "expiry", "status-deny", "exit-fee", "exit-holder"])
def test_rehashed_and_resigned_false_native_prerequisites_are_refuted(case):
    request, policy, evidence, k = fixture()
    if case == "signature":
        evidence["supports"]["attribute"]["signature"] = "0" * 128
    elif case == "wrong-attribute":
        evidence["supports"]["attribute"]["payload"]["witness"]["value"] = "not-selected-eligible"
        resign(evidence, "attribute", k["b"][0])
    elif case == "wrong-scope":
        evidence["supports"]["enrollment"]["payload"]["scope"] = "widened-scope"
        resign(evidence, "enrollment", k["a"][0])
    elif case == "expiry":
        evidence["supports"]["status"]["payload"]["valid_until"] = request["evaluation_at"]
        resign(evidence, "status", k["a"][0])
    elif case == "status-deny":
        evidence["supports"]["status"]["payload"]["witness"]["state"] = "TERMINATED"
        resign(evidence, "status", k["a"][0])
    elif case == "exit-fee":
        evidence["supports"]["exit"]["payload"]["witness"]["controller_id"] = "issuer-countersignature-and-fee-required"
        resign(evidence, "exit", k["a"][0])
    else:
        evidence["exit_probe"]["holder_id"] = "foreign-holder"
        evidence["exit_probe"]["signature"] = k["holder"][0].sign(native.probe_signing_bytes(evidence["exit_probe"])).hex()
    repin(request, evidence)
    assert replay(request, policy, evidence)["status"] == "FAIL"


def test_namespace_admission_does_not_grant_identity_purposes():
    def namespace_only(settings, *_):
        settings["sources"][0]["purposes"] = ["NAMESPACE_ADMIT"]
    request, policy, evidence, _ = fixture(mutate_policy=namespace_only)
    assert replay(request, policy, evidence)["status"] == "FAIL"


def test_configured_self_attribute_source_does_not_pass_as_independent_input():
    def self_key(settings, k, _):
        settings["sources"][1]["public_key"] = k["holder"][1]
    request, policy, evidence, k = fixture(mutate_policy=self_key)
    resign(evidence, "attribute", k["holder"][0])
    repin(request, evidence)
    assert replay(request, policy, evidence)["status"] == "FAIL"


def test_source_and_holder_key_absence_and_unimplemented_proof_mode_are_unknown():
    for case in ("source-key", "holder-key", "proof-mode"):
        def absent(settings, *_):
            if case == "source-key":
                settings["sources"][0]["public_key"] = None
            elif case == "holder-key":
                settings["holder_public_key"] = None
            else:
                settings["public_proof_mode"] = "unimplemented-zero-knowledge-proof"
        request, policy, evidence, _ = fixture(mutate_policy=absent)
        assert replay(request, policy, evidence)["status"] == "UNKNOWN"


def test_backend_absence_or_cancellation_is_unknown_not_native_pass(monkeypatch):
    request, policy, evidence, _ = fixture()
    for error in (Unavailable("backend absent"), CancelledError()):
        def stopped(*_):
            raise error
        monkeypatch.setattr(native, "_verify_signature", stopped)
        assert replay(request, policy, evidence)["status"] == "UNKNOWN"


def test_known_signature_refutation_survives_later_cancellation(monkeypatch):
    request, policy, evidence, _ = fixture()
    def outcomes(_key, _signature, message):
        if b'"requirement_id":"assurance"' in message:
            raise Refuted("known false exact signature")
        raise CancelledError()
    monkeypatch.setattr(native, "_verify_signature", outcomes)
    assert replay(request, policy, evidence)["status"] == "FAIL"


@pytest.mark.parametrize("limit", ["max_supports", "max_operations", "max_evidence_bytes"])
def test_selected_bounds_stay_unknown_with_unrun_descendants(limit):
    request, policy, evidence, _ = fixture(limits={limit: 1})
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"


def test_known_refutation_before_budget_exhaustion_is_retained():
    request, policy, evidence, k = fixture(limits={"max_operations": 4})
    evidence["supports"]["assurance"]["payload"]["scope"] = "foreign"
    resign(evidence, "assurance", k["a"][0])
    repin(request, evidence)
    result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert any(x["status"] == "UNKNOWN" for x in result["evaluation"]["observations"]["components"])


@pytest.mark.parametrize("field", ["status", "whole_identity_closure", "human_authenticity"])
def test_rehashed_outer_pass_and_dropped_witness_refuse_transport(field):
    request, policy, evidence, _ = fixture()
    certificate = native.build_identity_presentation_certificate(request, canonical_bytes(evidence), policy=policy)
    value = json.loads(certificate)
    value["result"][field] = "FAIL" if field == "status" else "PASS"
    value["digest"] = digest({k: v for k, v in value.items() if k != "digest"})
    with pytest.raises(ValueError):
        native.recheck_identity_presentation_certificate(canonical_bytes(value), expected_request=request, policy=policy)
    value = json.loads(certificate)
    value["evidence_payloads"] = {}
    value["digest"] = digest({k: v for k, v in value.items() if k != "digest"})
    with pytest.raises(ValueError):
        native.recheck_identity_presentation_certificate(canonical_bytes(value), expected_request=request, policy=policy)


def test_request_and_policy_capture_precedes_source_reader_mutation(monkeypatch):
    request, policy, evidence, _ = fixture()
    original_request, original_policy = copy.deepcopy(request), copy.deepcopy(policy)
    read = native.mechanism_digest
    def mutate_after_capture():
        request["support_refs"].clear()
        policy["sources"][0]["public_key"] = None
        policy["requirements"].clear()
        return read()
    monkeypatch.setattr(native, "mechanism_digest", mutate_after_capture)
    certificate = native.build_identity_presentation_certificate(request, canonical_bytes(evidence), policy=policy)
    monkeypatch.setattr(native, "mechanism_digest", read)
    assert native.recheck_identity_presentation_certificate(certificate, expected_request=original_request, policy=original_policy)["status"] == "PASS"


def test_foreign_callback_values_and_bool_times_are_refused_before_serialization():
    request, policy, evidence, _ = fixture()
    class Foreign(dict):
        def items(self):
            raise AssertionError("foreign callback must never execute")
    with pytest.raises(ValueError):
        native.build_identity_presentation_certificate(Foreign(request), canonical_bytes(evidence), policy=policy)
    request["evaluation_at"] = True
    with pytest.raises(ValueError):
        native.build_identity_presentation_certificate(request, canonical_bytes(evidence), policy=policy)


@pytest.mark.parametrize("relative", ["domains/contracts/identity_presentation.py", "standard/CURRENT_IDENTITY_PRESENTATION.md",
    "domains/contracts/identity_lifecycle.py", "domains/contracts/identity_scope.py", "core/signature_keys.py",
    "schemas/identity_presentation_evidence.json"])
def test_source_and_recursive_child_drift_invalidate_old_policy(relative, monkeypatch):
    request, policy, evidence, _ = fixture()
    certificate = native.build_identity_presentation_certificate(request, canonical_bytes(evidence), policy=policy)
    target = Path(native.__file__).parents[2] / relative
    read = Path.read_bytes
    def changed(path):
        value = read(path)
        return value + b"\nchanged identity prerequisite dependency\n" if path == target else value
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        native.recheck_identity_presentation_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("absent", ["child2", "child3", "source-key", "holder-key", "backend"])
@pytest.mark.parametrize("contradiction", ["subject", "clock", "attribute", "status", "controller"])
def test_present_supported_refutation_precedes_unavailable_companion(absent, contradiction, monkeypatch):
    def missing(settings, *_):
        if absent == "source-key":
            settings["sources"][0]["public_key"] = None
        if absent == "holder-key":
            settings["holder_public_key"] = None
    request, policy, evidence, k = fixture(mutate_policy=missing)
    if absent in ("child2", "child3"):
        evidence["identity_lifecycle_certificate" if absent == "child2" else "identity_scope_certificate"] = None
    if absent == "backend":
        def unavailable(*_):
            raise native.IdentityPresentationUnavailable("actual backend capacity unavailable")
        monkeypatch.setattr(native, "_verify_signature", unavailable)
    if contradiction in ("subject", "clock"):
        evidence["supports"]["assurance"]["payload"]["subject_id" if contradiction == "subject" else "clock_id"] = "foreign-selection"
        resign(evidence, "assurance", k["a"][0])
    elif contradiction == "attribute":
        evidence["supports"]["attribute"]["payload"]["witness"]["value"] = False
        resign(evidence, "attribute", k["b"][0])
    elif contradiction == "status":
        evidence["supports"]["status"]["payload"]["witness"]["state"] = "TERMINATED"
        resign(evidence, "status", k["a"][0])
    else:
        evidence["exit_probe"]["controller_id"] = "issuer-permission-and-fee"
        evidence["exit_probe"]["signature"] = k["holder"][0].sign(native.probe_signing_bytes(evidence["exit_probe"])).hex()
    repin(request, evidence)
    assert replay(request, policy, evidence)["status"] == "FAIL"


@pytest.mark.parametrize("case", ["support-pin", "probe-pin", "support-shape", "probe-shape", "child-pin"])
def test_independent_present_transport_checks_run_before_native_callbacks(case, monkeypatch):
    request, policy, evidence, _ = fixture()
    evidence["identity_scope_certificate"] = None
    if case == "support-pin":
        request["support_refs"]["assurance"] = "sha256:" + "f" * 64
    elif case == "probe-pin":
        request["exit_probe_ref"] = "sha256:" + "f" * 64
    elif case == "support-shape":
        evidence["supports"]["assurance"]["foreign"] = True
    elif case == "probe-shape":
        evidence["exit_probe"]["foreign"] = True
    else:
        request["identity_lifecycle_certificate_ref"] = "sha256:" + "f" * 64
    request["evidence_ref"] = digest(evidence)
    def not_called(*_, **__):
        raise AssertionError("present independent refutation must precede child callback")
    monkeypatch.setattr(native.identity_scope, "recheck_identity_scope_certificate", not_called)
    monkeypatch.setattr(native.identity_lifecycle, "recheck_identity_lifecycle_certificate", not_called)
    assert replay(request, policy, evidence)["status"] == "FAIL"


def test_all_present_predicates_are_inspected_before_signature_and_child_callbacks(monkeypatch):
    request, policy, evidence, _ = fixture()
    inspected = set()
    original = native._support
    def inspect(value, row, *args, **kwargs):
        if kwargs.get("verify") is False:
            inspected.add(row["requirement_id"])
        return original(value, row, *args, **kwargs)
    monkeypatch.setattr(native, "_support", inspect)
    expected = {row["requirement_id"] for row in policy["requirements"]}
    verify = native._verify_signature
    def signature(*args):
        assert inspected == expected
        return verify(*args)
    monkeypatch.setattr(native, "_verify_signature", signature)
    check = native.identity_scope.recheck_identity_scope_certificate
    def child(*args, **kwargs):
        assert inspected == expected
        return check(*args, **kwargs)
    monkeypatch.setattr(native.identity_scope, "recheck_identity_scope_certificate", child)
    assert replay(request, policy, evidence)["status"] == "PASS"


@pytest.mark.parametrize("purpose,time,expected", [
    ("assurance", 110, "PASS"), ("assurance", 111, "FAIL"),
    ("exit_grant", 110, "PASS"), ("exit_grant", 111, "FAIL")
])
def test_age_is_enforced_at_every_presentation_and_exit_probe(purpose, time, expected):
    request, policy, evidence, _ = fixture()
    context = native._retained_context(evidence, request)
    row = next(x for x in policy["requirements"] if x["purpose"] == purpose)
    source = next(x for x in policy["sources"] if x["source_id"] == row["source_id"])
    presentations = copy.deepcopy(context["presentations"])
    if purpose == "assurance":
        presentations.append({**presentations[0], "at": time})
    else:
        request["exit_probe_at"] = time
    envelope = copy.deepcopy(evidence["supports"][row["requirement_id"]])
    envelope["payload"]["selection_digest"] = native.claim_selection_digest(request)
    action = lambda: native._support(envelope, row, source, request, policy, context["binding"],
        presentations, context["lifecycle"], request["exit_probe_ref"], verify=False)
    if expected == "FAIL":
        with pytest.raises(Refuted, match="freshness"):
            action()
    else:
        action()


def test_future_issue_time_and_probe_time_refute_before_missing_keys():
    request, policy, evidence, _ = fixture(mutate_policy=lambda settings, *_: settings.update(holder_public_key=None))
    context = native._retained_context(evidence, request)
    probe = copy.deepcopy(evidence["exit_probe"])
    request["exit_probe_at"] = request["evaluation_at"] - 1
    probe.update(at=request["exit_probe_at"], selection_digest=native.claim_selection_digest(request))
    with pytest.raises(Refuted, match="precedes"):
        native._exit_probe(probe, request, policy, context["lifecycle"], verify=False)
    request, policy, evidence, _ = fixture(mutate_policy=lambda settings, *_: settings["sources"][0].update(public_key=None))
    context = native._retained_context(evidence, request)
    row = policy["requirements"][0]
    envelope = copy.deepcopy(evidence["supports"][row["requirement_id"]])
    envelope["payload"]["issued_at"] = context["presentations"][0]["at"] + 1
    with pytest.raises(Refuted, match="freshness"):
        native._support(envelope, row, policy["sources"][0], request, policy, context["binding"],
            context["presentations"], context["lifecycle"], request["exit_probe_ref"], verify=False)


@pytest.mark.parametrize("error", [OSError, RecursionError, OverflowError])
@pytest.mark.parametrize("target", ["child3", "child2", "inner-decoder", "outer-decoder", "signature"])
def test_actual_resource_unavailability_is_unknown_and_old_replay_is_typed_unavailable(error, target, monkeypatch):
    request, policy, evidence, _ = fixture()
    certificate = native.build_identity_presentation_certificate(request, canonical_bytes(evidence), policy=policy)
    def unavailable(*_, **__):
        raise error("checking capacity unavailable")
    if target == "child3":
        monkeypatch.setattr(native.identity_scope, "recheck_identity_scope_certificate", unavailable)
    elif target == "child2":
        monkeypatch.setattr(native.identity_lifecycle, "recheck_identity_lifecycle_certificate", unavailable)
    elif target == "signature":
        monkeypatch.setattr(native, "_verify_signature", unavailable)
    else:
        read = native.strict_json_loads
        def decoder(text):
            if target == "outer-decoder" or text.startswith('{"binding":'):
                raise error("actual retained decoder capacity unavailable")
            return read(text)
        monkeypatch.setattr(native, "strict_json_loads", decoder)
    if target != "outer-decoder":
        evaluated = native._evaluate(canonical_bytes(evidence), request, policy)
        assert evaluated.outcome.value == "UNKNOWN"
    with pytest.raises(native.IdentityPresentationUnavailable):
        native.recheck_identity_presentation_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("field", ["claim", "binding", "outcome", "count", "shape", "digest"])
def test_carried_independent_refusals_precede_inner_decoder_capacity(field, monkeypatch):
    request, policy, evidence, _ = fixture()
    value = json.loads(native.build_identity_presentation_certificate(request, canonical_bytes(evidence), policy=policy))
    if field == "claim":
        value["result"]["whole_identity_closure"] = "PASS"
    elif field == "binding":
        value["result"]["evaluation"]["binding_digest"] = "sha256:" + "f" * 64
    elif field == "outcome":
        value["result"]["evaluation"]["outcome"] = "FAIL"
    elif field == "count":
        value["result"]["evaluation"]["observed_evidence_bytes"] = True
    elif field == "shape":
        value["result"]["foreign"] = None
    value["digest"] = "sha256:" + "f" * 64 if field == "digest" else digest({k: v for k, v in value.items() if k != "digest"})
    read = native.strict_json_loads
    def decoder(text):
        if text.startswith('{"binding":'):
            raise RecursionError("native payload decoder unavailable")
        return read(text)
    monkeypatch.setattr(native, "strict_json_loads", decoder)
    with pytest.raises(native.IdentityPresentationError):
        native.recheck_identity_presentation_certificate(canonical_bytes(value), expected_request=request, policy=policy)


def test_honest_local_fail_remains_fail_with_new_child_capacity_but_reproduction_is_unavailable(monkeypatch):
    request, policy, evidence, k = fixture()
    evidence["supports"]["assurance"]["payload"]["witness"]["method"] = "false-supported-method"
    resign(evidence, "assurance", k["a"][0])
    repin(request, evidence)
    certificate = native.build_identity_presentation_certificate(request, canonical_bytes(evidence), policy=policy)
    assert json.loads(certificate)["result"]["status"] == "FAIL"
    def unavailable(*_, **__):
        raise native.identity_scope.IdentityScopeUnavailable("child capacity unavailable")
    monkeypatch.setattr(native.identity_scope, "recheck_identity_scope_certificate", unavailable)
    assert native._evaluate(canonical_bytes(evidence), request, policy).outcome.value == "FAIL"
    with pytest.raises(native.IdentityPresentationUnavailable):
        native.recheck_identity_presentation_certificate(certificate, expected_request=request, policy=policy)


def test_semantic_child_refusal_is_not_downgraded_after_another_child_is_unavailable(monkeypatch):
    request, policy, evidence, _ = fixture()
    certificate = native.build_identity_presentation_certificate(request, canonical_bytes(evidence), policy=policy)
    def unavailable(*_, **__):
        raise OSError("child3 unavailable")
    def refused(*_, **__):
        raise ValueError("actual semantic child2 refusal")
    monkeypatch.setattr(native.identity_scope, "recheck_identity_scope_certificate", unavailable)
    monkeypatch.setattr(native.identity_lifecycle, "recheck_identity_lifecycle_certificate", refused)
    with pytest.raises(native.IdentityPresentationError):
        native.recheck_identity_presentation_certificate(certificate, expected_request=request, policy=policy)


def test_preflight_rejects_depth_before_decoder_and_capacity_certificate_before_decode(monkeypatch):
    request, policy, evidence, _ = fixture()
    data = b"[" * 65 + b"0" + b"]" * 65
    def not_called(*_):
        raise AssertionError("retained bound must precede decoder")
    monkeypatch.setattr(native, "strict_json_loads", not_called)
    assert native._evaluate(data, request, policy).outcome.value == "UNKNOWN"
    with pytest.raises(native.IdentityPresentationUnavailable):
        native.recheck_identity_presentation_certificate(data, expected_request=request, policy=policy)
    with pytest.raises(native.IdentityPresentationUnavailable):
        native.recheck_identity_presentation_certificate(b" " * (policy["max_certificate_bytes"] + 1), expected_request=request, policy=policy)
    with pytest.raises(native.IdentityPresentationError):
        native.recheck_identity_presentation_certificate(bytearray(b"{}"), expected_request=request, policy=policy)


@pytest.mark.parametrize("entry", ["policy", "request", "recheck"])
def test_all_remaining_public_capture_precedes_source_callback_mutation(entry, monkeypatch):
    request, policy, evidence, _ = fixture()
    certificate = native.build_identity_presentation_certificate(request, canonical_bytes(evidence), policy=policy)
    selected, admitted = copy.deepcopy(request), copy.deepcopy(policy)
    settings = {key: copy.deepcopy(value) for key, value in policy.items() if key not in ("schema_version", "mechanism_id", "mechanism_digest")}
    read = native.mechanism_digest
    def mutate():
        request["identity_lifecycle_request"]["identity_scope_request"]["subject_id"] = "foreign-borrowed-subject"
        policy["sources"][0]["public_key"] = None
        settings["requirements"].clear()
        return read()
    monkeypatch.setattr(native, "mechanism_digest", mutate)
    if entry == "policy":
        assert native.identity_presentation_policy(**settings) == admitted
    elif entry == "request":
        got = native.identity_presentation_request(identity_lifecycle_request=request["identity_lifecycle_request"],
            identity_lifecycle_certificate_ref=request["identity_lifecycle_certificate_ref"], exit_probe_at=request["exit_probe_at"],
            exit_challenge_digest=request["exit_challenge_digest"], exit_probe_ref=request["exit_probe_ref"], support_refs=request["support_refs"],
            evidence_ref=request["evidence_ref"], policy=policy, limits=request["limits"])
        assert got == selected
    else:
        assert native.recheck_identity_presentation_certificate(certificate, expected_request=request, policy=policy)["status"] == "PASS"


def test_owned_registration_and_foreign_signing_inputs():
    first = native.registration()
    first["exclusions"].clear()
    assert native.registration()["exclusions"]
    class Foreign(dict):
        def items(self):
            raise AssertionError("foreign input callback must never run")
    with pytest.raises(native.IdentityPresentationError):
        native.claim_selection_digest(Foreign())
    with pytest.raises(native.IdentityPresentationError):
        native.support_signing_bytes("source", "key", Foreign())
    with pytest.raises(native.IdentityPresentationError):
        native.probe_signing_bytes(Foreign())


def test_schema_is_canonical_route_and_structural_witness_grammar_only():
    path = Path(native.__file__).parents[2] / "schemas" / "identity_presentation_evidence.json"
    schema = json.loads(path.read_bytes())
    assert schema["$id"] == "https://timelordraps.github.io/verifier/schemas/" + path.name
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"schema_version", "identity_scope_certificate", "identity_lifecycle_certificate", "supports", "exit_probe"}
    assert schema["properties"]["supports"]["maxProperties"] == native._CEILINGS["max_supports"]
    assert "$ref" not in schema["$defs"]["supportPayload"]["properties"]["witness"]


def test_actual_optional_backend_import_absence_is_unknown(monkeypatch):
    request, policy, evidence, _ = fixture()
    monkeypatch.setitem(sys.modules, "cryptography.exceptions", None)
    assert replay(request, policy, evidence)["status"] == "UNKNOWN"


@pytest.mark.parametrize("error", [RecursionError, OverflowError])
def test_actual_declared_interpreter_resource_does_not_mask_readable_binding_refutation(error, monkeypatch):
    request, policy, evidence, k = fixture()
    evidence["supports"]["attribute"]["payload"]["witness"]["subject_id"] = "foreign-representation"
    resign(evidence, "attribute", k["b"][0])
    repin(request, evidence)
    def unavailable(*_, **__):
        raise error("actual declared interpreter unavailable")
    monkeypatch.setattr(native.identity_lifecycle_replay, "replay_declared_identity_lifecycle", unavailable)
    evaluated = native._evaluate(canonical_bytes(evidence), request, policy)
    assert evaluated.outcome.value == "FAIL"
    assert evaluated.observations["unavailable_execution"]
    assert any(x["name"] == "support_predicates:attribute" and x["status"] == "FAIL" for x in evaluated.observations["components"])


def test_actual_consistent_terminated_history_refutes_reliance_before_unavailable_native_child(monkeypatch):
    request, policy, evidence, k = fixture()
    child = copy.deepcopy(request["identity_lifecycle_request"])
    lifecycle = json.loads(base64.b64decode(evidence["identity_lifecycle_certificate"]["evidence_payloads"][child["evidence_ref"]]))
    events = lifecycle["events"]
    events.append({"schema_version": native.identity_lifecycle_replay.EVENT_VERSION, "event_id": "retained-revocation",
        "position": len(events), "binding_digest": request["binding_digest"][7:], "previous_event_digest": digest(events[-1])[7:],
        "kind": "revocation", "at": 40, "payload": {"revocation_id": "retained-withdrawal", "reason_ref": digest("retained-reason")},
        "authority_evidence_ref": None})
    child.update(events_digest=digest(events), selected_head_digest=digest(events[-1]), selected_event_count=len(events), evidence_ref=digest(lifecycle))
    raw = identity_lifecycle.build_identity_lifecycle_certificate(child, canonical_bytes(lifecycle), policy=policy["identity_lifecycle_policy"])
    assert json.loads(raw)["result"]["status"] == "PASS"  # Actual declared consistency, with reliance still inactive.
    evidence["identity_lifecycle_certificate"] = json.loads(raw)
    request.update(identity_lifecycle_request=child, identity_lifecycle_certificate_ref=digest(json.loads(raw)))
    selection = native.claim_selection_digest(request)
    evidence["exit_probe"].update(selection_digest=selection, head_digest=child["selected_head_digest"])
    evidence["exit_probe"]["signature"] = k["holder"][0].sign(native.probe_signing_bytes(evidence["exit_probe"])).hex()
    probe_ref = digest(evidence["exit_probe"])
    evidence["supports"]["status"]["payload"]["witness"].update(head_digest=child["selected_head_digest"], event_count=len(events))
    evidence["supports"]["exit"]["payload"]["witness"]["probe_ref"] = probe_ref
    for rid, envelope in evidence["supports"].items():
        envelope["payload"]["selection_digest"] = selection
        resign(evidence, rid, k["b"][0] if rid == "attribute" else k["a"][0])
    repin(request, evidence)
    def unavailable(*_, **__):
        raise OSError("actual child checking unavailable")
    monkeypatch.setattr(native.identity_scope, "recheck_identity_scope_certificate", unavailable)
    evaluated = native._evaluate(canonical_bytes(evidence), request, policy)
    assert evaluated.outcome.value == "FAIL"
    assert evaluated.observations["declared_eligibility_failure"]
    assert evaluated.observations["unavailable_execution"]


@pytest.mark.parametrize("error", [RecursionError, OverflowError])
def test_terminal_interpreter_internal_resource_unknown_is_typed_unavailable(error, monkeypatch):
    request, policy, evidence, _ = fixture()
    certificate = native.build_identity_presentation_certificate(request, canonical_bytes(evidence), policy=policy)
    execute = native.identity_lifecycle_replay.replay_declared_identity_lifecycle
    def terminal(binding, events, rows, **selections):
        if events and events[-1]["kind"] == "human_exit":
            original = native.identity_lifecycle_replay._digest
            def capacity(value):
                if type(value) is list and value is events:
                    raise error("actual augmented retained-history hash capacity unavailable")
                return original(value)
            with monkeypatch.context() as temporary:
                temporary.setattr(native.identity_lifecycle_replay, "_digest", capacity)
                return execute(binding, events, rows, **selections)
        return execute(binding, events, rows, **selections)
    monkeypatch.setattr(native.identity_lifecycle_replay, "replay_declared_identity_lifecycle", terminal)
    evaluated = native._evaluate(canonical_bytes(evidence), request, policy)
    assert evaluated.outcome.value == "UNKNOWN"
    assert evaluated.observations["unavailable_execution"]
    with pytest.raises(native.IdentityPresentationUnavailable):
        native.recheck_identity_presentation_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("case,expected,exit_code", [("complete", "PASS", 0), ("missing", "UNKNOWN", 2), ("false", "FAIL", 1)])
def test_public_route_cli_and_inventory_preserve_configured_scope(case, expected, exit_code, tmp_path, capsys):
    from verifier.domains.inventory import get_slot
    from verifier.domains.contracts.current_object_routes import replay_current_object_certificate
    from verifier.runtime.public_cli import main
    request, policy, evidence, k = fixture()
    if case == "false":
        evidence["supports"]["attribute"]["payload"]["witness"]["value"] = "foreign-selected-value"
        resign(evidence, "attribute", k["b"][0])
        repin(request, evidence)
    raw = None if case == "missing" else canonical_bytes(evidence)
    certificate = native.build_identity_presentation_certificate(request, raw, policy=policy)
    report = replay_current_object_certificate(certificate, semantic_version=native.SEMANTIC_VERSION,
        objective=native.COORDINATE, represented_kind="IDENTITY", expected_request=request, policy=policy)
    assert report["computational_status"] == expected
    for field in ("real_issuer_authority", "human_authenticity", "physical_exit_enforcement", "whole_identity_closure", "object_profile_conformance"):
        assert report["native_result"][field] == "NOT_ESTABLISHED"
    slot = get_slot("IDENTITY", 4)
    assert slot.mechanized and slot.coordinate == "IDENTITY-4.1" and slot.status == "REPLAYABLE"
    for name, value in (("certificate", certificate), ("request", canonical_bytes(request)), ("policy", canonical_bytes(policy))):
        (tmp_path / (name + ".json")).write_bytes(value)
    assert main(["current-object", "check", str(tmp_path / "certificate.json"), "--semantic-version", native.SEMANTIC_VERSION,
        "--objective", native.COORDINATE, "--represented-kind", "IDENTITY", "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"]) == exit_code
    assert json.loads(capsys.readouterr().out)["computational_status"] == expected


@pytest.mark.parametrize("error", [RecursionError, OverflowError, OSError])
@pytest.mark.parametrize("false_attribute", [False, True])
def test_actual_inherited_native2_evidence_reader_capacity_and_fresh_refutation(error, false_attribute, monkeypatch):
    request, policy, evidence, k = fixture()
    certificate = native.build_identity_presentation_certificate(request, canonical_bytes(evidence), policy=policy)
    if false_attribute:
        evidence["supports"]["attribute"]["payload"]["witness"]["value"] = "foreign-selected-value"
        resign(evidence, "attribute", k["b"][0])
        repin(request, evidence)
    original = identity_lifecycle.strict_json_loads
    def unavailable(text):
        if text.startswith('{"binding":'):
            raise error("actual inherited native2 retained evidence reader capacity unavailable")
        return original(text)
    monkeypatch.setattr(identity_lifecycle, "strict_json_loads", unavailable)
    decision = native._evaluate(canonical_bytes(evidence), request, policy)
    assert decision.outcome.value == ("FAIL" if false_attribute else "UNKNOWN")
    assert decision.observations["unavailable_execution"]
    with pytest.raises(native.IdentityPresentationUnavailable):
        native.recheck_identity_presentation_certificate(certificate, expected_request=request if not false_attribute else json.loads(certificate)["request"], policy=policy)


def test_fresh_native_refutation_of_carried_pass_is_refused_even_with_child_capacity(monkeypatch):
    request, policy, evidence, _ = fixture()
    certificate = native.build_identity_presentation_certificate(request, canonical_bytes(evidence), policy=policy)
    def unavailable(*_, **__):
        raise OSError("selected native3 execution unavailable")
    def refused(*_, **__):
        raise Refuted("fresh independently evaluated support refutation")
    monkeypatch.setattr(native.identity_scope, "recheck_identity_scope_certificate", unavailable)
    monkeypatch.setattr(native, "_support", refused)
    decision = native._evaluate(canonical_bytes(evidence), request, policy)
    assert decision.outcome.value == "FAIL" and decision.observations["unavailable_execution"]
    with pytest.raises(native.IdentityPresentationError):
        native.recheck_identity_presentation_certificate(certificate, expected_request=request, policy=policy)
