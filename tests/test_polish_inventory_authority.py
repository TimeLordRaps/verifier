"""Independent finite inventory operator-admission controls.

Verifier Standard (VSTD); JavaScript Object Notation (JSON);
Secure Hash Algorithm 256-bit (SHA-256); hash-based message authentication code
(HMAC). These synthetic roots establish no real-world authority. Counts are
dimensionless; byte bounds and integer Unix seconds are explicit selections.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import hmac
import importlib
import json
import secrets

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.governance import (
    GovernanceContext, GovernancePolicy, GovernancePrincipal, evaluate_governance,
    policy_digest,
)
from verifier.runtime import polish_inventory
from test_polish_inventory import digest, plan, request, fixture


OPERATION = "ADMIT_SELECTED_POLISH_INVENTORY"
SUBJECT_VERSION = "verifier-polish-inventory-authority-subject-1"
REQUEST_VERSION = "verifier-polish-inventory-authority-request-1"


def module():
    return importlib.import_module("verifier.runtime.polish_inventory_authority")


def sign(payload, key):
    return {**payload, "signature": hmac.new(key, canonical_bytes(payload), hashlib.sha256).hexdigest()}


def selected_subject(inputs, report, authority_mechanism):
    supplied = json.loads(inputs["plan_bytes"])
    omitted = [row for row in supplied["requirements"] if row["applicability"] == "NOT_APPLICABLE"]
    return {"schema_version": SUBJECT_VERSION, "operation": OPERATION,
        "authority_mechanism_digest": authority_mechanism,
        "inventory_assessment_digest": report["assessment_digest"],
        "input_digests": {name: digest(inputs[name + "_bytes"]) for name in (
            "plan", "profile", "collection", "inventory_request")},
        "root_id": report["root_id"], "profile_digest": report["profile_digest"],
        "collection_digest": report["collection_digest"],
        "admitted_inapplicability": omitted}


def specimen(authority_mechanism="sha256:" + "c" * 64, *, optional=False, unresolved=False):
    payload = {"signals": {"enabled": not optional},
               "private_witness": "authority-private-witness-do-not-echo"}
    if unresolved:
        payload["signals"] = {}
    profile, collection, objects = fixture(payload=payload)
    selected = request(profile, collection, objects)
    proposed = plan(profile, selected, enabled="UNKNOWN" if unresolved else
                    "NOT_APPLICABLE" if optional else "REQUIRED")
    values = {"plan_bytes": canonical_bytes(proposed), "profile_bytes": canonical_bytes(profile),
        "collection_bytes": canonical_bytes(collection), "inventory_request_bytes": canonical_bytes(selected)}
    report = polish_inventory.assess_objective_inventory(values["plan_bytes"],
        profile_bytes=values["profile_bytes"], collection_bytes=values["collection_bytes"],
        request_bytes=values["inventory_request_bytes"])
    assert report["status"] == ("UNKNOWN" if unresolved else "PASS")
    subject = selected_subject(values, report, authority_mechanism)
    principals = tuple(GovernancePrincipal(actor, actor + "-key", secrets.token_bytes(32))
                       for actor in ("reviewer-a", "reviewer-b", "reviewer-veto"))
    policy = GovernancePolicy("independent-fixture-operator", 3, ("OBJECT",), (OPERATION,),
        ("synthetic/lab",), principals, 2, ("reviewer-veto",), "status-key",
        secrets.token_bytes(32), 100, 1000, 30)
    selection = {"schema_version": REQUEST_VERSION, "mechanism_digest": authority_mechanism,
        "subject_digest": digest(canonical_bytes(subject)), "policy_digest": policy_digest(policy),
        "actor_id": "submitter", "observer_id": "qualified-operator",
        "purpose": "review exact finite application profile and derived applicability",
        "timestamp": 200, "jurisdiction": "synthetic/lab", "invocation_id": "selected-inventory-1",
        "admitted_inapplicability": subject["admitted_inapplicability"]}
    context = GovernanceContext("OBJECT", selection["subject_digest"][7:], OPERATION,
        selection["actor_id"], selection["observer_id"], selection["purpose"],
        selection["timestamp"], selection["jurisdiction"], selection["invocation_id"])
    decisions = [sign({"schema": "verifier-governance-decision-1",
        "decision_id": actor.actor_id + "-approval", "policy_digest": policy_digest(policy),
        "binding": asdict(context), "actor_id": actor.actor_id, "key_id": actor.key_id,
        "decision": "APPROVE", "issued_at": 190, "expires_at": 250}, actor.key)
        for actor in principals[:2]]
    status = sign({"schema": "verifier-governance-status-1", "policy_digest": policy_digest(policy),
        "key_id": policy.status_key_id, "observed_at": 195, "expires_at": 225,
        "revoked_decisions": [], "revoked_actors": [], "consumed_invocations": []}, policy.status_key)
    values.update(authority_request_bytes=canonical_bytes(selection),
        authority_evidence_bytes=canonical_bytes({"decisions": decisions, "status": status}),
        policy=policy, evaluation_time=200)
    return values, subject, context


def current(**kwargs):
    return specimen(module().mechanism_digest(), **kwargs)


def assess(values, **changes):
    return module().assess_inventory_authority(**{**values, **changes})


def rewrite(raw, **changes):
    return canonical_bytes({**json.loads(raw), **changes})


def resign_votes(values, binding=None, *, decision=None):
    evidence = json.loads(values["authority_evidence_bytes"])
    for index, row in enumerate(evidence["decisions"]):
        payload = {name: value for name, value in row.items() if name != "signature"}
        if binding is not None:
            payload["binding"] = asdict(binding)
        if decision is not None:
            payload["decision"] = decision
        evidence["decisions"][index] = sign(payload, values["policy"].principals[index].key)
    return canonical_bytes(evidence)


def test_existing_inventory_and_signed_action_independently_pass():
    values, subject, context = specimen(optional=True)
    evidence = json.loads(values["authority_evidence_bytes"])
    result = evaluate_governance(context, tuple(evidence["decisions"]), policy=values["policy"],
        status=evidence["status"], evaluation_time=200, computational_verdict="PASS")
    assert result.verdict.value == "PASS"
    assert len(subject["admitted_inapplicability"]) == 1
    assert result.receipt["binding"]["artifact_digest"] == digest(canonical_bytes(subject))[7:]


def test_existing_signed_action_cannot_be_reused_for_namespace_admission():
    values, _, context = specimen()
    evidence = json.loads(values["authority_evidence_bytes"])
    result = evaluate_governance(replace(context, operation="NAMESPACE_ADMIT"),
        tuple(evidence["decisions"]), policy=values["policy"], status=evidence["status"],
        evaluation_time=200, computational_verdict="PASS")
    assert result.verdict.value == "REJECTED"


@pytest.mark.parametrize("optional", [False, True])
def test_exact_selected_authority_pass_retains_other_open_gates(optional):
    values, subject, _ = current(optional=optional)
    result = assess(values)
    assert result["status"] == "PASS"
    assert result["inventory_status"] == "PASS"
    assert result["profile_authority_status"] == "PASS"
    assert result["inapplicability_authority_status"] == "PASS"
    assert result["subject_digest"] == digest(canonical_bytes(subject))
    assert result["admitted_inapplicability_count"] == int(optional)
    assert result["objective_inventory_closure"] == "NOT_ESTABLISHED"
    assert result["native_objective_truth"] == "NOT_EVALUATED"
    assert result["public_checkability"] == "NOT_ESTABLISHED"
    assert result["polished"] is False
    assert result["invocation_consumption"] == "NOT_PERFORMED"


def test_keys_and_private_witness_are_not_serialized():
    values, _, _ = current()
    result = assess(values)
    assert result["status"] == "PASS"
    encoded = canonical_bytes(result)
    assert b"authority-private-witness-do-not-echo" not in encoded
    for secret in (values["policy"].status_key, *(p.key for p in values["policy"].principals)):
        assert secret not in encoded and secret.hex().encode() not in encoded


@pytest.mark.parametrize("field,value", [
    ("subject_digest", "sha256:" + "0" * 64),
    ("mechanism_digest", "sha256:" + "0" * 64),
    ("policy_digest", "0" * 64), ("actor_id", "another-submitter"),
    ("observer_id", "another-observer"), ("purpose", "publish"),
    ("jurisdiction", "another-lab"), ("invocation_id", "another-invocation"),
    ("timestamp", 201), ("timestamp", 200.0), ("timestamp", True),
    ("schema_version", "verifier-current-object-governance-request-1"),
])
def test_independent_selection_substitution_refuses(field, value):
    values, _, _ = current()
    result = assess(values, authority_request_bytes=rewrite(values["authority_request_bytes"], **{field: value}))
    assert result["status"] == "FAIL"


@pytest.mark.parametrize("change", ["omit", "extra", "promote-required"])
def test_inapplicability_admission_is_exact_and_not_a_blanket_waiver(change):
    values, _, _ = current(optional=True)
    selected = json.loads(values["authority_request_bytes"])
    if change == "omit":
        selected["admitted_inapplicability"] = []
    elif change == "extra":
        selected["admitted_inapplicability"].append({"object_id": "root", "coordinate": "OBJECT-9.1",
            "semantic_version": "verifier-current-object-obligations-1", "applicability": "NOT_APPLICABLE"})
    else:
        selected["admitted_inapplicability"][0]["applicability"] = "REQUIRED"
    result = assess(values, authority_request_bytes=canonical_bytes(selected))
    assert result["status"] == "FAIL"


def test_unresolved_declared_applicability_never_gets_authority_pass():
    values, _, _ = current(unresolved=True)
    result = assess(values)
    assert result["status"] == "UNKNOWN"
    assert result["inventory_status"] == "UNKNOWN"
    assert result["inapplicability_authority_status"] != "PASS"
    assert result["polished"] is False


def test_known_inventory_omission_precedes_any_authority_call(monkeypatch):
    values, _, _ = current()
    supplied = json.loads(values["plan_bytes"])
    supplied["requirements"].pop()
    invoked = []
    monkeypatch.setattr(module(), "evaluate_governance", lambda *args, **kwargs: invoked.append(1))
    result = assess(values, plan_bytes=canonical_bytes(supplied))
    assert result["status"] == "FAIL" and result["inventory_status"] == "FAIL"
    assert invoked == []


def test_changed_but_valid_collection_cannot_reuse_admission():
    values, _, _ = current()
    changed, _, _ = current(optional=True)
    for name in ("plan_bytes", "profile_bytes", "collection_bytes", "inventory_request_bytes"):
        values[name] = changed[name]
    native = polish_inventory.assess_objective_inventory(values["plan_bytes"],
        profile_bytes=values["profile_bytes"], collection_bytes=values["collection_bytes"],
        request_bytes=values["inventory_request_bytes"])
    assert native["status"] == "PASS"
    assert assess(values)["status"] == "FAIL"


@pytest.mark.parametrize("case", ["signature", "duplicate", "veto", "revoke-decision", "revoke-actor", "consumed"])
def test_actual_governance_failures_refuse_selected_inventory(case):
    values, _, _ = current()
    evidence = json.loads(values["authority_evidence_bytes"])
    if case == "signature":
        evidence["decisions"][0]["signature"] = "0" * 64
    elif case == "duplicate":
        evidence["decisions"][1] = evidence["decisions"][0]
    elif case == "veto":
        payload = {name: value for name, value in evidence["decisions"][0].items() if name != "signature"}
        payload["decision"] = "DENY"
        evidence["decisions"][0] = sign(payload, values["policy"].principals[0].key)
    else:
        payload = {name: value for name, value in evidence["status"].items() if name != "signature"}
        field, value = {"revoke-decision": ("revoked_decisions", "reviewer-a-approval"),
            "revoke-actor": ("revoked_actors", "reviewer-a"),
            "consumed": ("consumed_invocations", "selected-inventory-1")}[case]
        payload[field] = [value]
        evidence["status"] = sign(payload, values["policy"].status_key)
    assert assess(values, authority_evidence_bytes=canonical_bytes(evidence))["status"] == "FAIL"


@pytest.mark.parametrize("case", ["clock", "policy", "evidence", "quorum", "status", "stale-status"])
def test_missing_authority_evidence_stays_unknown(case):
    values, _, _ = current()
    if case == "clock":
        values["evaluation_time"] = None
    elif case == "policy":
        values["policy"] = None
    elif case == "evidence":
        values["authority_evidence_bytes"] = None
    else:
        evidence = json.loads(values["authority_evidence_bytes"])
        if case == "quorum":
            evidence["decisions"] = evidence["decisions"][:1]
        elif case == "status":
            evidence["status"] = None
        else:
            payload = {name: value for name, value in evidence["status"].items() if name != "signature"}
            payload.update(observed_at=101, expires_at=900)
            evidence["status"] = sign(payload, values["policy"].status_key)
        values["authority_evidence_bytes"] = canonical_bytes(evidence)
    result = assess(values)
    assert result["status"] == "UNKNOWN"
    assert result["profile_authority_status"] != "PASS"


def test_selected_submitter_cannot_supply_its_own_approval():
    values, _, context = current()
    selected = json.loads(values["authority_request_bytes"])
    selected["actor_id"] = "reviewer-a"
    context = replace(context, actor_id="reviewer-a")
    values["authority_request_bytes"] = canonical_bytes(selected)
    values["authority_evidence_bytes"] = resign_votes(values, context)
    evidence = json.loads(values["authority_evidence_bytes"])
    actual = evaluate_governance(context, tuple(evidence["decisions"]), policy=values["policy"],
        status=evidence["status"], evaluation_time=200, computational_verdict="PASS")
    assert actual.verdict.value == "PASS"
    assert assess(values)["status"] == "FAIL"


def test_root_rotation_refuses_even_when_public_terms_stay_the_same():
    values, _, _ = current()
    previous = values["policy"]
    replacement = replace(previous, principals=tuple(replace(p, key=secrets.token_bytes(32))
                                                    for p in previous.principals))
    assert policy_digest(previous) == policy_digest(replacement)
    assert assess(values, policy=replacement)["status"] == "FAIL"


def test_invalid_policy_type_is_refused_without_attribute_callback():
    values, _, _ = current()
    callbacks = []
    class Foreign:
        def __getattribute__(self, name):
            callbacks.append(name)
            raise AssertionError("foreign policy was inspected")
    assert assess(values, policy=Foreign())["status"] == "FAIL"
    assert callbacks == []


@pytest.mark.parametrize("field", ["plan_bytes", "profile_bytes", "collection_bytes", "inventory_request_bytes",
                                   "authority_request_bytes", "authority_evidence_bytes"])
def test_foreign_byte_subclasses_refuse_before_length_or_hash(field):
    values, _, _ = current()
    callbacks = []
    class Foreign(bytes):
        def __len__(self):
            callbacks.append("length")
            raise AssertionError("foreign length callback")
    result = assess(values, **{field: Foreign(values[field])})
    assert result["status"] == "FAIL"
    assert callbacks == []


def test_oversized_authority_request_refuses_before_hash(monkeypatch):
    values, _, _ = current()
    calls = []
    actual = module().hashlib.sha256
    def instrumented(raw=b"", *args, **kwargs):
        calls.append(len(raw))
        return actual(raw, *args, **kwargs)
    monkeypatch.setattr(module().hashlib, "sha256", instrumented)
    result = assess(values, authority_request_bytes=b" " * (1024 * 1024 + 1))
    assert result["status"] == "FAIL" and calls == []


@pytest.mark.parametrize("field", ["authority_request_bytes", "authority_evidence_bytes"])
def test_duplicate_json_key_refuses(field):
    values, _, _ = current()
    if field == "authority_request_bytes":
        duplicate = b'{"timestamp":200,' + values[field][1:]
    else:
        duplicate = b'{"status":null,' + values[field][1:]
    assert assess(values, **{field: duplicate})["status"] == "FAIL"


def test_real_positive_replay_and_rehashed_promotions_refuse():
    values, _, _ = current(optional=True)
    result = assess(values)
    assert result["status"] == "PASS"
    replay = module().recheck_inventory_authority(canonical_bytes(result), **values)
    assert replay["replay_status"] == "REPRODUCED" and replay["status"] == "PASS"
    for field, promoted in [("polished", True), ("objective_inventory_closure", "PASS"),
                            ("public_checkability", "PASS"), ("native_objective_truth", "PASS")]:
        altered = {**result, field: promoted}
        altered.pop("assessment_digest")
        altered["assessment_digest"] = digest(canonical_bytes(altered))
        refused = module().recheck_inventory_authority(canonical_bytes(altered), **values)
        assert refused["replay_status"] == "REJECTED"


def test_unknown_replay_is_scoped_and_does_not_become_authority_pass():
    values, _, _ = current()
    values["evaluation_time"] = None
    result = assess(values)
    assert result["status"] == "UNKNOWN"
    replay = module().recheck_inventory_authority(canonical_bytes(result), **values)
    assert replay["replay_status"] == "REPRODUCED" and replay["status"] == "UNKNOWN"


def test_positive_receipt_refutes_changed_exact_selection_bytes():
    values, _, _ = current()
    result = assess(values)
    assert result["status"] == "PASS"
    changed = {**values, "authority_request_bytes": json.dumps(
        json.loads(values["authority_request_bytes"]), indent=2).encode()}
    assert assess(changed)["status"] == "PASS"
    assert module().recheck_inventory_authority(canonical_bytes(result), **changed)["replay_status"] == "REJECTED"


def test_replay_refuses_foreign_assessment_without_callbacks():
    values, _, _ = current()
    callbacks = []
    class Foreign(bytes):
        def __len__(self):
            callbacks.append("length")
            raise AssertionError("untrusted receipt length callback")
    result = assess(values)
    assert result["status"] == "PASS"
    refused = module().recheck_inventory_authority(Foreign(canonical_bytes(result)), **values)
    assert refused["replay_status"] == "REJECTED" and callbacks == []


def test_authenticated_denial_survives_unresolved_applicability():
    values, _, context = current(unresolved=True)
    values["authority_evidence_bytes"] = resign_votes(values, decision="DENY")
    evidence = json.loads(values["authority_evidence_bytes"])
    actual = evaluate_governance(context, tuple(evidence["decisions"]), policy=values["policy"],
        status=evidence["status"], evaluation_time=200, computational_verdict="UNKNOWN")
    assert actual.verdict.value == "REJECTED"
    result = assess(values)
    assert result["inventory_status"] == "UNKNOWN"
    assert result["status"] == "FAIL"
    assert result["profile_authority_status"] == "REJECTED"


@pytest.mark.parametrize("alteration", ["float", "binding", "promotion"])
def test_returned_governance_evidence_is_independently_replayed(monkeypatch, alteration):
    values, _, _ = current()
    original = module().evaluate_governance
    def corrupt(*args, **kwargs):
        returned = original(*args, **kwargs)
        assert returned.verdict.value == "PASS"
        changed = deepcopy(returned.receipt)
        if alteration == "float":
            changed["policy_revision"] = float(changed["policy_revision"])
        elif alteration == "binding":
            changed["binding"]["artifact_digest"] = "0" * 64
        else:
            changed["consent"] = "PASS"
        return replace(returned, receipt=changed)
    monkeypatch.setattr(module(), "evaluate_governance", corrupt)
    assert assess(values)["status"] == "FAIL"


def test_returned_foreign_evidence_refuses_before_callback(monkeypatch):
    values, _, _ = current()
    callbacks = []
    original = module().evaluate_governance
    class ForeignMeta(type):
        def __eq__(self, other):
            callbacks.append("type-equality")
            return False
    class Foreign(dict, metaclass=ForeignMeta):
        def items(self):
            callbacks.append("items")
            raise AssertionError("foreign evidence callback")
    def corrupt(*args, **kwargs):
        returned = original(*args, **kwargs)
        assert returned.verdict.value == "PASS"
        return replace(returned, receipt=Foreign(returned.receipt))
    monkeypatch.setattr(module(), "evaluate_governance", corrupt)
    assert assess(values)["status"] == "FAIL"
    assert callbacks == []


@pytest.mark.parametrize("mode", ["required", "inapplicable", "unresolved"])
def test_subject_builder_matches_independently_written_signing_subject(mode):
    values, subject, _ = current(optional=mode == "inapplicable", unresolved=mode == "unresolved")
    selected = {name: values[name] for name in (
        "plan_bytes", "profile_bytes", "collection_bytes", "inventory_request_bytes")}
    assert module().build_inventory_authority_subject(**selected) == canonical_bytes(subject)


def test_subject_builder_refuses_a_known_omitted_requirement():
    values, _, _ = current()
    supplied = json.loads(values["plan_bytes"])
    supplied["requirements"].pop()
    selected = {name: values[name] for name in (
        "plan_bytes", "profile_bytes", "collection_bytes", "inventory_request_bytes")}
    selected["plan_bytes"] = canonical_bytes(supplied)
    with pytest.raises(ValueError):
        module().build_inventory_authority_subject(**selected)


def test_subject_builder_cannot_bypass_selected_capacity():
    values, _, _ = current()
    selection = json.loads(values["inventory_request_bytes"])
    selection["limits"]["expanded_objectives"] = 1
    values["inventory_request_bytes"] = canonical_bytes(selection)
    supplied = json.loads(values["plan_bytes"])
    supplied["request_digest"] = digest(values["inventory_request_bytes"])
    values["plan_bytes"] = canonical_bytes(supplied)
    selected = {name: values[name] for name in (
        "plan_bytes", "profile_bytes", "collection_bytes", "inventory_request_bytes")}
    native = polish_inventory.assess_objective_inventory(values["plan_bytes"],
        profile_bytes=values["profile_bytes"], collection_bytes=values["collection_bytes"],
        request_bytes=values["inventory_request_bytes"])
    assert native["status"] == "UNKNOWN" and native["reason"] == "RESOURCE_LIMIT_EXCEEDED"
    with pytest.raises(module().InventoryAuthorityUnavailable):
        module().build_inventory_authority_subject(**selected)
