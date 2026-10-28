"""Current EVENT-2.1 retained declared dispatch and acknowledgment replay.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Log positions, counts and checker budgets are
dimensionless. A retained acknowledgment is not proof that a handler ran.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import random

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import event_dispatch
from verifier.domains.inventory import get_slot


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def base_inputs() -> dict:
    handlers = [
        {"id": "audit", "topics": ["order.created", "order.paid"],
         "writes": {"audited": True}},
        {"id": "billing", "topics": ["order.created"],
         "writes": {"stage": "billed"}},
        {"id": "shipping", "topics": ["order.paid"],
         "writes": {"stage": "shipped"}},
    ]
    log = [
        {"op": "emit", "event": "e1", "topic": "order.created"},
        {"op": "dispatch", "event": "e1", "handler": "audit"},
        {"op": "dispatch", "event": "e1", "handler": "billing"},
        {"op": "ack", "event": "e1", "handler": "billing"},
        {"op": "ack", "event": "e1", "handler": "audit"},
        {"op": "emit", "event": "e2", "topic": "order.paid"},
        {"op": "dispatch", "event": "e2", "handler": "shipping"},
        {"op": "dispatch", "event": "e2", "handler": "audit"},
        {"op": "ack", "event": "e2", "handler": "audit"},
        {"op": "ack", "event": "e2", "handler": "shipping"},
    ]
    return {"handlers": handlers, "initial_state": {"audited": False, "stage": "new"},
            "log": log, "final_state": {"audited": True, "stage": "shipped"}}


def oracle(inputs: dict) -> str:
    """Independent whole-log set and counter reading of the declared proposition."""
    log = inputs["log"]
    if not log:
        return "UNKNOWN"
    topics = {row["id"]: set(row["topics"]) for row in inputs["handlers"]}
    emits = [(i, row) for i, row in enumerate(log) if row["op"] == "emit"]
    dispatches = [(i, row) for i, row in enumerate(log) if row["op"] == "dispatch"]
    acks = [(i, row) for i, row in enumerate(log) if row["op"] == "ack"]
    if max(Counter(row["event"] for _, row in emits).values(), default=0) > 1:
        return "FAIL"
    emitted_at = {row["event"]: (i, row["topic"]) for i, row in emits}
    expected = {(event, handler) for event, (_, topic) in emitted_at.items()
                for handler, subscribed in topics.items() if topic in subscribed}
    dispatch_pairs = Counter((row["event"], row["handler"]) for _, row in dispatches)
    ack_pairs = Counter((row["event"], row["handler"]) for _, row in acks)
    if set(dispatch_pairs) != expected or any(n != 1 for n in dispatch_pairs.values()):
        return "FAIL"
    if set(ack_pairs) != expected or any(n != 1 for n in ack_pairs.values()):
        return "FAIL"
    dispatched_at = {(row["event"], row["handler"]): i for i, row in dispatches}
    if any(emitted_at[row["event"]][0] > i for i, row in dispatches):
        return "FAIL"
    if any(dispatched_at[(row["event"], row["handler"])] > i for i, row in acks):
        return "FAIL"
    writes = {row["id"]: row["writes"] for row in inputs["handlers"]}
    state = dict(inputs["initial_state"])
    for _, row in acks:
        state = {**state, **writes[row["handler"]]}
    return "PASS" if state == inputs["final_state"] else "FAIL"


def selected(inputs: dict | None = None, *, include_inputs: bool = True,
             subject_id: str = "bus", **limits: int):
    inputs = base_inputs() if inputs is None else inputs
    fixed = [
        NamespaceObject.create("clock", "TIME", {}),
        NamespaceObject.create("place", "SPACE", {}),
        NamespaceObject.create("meaning", "OBJECT", {}),
    ]
    subject = NamespaceObject.create(subject_id, "EVENT", {
        "scope": "retained-event-dispatch", "dispatch_digest": digest(inputs)},
        {"time": ["clock"], "space": ["place"], "meaning": ["meaning"]})
    objects = [*fixed, subject]
    evidence = canonical_bytes({
        "schema_version": event_dispatch.EVIDENCE_VERSION,
        "objects": [obj.to_dict() for obj in objects],
        "inputs": inputs if include_inputs else None,
    })
    policy = event_dispatch.event_dispatch_policy(trust_roots=["selected-event-bus"])
    request = event_dispatch.event_dispatch_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits)
    return request, policy, evidence


def status(request: dict, policy: dict, evidence: bytes | None) -> str:
    certificate = event_dispatch.build_event_dispatch_certificate(
        request, evidence, policy=policy)
    return event_dispatch.recheck_event_dispatch_certificate(
        certificate, expected_request=request, policy=policy)["status"]


def test_inventory_selects_event_dispatch_for_event_dynamics():
    slot = get_slot("EVENT", 2)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.coordinate == "EVENT-2.1"
    assert slot.mechanized_route["artifact_coordinate"] == "EVENT-2.1"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.event_dispatch.recheck_event_dispatch_certificate")


def test_declared_dispatch_passes_and_rechecks_from_decoded_bytes(tmp_path: Path):
    assert oracle(base_inputs()) == "PASS"
    request, policy, evidence = selected()
    certificate = event_dispatch.build_event_dispatch_certificate(
        request, evidence, policy=policy)
    (tmp_path / "certificate.json").write_bytes(certificate)
    decoded = json.loads((tmp_path / "certificate.json").read_bytes().decode("utf-8"))
    reread = canonical_bytes(decoded)
    assert reread == certificate
    result = event_dispatch.recheck_event_dispatch_certificate(
        reread, expected_request=json.loads(canonical_bytes(request)),
        policy=json.loads(canonical_bytes(policy)))
    assert result["status"] == "PASS"
    assert result["declared_dispatch_and_acknowledgment"] == "PASS"
    for field in ("occurrence_authenticity", "handler_execution", "delivery_guarantee",
                  "physical_causality", "operand_truth", "whole_event_dynamics",
                  "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"
    assert result["evaluation"]["outcome"] == "PASS"


def _remove(log: list, row: dict) -> None:
    log.remove(row)


def _missing_matching_dispatch(inputs):
    _remove(inputs["log"], {"op": "dispatch", "event": "e1", "handler": "billing"})
    _remove(inputs["log"], {"op": "ack", "event": "e1", "handler": "billing"})
    inputs["final_state"] = {"audited": True, "stage": "shipped"}


def _extra_nonmatching_dispatch(inputs):
    inputs["log"][3:3] = [{"op": "dispatch", "event": "e1", "handler": "shipping"},
                          {"op": "ack", "event": "e1", "handler": "shipping"}]


def _duplicate_ack(inputs):
    inputs["log"].append({"op": "ack", "event": "e2", "handler": "shipping"})


def _ack_before_dispatch(inputs):
    log = inputs["log"]
    log[6], log[9] = log[9], log[6]


def _dispatch_before_emission(inputs):
    log = inputs["log"]
    row = {"op": "dispatch", "event": "e2", "handler": "shipping"}
    log.remove(row)
    log.insert(0, row)


def _unacknowledged_dispatch(inputs):
    _remove(inputs["log"], {"op": "ack", "event": "e1", "handler": "audit"})


def _ack_order_changes_state_fold(inputs):
    log = inputs["log"]
    row = {"op": "ack", "event": "e1", "handler": "billing"}
    log.remove(row)
    log.append(row)


def _duplicate_emission(inputs):
    inputs["log"].append({"op": "emit", "event": "e1", "topic": "order.created"})


def _undeclared_handler(inputs):
    inputs["log"].insert(1, {"op": "dispatch", "event": "e1", "handler": "ghost"})


def _final_state_not_fold(inputs):
    inputs["final_state"] = {"audited": True, "stage": "billed"}


MUTANTS = {
    "missing-matching-dispatch": _missing_matching_dispatch,
    "extra-nonmatching-dispatch": _extra_nonmatching_dispatch,
    "duplicate-acknowledgment": _duplicate_ack,
    "acknowledgment-before-dispatch": _ack_before_dispatch,
    "dispatch-before-emission": _dispatch_before_emission,
    "unacknowledged-dispatch": _unacknowledged_dispatch,
    "acknowledgment-order-changes-fold": _ack_order_changes_state_fold,
    "duplicate-emission": _duplicate_emission,
    "undeclared-handler": _undeclared_handler,
    "final-state-not-fold": _final_state_not_fold,
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_rehashed_dispatch_counterexamples_fail(name):
    inputs = base_inputs()
    MUTANTS[name](inputs)
    assert oracle(inputs) == "FAIL"
    request, policy, evidence = selected(inputs)
    assert status(request, policy, evidence) == "FAIL"


def test_reordered_acknowledgment_with_matching_fold_still_passes():
    inputs = base_inputs()
    _ack_order_changes_state_fold(inputs)
    inputs["final_state"] = {"audited": True, "stage": "billed"}
    assert oracle(inputs) == "PASS"
    request, policy, evidence = selected(inputs)
    assert status(request, policy, evidence) == "PASS"


def _random_inputs(rng: random.Random) -> dict:
    inputs = base_inputs()
    log = inputs["log"]
    choice = rng.randrange(6)
    if choice == 0:
        index = rng.randrange(len(log))
        log.pop(index)
    elif choice == 1:
        i, j = rng.randrange(len(log)), rng.randrange(len(log))
        log[i], log[j] = log[j], log[i]
    elif choice == 2:
        log.insert(rng.randrange(len(log) + 1), deepcopy(rng.choice(log)))
    elif choice == 3:
        acks = [row for row in log if row["op"] == "ack"]
        rng.shuffle(acks)
        others = [row for row in log if row["op"] != "ack"]
        log[:] = others + acks
    elif choice == 4:
        inputs["final_state"] = {"audited": rng.choice([True, False]),
                                 "stage": rng.choice(["new", "billed", "shipped"])}
    else:
        row = rng.choice(log)
        if "handler" in row:
            row["handler"] = rng.choice(["audit", "billing", "shipping"])
        else:
            row["topic"] = rng.choice(["order.created", "order.paid"])
    return inputs


def test_seeded_random_logs_agree_with_independent_oracle():
    rng = random.Random(20261001)
    seen = Counter()
    for _ in range(40):
        inputs = _random_inputs(rng)
        expected = oracle(inputs)
        request, policy, evidence = selected(inputs)
        assert status(request, policy, evidence) == expected, inputs
        seen[expected] += 1
    assert seen["FAIL"] > 0 and seen["PASS"] > 0


def test_absent_empty_or_exhausted_retained_log_remains_unknown():
    request, policy, evidence = selected(include_inputs=False)
    assert status(request, policy, evidence) == "UNKNOWN"
    request, policy, evidence = selected()
    assert status(request, policy, None) == "UNKNOWN"
    empty = base_inputs()
    empty["log"] = []
    empty["final_state"] = empty["initial_state"]
    assert oracle(empty) == "UNKNOWN"
    request, policy, evidence = selected(empty)
    assert status(request, policy, evidence) == "UNKNOWN"
    for bound in ("max_operations", "max_items", "max_objects",
                  "max_composition_operations", "max_evidence_bytes",
                  "max_payload_bytes", "max_reference_bytes"):
        request, policy, evidence = selected(**{bound: 1})
        assert status(request, policy, evidence) == "UNKNOWN", bound


def test_one_bit_certificate_tamper_is_refused():
    request, policy, evidence = selected()
    certificate = event_dispatch.build_event_dispatch_certificate(
        request, evidence, policy=policy)
    for position in (0, len(certificate) // 3, len(certificate) // 2, len(certificate) - 2):
        tampered = bytearray(certificate)
        tampered[position] ^= 0x01
        with pytest.raises(event_dispatch.EventDispatchError):
            event_dispatch.recheck_event_dispatch_certificate(
                bytes(tampered), expected_request=request, policy=policy)


def test_substituted_subject_request_policy_and_verdict_are_refused():
    request, policy, evidence = selected()
    certificate = event_dispatch.build_event_dispatch_certificate(
        request, evidence, policy=policy)
    changed = deepcopy(request)
    changed["subject_id"] = "other-bus"
    with pytest.raises(event_dispatch.EventDispatchError):
        event_dispatch.recheck_event_dispatch_certificate(
            certificate, expected_request=changed, policy=policy)
    other_request, _, _ = selected(subject_id="other-bus")
    with pytest.raises(event_dispatch.EventDispatchError):
        event_dispatch.recheck_event_dispatch_certificate(
            certificate, expected_request=other_request, policy=policy)
    other_policy = deepcopy(policy)
    other_policy["trust_roots"] = ["other-root"]
    with pytest.raises(event_dispatch.EventDispatchError):
        event_dispatch.recheck_event_dispatch_certificate(
            certificate, expected_request=request, policy=other_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(event_dispatch.EventDispatchError):
        event_dispatch.recheck_event_dispatch_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    wrong_kind = deepcopy(request)
    wrong_kind["object_kind"] = "SPACE"
    with pytest.raises(event_dispatch.EventDispatchError):
        event_dispatch.build_event_dispatch_certificate(wrong_kind, evidence, policy=policy)
    _, _, other_evidence = selected(subject_id="other-bus")
    with pytest.raises(event_dispatch.EventDispatchError):
        event_dispatch.build_event_dispatch_certificate(request, other_evidence, policy=policy)


def test_retained_dispatch_certificate_refuses_evidence_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty)

    request, policy, evidence = selected()
    retained = json.loads(event_dispatch.build_event_dispatch_certificate(
        request, evidence, policy=policy))
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface("EVENT", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",)) for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


@pytest.mark.parametrize("relative", [
    "domains/contracts/event_dispatch.py", "domains/contracts/retained_selection.py",
    "domains/common.py", "core/namespace.py", "core/certificate.py",
    "core/evidence.py", "core/receipt.py", "standard/CURRENT_EVENT_DISPATCH.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate = event_dispatch.build_event_dispatch_certificate(
        request, evidence, policy=policy)
    original = Path.read_bytes
    target = Path(event_dispatch.__file__).parents[2] / relative

    def changed(path):
        data = original(path)
        return data + b"\nchanged dispatch dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        event_dispatch.recheck_event_dispatch_certificate(
            certificate, expected_request=request, policy=policy)


def test_public_route_command_and_polish_keep_dynamics_boundary(tmp_path, capsys):
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish

    request, policy, evidence = selected()
    certificate = event_dispatch.build_event_dispatch_certificate(
        request, evidence, policy=policy)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=event_dispatch.SEMANTIC_VERSION,
        objective=event_dispatch.COORDINATE, represented_kind="EVENT",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["handler_execution"] == "NOT_ESTABLISHED"
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)),
                           ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
        "--semantic-version", event_dispatch.SEMANTIC_VERSION,
        "--objective", event_dispatch.COORDINATE, "--represented-kind", "EVENT",
        "--request", str(tmp_path / "request.json"),
        "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    certificate_digest = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(evidence)["objects"],
              "certificates": {certificate_digest: certificate.decode()}}
    selected_request = {"schema_version": "verifier-polish-request-1",
        "root_id": "bus", "collection_digest": request["collection_digest"],
        "bundle_digest": digest(bundle),
        "requirements": [{"object_id": "bus", "tier": tier,
            "applicability": "REQUIRED", "rationale": "Selected declared dispatch only",
            "objectives": []} for tier in range(1, 10)]}
    selected_request["requirements"][1]["objectives"] = [{
        "semantic_version": event_dispatch.SEMANTIC_VERSION,
        "coordinate": event_dispatch.COORDINATE,
        "request": request, "policy": policy,
        "certificate_digest": certificate_digest}]
    polished = assess_polish(canonical_bytes(bundle),
                             request_bytes=canonical_bytes(selected_request))
    assert polished["objectives"][0]["status"] == "PASS", polished["objectives"][0]
    assert polished["objectives"][0]["public_checkability"] == "NOT_ESTABLISHED"
    assert polished["status"] == "UNKNOWN" and polished["polished"] is False
