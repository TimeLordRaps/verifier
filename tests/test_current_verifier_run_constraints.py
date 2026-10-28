"""VERIFIER-3.1 run-bound constraint observations, not substrate identity.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Event maxima count interpreter trace events
(dimensionless); report maxima are bytes. The run is two in-process replays of
one separately selected registered child certificate. Caller declarations are
retained but never count as observations.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import space_layout
from verifier.domains.contracts import verifier_run_constraints as vrc
from verifier.domains.inventory import get_slot

ZERO = "sha256:" + "0" * 64
ROUTE = (space_layout.SEMANTIC_VERSION, space_layout.COORDINATE, "SPACE")
PASSING = [
    {"id": "right", "start_byte": 16, "end_byte": 32, "alignment_bytes": 8},
    {"id": "left", "start_byte": 0, "end_byte": 16, "alignment_bytes": 16},
]
OVERLAP = [
    {"id": "a", "start_byte": 0, "end_byte": 24, "alignment_bytes": 8},
    {"id": "b", "start_byte": 16, "end_byte": 32, "alignment_bytes": 8},
]
EXCLUDED = ("execution_substrate_identity", "physical_resource_constraints",
            "isolation", "class_wide_soundness", "determinism_on_other_inputs",
            "cross_process_or_platform_determinism", "general_termination",
            "whole_verifier_statics", "object_profile_conformance")


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def raw_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def child(partitions: list | None = None, *, retained: bool = True):
    partitions = PASSING if partitions is None else partitions
    subject = NamespaceObject.create("space-root", "SPACE", {
        "scope": "retained-logical-byte-partitions", "unit": "byte",
        "extent_bytes": 32, "partitions_digest": digest(partitions)})
    evidence = canonical_bytes({
        "schema_version": space_layout.EVIDENCE_VERSION,
        "objects": [subject.to_dict()], "inputs": {"partitions": partitions}})
    policy = space_layout.space_layout_policy(trust_roots=["layout-root"])
    request = space_layout.space_layout_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        evidence_ref=digest(json.loads(evidence)), policy=policy)
    certificate = space_layout.build_space_layout_certificate(
        request, evidence if retained else None, policy=policy)
    return request, policy, certificate


def verifier_object(selection=ROUTE, identity: str = "verifier-run") -> NamespaceObject:
    semantic_version, objective, kind = selection
    return NamespaceObject.create(identity, "VERIFIER", {
        "checker_kind": "CURRENT_OBJECT_ROUTE", "semantic_version": semantic_version,
        "objective": objective, "represented_kind": kind})


def constraints(*, events: int = 5_000_000, report_bytes: int = 1_000_000,
                extra: tuple = ()) -> list[dict]:
    rows = [{"constraint_id": "events", "quantity": "traced_python_events", "maximum": events},
            {"constraint_id": "report", "quantity": "replay_report_bytes", "maximum": report_bytes},
            *extra]
    return sorted(rows, key=lambda row: row["constraint_id"])


def selected(*, partitions: list | None = None, retained_child: bool = True,
             rows: list | None = None, declared: tuple = (), subject=None,
             limits: dict | None = None, include: bool = True, certificate=None):
    child_request, child_policy, child_certificate = child(partitions, retained=retained_child)
    if certificate is not None:
        child_certificate = certificate(child_certificate)
    item = subject or verifier_object()
    expected_item = verifier_object()
    policy = vrc.verifier_run_constraints_policy(trust_roots=["run-root"])
    request = vrc.verifier_run_constraints_request(
        subject_id=expected_item.object_id, object_digest=expected_item.digest,
        collection_digest=composition_digest([expected_item]),
        child_semantic_version=ROUTE[0], child_objective=ROUTE[1],
        child_represented_kind=ROUTE[2],
        child_request_digest=digest(child_request),
        child_policy_digest=digest(child_policy),
        child_certificate_digest=raw_digest(child_certificate),
        declarant="caller:test-selector",
        constraints=rows if rows is not None else constraints(),
        evidence_ref=ZERO, policy=policy, limits=limits)
    run = vrc.run_digest(request)
    observations = [dict(row, run_digest=run if row["run_digest"] == "RUN" else row["run_digest"])
                    for row in declared]
    evidence = canonical_bytes({
        "schema_version": vrc.EVIDENCE_VERSION, "verifier_object": item.to_dict(),
        "child_request": child_request, "child_policy": child_policy,
        "child_certificate": base64.b64encode(child_certificate).decode("ascii"),
        "declared_observations": observations})
    request = dict(request, evidence_ref=raw_digest(evidence))
    return request, policy, (evidence if include else None), (child_request, child_policy, child_certificate)


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = vrc.build_verifier_run_constraints_certificate(request, evidence, policy=policy)
    result = vrc.recheck_verifier_run_constraints_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def route_report(child_request: dict, child_policy: dict, child_certificate: bytes) -> dict:
    """Independent oracle: one direct registered-route replay, no tracer."""
    return routes.replay_current_object_certificate(
        child_certificate, semantic_version=ROUTE[0], objective=ROUTE[1],
        represented_kind=ROUTE[2], expected_request=deepcopy(child_request),
        policy=deepcopy(child_policy))


def test_inventory_selects_the_run_constraint_recheck():
    slot = get_slot("VERIFIER", 3)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.coordinate == "VERIFIER-3.1"
    assert slot.mechanized_route["artifact_coordinate"] == "VERIFIER-3.1"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.verifier_run_constraints."
        "recheck_verifier_run_constraints_certificate")


def test_checker_observed_constraints_pass_and_recheck_from_decoded_bytes():
    request, policy, evidence, child_parts = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["run_bound_constraint_observations"] == "PASS"
    for field in EXCLUDED:
        assert result[field] == "NOT_ESTABLISHED", field
    decoded = json.loads(certificate.decode("utf-8"))
    again = vrc.recheck_verifier_run_constraints_certificate(
        canonical_bytes(decoded), expected_request=request, policy=policy)
    assert again == result
    observed = result["evaluation"]["observations"]
    assert observed["run_digest"] == vrc.run_digest(request)
    oracle = route_report(*child_parts)
    assert oracle["computational_status"] == "PASS"
    assert observed["child_report_digest"] == digest(oracle)
    rows = {row["constraint_id"]: row for row in observed["constraints"]}
    assert rows["report"]["observed_value"] == len(canonical_bytes(oracle))
    assert rows["events"]["observed_value"] is None
    assert {row["relation"] for row in rows.values()} == {"WITHIN_MAXIMUM"}
    assert {row["producer"] for row in rows.values()} == {vrc.PRODUCER}
    assert {row["run_digest"] for row in rows.values()} == {vrc.run_digest(request)}
    assert observed["caller_declarations_admitted"] == 0


def test_nondeterministic_registered_route_is_a_counterexample(monkeypatch):
    key = (ROUTE[0], ROUTE[1])
    original = routes._ROUTES[key]
    calls = {"count": 0}

    def drifting(certificate_bytes, *, expected_request, policy):
        calls["count"] += 1
        native = dict(original.replay(certificate_bytes,
                                      expected_request=expected_request, policy=policy))
        native["replay_ordinal"] = calls["count"]
        return native

    monkeypatch.setitem(routes._ROUTES, key, routes._Route(
        original.module, drifting, original.fixed_kind, original.scope))
    request, policy, evidence, child_parts = selected()
    first, second = route_report(*child_parts), route_report(*child_parts)
    assert canonical_bytes(first) != canonical_bytes(second)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_traced_event_maximum_below_the_run_is_a_counterexample():
    request, policy, evidence, child_parts = selected(rows=constraints(events=10))
    assert route_report(*child_parts)["computational_status"] == "PASS"
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert "traced_python_events" in result["evaluation"]["details"]


def test_report_byte_maximum_below_the_observed_report_is_a_counterexample():
    request, policy, evidence, child_parts = selected(rows=constraints(report_bytes=10))
    assert len(canonical_bytes(route_report(*child_parts))) > 10
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_child_fail_makes_the_parent_fail():
    request, policy, evidence, child_parts = selected(partitions=OVERLAP)
    assert json.loads(child_parts[2])["result"]["status"] == "FAIL"
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_rehashed_child_verdict_is_refused_by_the_registered_route():
    def forge(raw: bytes) -> bytes:
        value = json.loads(raw)
        value["result"]["status"] = "FAIL"
        value.pop("digest")
        value["digest"] = digest(value)
        return canonical_bytes(value)

    request, policy, evidence, child_parts = selected(certificate=forge)
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        route_report(*child_parts)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_child_unknown_makes_the_parent_unknown():
    request, policy, evidence, child_parts = selected(retained_child=False)
    assert route_report(*child_parts)["computational_status"] == "UNKNOWN"
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"


def test_event_ceiling_exhaustion_is_unknown_not_fail():
    request, policy, evidence, _ = selected(limits={"max_replay_events": 50})
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "UNKNOWN"
    assert result["run_bound_constraint_observations"] == "NOT_ESTABLISHED"


def test_caller_declarations_alone_leave_the_constraint_unknown():
    resident = {"constraint_id": "resident", "quantity": "resident_memory_bytes",
                "maximum": 2**30}
    declared = ({"observation_id": "o1", "run_digest": "RUN", "producer": vrc.PRODUCER,
                 "quantity": "resident_memory_bytes", "value": 1024},)
    request, policy, evidence, _ = selected(rows=constraints(extra=(resident,)),
                                            declared=declared)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "UNKNOWN"
    assert "CALLER_DECLARATION_ONLY" in result["evaluation"]["details"]
    request, policy, evidence, _ = selected(rows=[resident])
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "UNKNOWN"
    assert "NO_INDEPENDENT_OBSERVATION" in result["evaluation"]["details"]
    request, policy, _, _ = selected()
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


def test_observed_violation_outranks_an_unobservable_constraint():
    resident = {"constraint_id": "resident", "quantity": "resident_memory_bytes",
                "maximum": 2**30}
    request, policy, evidence, _ = selected(
        rows=constraints(report_bytes=10, extra=(resident,)))
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"


def test_one_bit_flip_in_the_certificate_is_refused():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    for position in (1, len(certificate) // 3, len(certificate) // 2, len(certificate) - 2):
        flipped = bytearray(certificate)
        flipped[position] ^= 1
        with pytest.raises(vrc.VerifierRunConstraintsError):
            vrc.recheck_verifier_run_constraints_certificate(
                bytes(flipped), expected_request=request, policy=policy)


def test_wrong_subject_and_substituted_selection_are_refused():
    other = verifier_object((ROUTE[0], "SPACE-4.1", "SPACE"))
    request, policy, evidence, _ = selected(subject=other)
    assert replay(request, policy, evidence)[1]["status"] == "FAIL"
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    substituted = deepcopy(request)
    substituted["constraints"][0]["maximum"] += 1
    with pytest.raises(vrc.VerifierRunConstraintsError):
        vrc.recheck_verifier_run_constraints_certificate(
            certificate, expected_request=substituted, policy=policy)
    renamed = dict(request, subject_id="another-verifier")
    with pytest.raises(vrc.VerifierRunConstraintsError):
        vrc.recheck_verifier_run_constraints_certificate(
            certificate, expected_request=renamed, policy=policy)
    other_policy = dict(policy, trust_roots=["other-root"])
    with pytest.raises(vrc.VerifierRunConstraintsError):
        vrc.recheck_verifier_run_constraints_certificate(
            certificate, expected_request=request, policy=other_policy)


@pytest.mark.parametrize("objective", ["VERIFIER-3.1", "VERIFIER-4.1"])
def test_own_objectives_are_not_admissible_children(objective):
    request, policy, _, _ = selected()
    with pytest.raises(vrc.VerifierRunConstraintsError):
        vrc.verifier_run_constraints_request(
            subject_id=request["subject_id"], object_digest=request["object_digest"],
            collection_digest=request["collection_digest"],
            child_semantic_version=ROUTE[0], child_objective=objective,
            child_represented_kind="VERIFIER",
            child_request_digest=ZERO, child_policy_digest=ZERO,
            child_certificate_digest=ZERO, declarant="caller:test-selector",
            constraints=constraints(), evidence_ref=ZERO, policy=policy)


def test_declarant_cannot_claim_the_checker_producer():
    request, policy, _, _ = selected()
    with pytest.raises(vrc.VerifierRunConstraintsError):
        vrc.verifier_run_constraints_request(
            subject_id=request["subject_id"], object_digest=request["object_digest"],
            collection_digest=request["collection_digest"],
            child_semantic_version=ROUTE[0], child_objective=ROUTE[1],
            child_represented_kind=ROUTE[2],
            child_request_digest=ZERO, child_policy_digest=ZERO,
            child_certificate_digest=ZERO, declarant=vrc.PRODUCER,
            constraints=constraints(), evidence_ref=ZERO, policy=policy)


def test_public_route_dispatch_reaches_pass():
    request, policy, evidence, _ = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=vrc.SEMANTIC_VERSION,
        objective=vrc.COORDINATE, represented_kind="VERIFIER",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["execution_substrate_identity"] == "NOT_ESTABLISHED"
    assert report["native_result"]["isolation"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("relative", [
    "domains/contracts/verifier_run_constraints.py",
    "domains/contracts/current_object_routes.py",
    "standard/CURRENT_VERIFIER_RUN_CONSTRAINTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence, _ = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(vrc.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        vrc.recheck_verifier_run_constraints_certificate(
            certificate, expected_request=request, policy=policy)


def test_a_route_refusal_during_the_traced_replay_is_a_counterexample(monkeypatch):
    request, policy, evidence, _ = selected()
    key = (ROUTE[0], ROUTE[1])
    original = routes._ROUTES[key]

    def rejecting(certificate_bytes, *, expected_request, policy):
        raise ValueError("the selected native checker rejects these bytes")

    monkeypatch.setitem(routes._ROUTES, key, routes._Route(
        original.module, rejecting, original.fixed_kind, original.scope))
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "FAIL"
    assert "refused by its registered route" in result["evaluation"]["details"]


def test_an_unreachable_child_checker_is_unknown_not_fail(monkeypatch):
    request, policy, evidence, _ = selected()

    class Unreachable(OSError):
        pass

    def unreachable(*args, **kwargs):
        raise Unreachable("the registered native checker cannot be reached")

    # The route module of the selector migration defines this exception; the integration route module may not, hence raising=False.
    monkeypatch.setattr(routes, "CurrentObjectRouteUnavailable", Unreachable, raising=False)
    monkeypatch.setattr(routes, "replay_current_object_certificate", unreachable)
    result = replay(request, policy, evidence)[1]
    assert result["status"] == "UNKNOWN"
    # The reason text is the module's own for this branch; the raised error's text is different, so a module that does not
    # reach the branch (the error then ends as a generic mechanism failure with the error's own text) cannot satisfy this.
    assert "selected child checker is unavailable" in result["evaluation"]["details"]
