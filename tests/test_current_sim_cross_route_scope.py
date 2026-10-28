"""Current SIM-2.1 and SIM-3.4 selected from one exact retained SIM record.

Verifier Standard (VSTD) binds canonical JavaScript Object Notation (JSON)
with Secure Hash Algorithm 256-bit (SHA-256). A simulation (SIM) record's
payload ``scope`` is either one legacy scalar member or one composable list
of distinct admitted members in ascending code-point order. Counts are
dimensionless and limits count bytes. Two route certificates over one record
establish two bounded propositions, not a tier, a profile or each other.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import sim_dynamics, sim_external_law

REPLAY = "selected-retained-trajectory-replay"
LAW = "selected-external-law-statement"
COMPOSED = [LAW, REPLAY]
ABSENT = object()
ZERO = "sha256:" + "0" * 64
STATEMENT = "A declared closed-system energy balance."
SOURCE_REF = "urn:example:external-law:v1"


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


class Record:
    """One exact SIM record, its complete collection and its retained replay operands."""

    def __init__(self, scope: Any) -> None:
        self.inputs = {"states": [{"x": 0.0}, {"x": 1.0}], "entropy": [1.0], "times": [0.0, 1.0]}
        self.artifact = {
            "transition": {"x": {"op": "add", "args": [{"var": "x"}, {"var": "entropy"}]}},
            "initial_state": {"x": 0.0},
            "trajectory_digest": digest(self.inputs["states"]),
            "entropy_digest": digest(self.inputs["entropy"]),
            "times_digest": digest(self.inputs["times"]),
        }
        self.law = NamespaceObject.create("law", "OBJECT", {
            "schema_version": sim_external_law.LAW_VERSION, "statement": STATEMENT,
            "applicability": "A declared closed system with boundary fluxes accounted for.",
            "source_ref": SOURCE_REF,
        })
        payload: dict[str, Any] = {
            "artifact_digest": digest(self.artifact), "inputs_digest": digest(self.inputs),
            "modelled_law_object_id": "law",
        }
        if scope is not ABSENT:
            payload["scope"] = scope
        self.subject = NamespaceObject.create("sim", "SIM", payload, {
            "data": ["data"], "verifier": ["checker"], "objects": ["law"], "env": ["env"]})
        self.objects = [
            NamespaceObject.create("data", "DATA", {}),
            NamespaceObject.create("checker", "VERIFIER", {}),
            NamespaceObject.create("env", "ENV", {}),
            self.law, self.subject,
        ]
        self.collection_digest = composition_digest(self.objects)

    def rows(self) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self.objects]


def dynamics_selection(record: Record, **overrides: Any) -> tuple[dict, dict, bytes]:
    evidence = {"schema_version": sim_dynamics.EVIDENCE_VERSION, "objects": record.rows(),
                "artifact": record.artifact, "inputs": record.inputs}
    policy = sim_dynamics.sim_dynamics_policy(trust_roots=["cross-route-fixture"])
    request = sim_dynamics.sim_dynamics_request(
        subject_id="sim", object_digest=record.subject.digest,
        collection_digest=record.collection_digest, artifact_digest=digest(record.artifact),
        inputs_digest=digest(record.inputs), expected_counts={"states": 2, "transitions": 1},
        evidence_ref=digest(evidence), policy=policy)
    request.update(overrides)
    return request, policy, canonical_bytes(evidence)


def external_law_selection(record: Record, **overrides: Any) -> tuple[dict, dict, bytes]:
    evidence = {"schema_version": sim_external_law.EVIDENCE_VERSION, "objects": record.rows()}
    policy = sim_external_law.sim_external_law_policy(trust_roots=["cross-route-fixture"])
    request = sim_external_law.sim_external_law_request(
        subject_id="sim", object_digest=record.subject.digest,
        collection_digest=record.collection_digest, law_object_id="law",
        law_object_digest=record.law.digest, law_statement_digest=digest(STATEMENT),
        source_ref=SOURCE_REF, evidence_ref=digest(evidence), policy=policy)
    request.update(overrides)
    return request, policy, canonical_bytes(evidence)


ROUTES = {
    "SIM-2.1": SimpleNamespace(
        module=sim_dynamics, member=REPLAY, other="SIM-3.4", select=dynamics_selection,
        policy=sim_dynamics.sim_dynamics_policy,
        build=sim_dynamics.build_sim_dynamics_certificate,
        recheck=sim_dynamics.recheck_sim_dynamics_certificate,
        error=sim_dynamics.SimDynamicsError, tier="sim_tier_2_conformance"),
    "SIM-3.4": SimpleNamespace(
        module=sim_external_law, member=LAW, other="SIM-2.1", select=external_law_selection,
        policy=sim_external_law.sim_external_law_policy,
        build=sim_external_law.build_sim_external_law_certificate,
        recheck=sim_external_law.recheck_sim_external_law_certificate,
        error=sim_external_law.SimExternalLawError, tier="sim_tier_3_conformance"),
}
ROUTE_IDS = sorted(ROUTES)


def certify(route: str, record: Record, **overrides: Any):
    lane = ROUTES[route]
    request, policy, evidence = lane.select(record, **overrides)
    certificate = lane.build(request, evidence, policy=policy)
    result = lane.recheck(certificate, expected_request=request, policy=policy)
    assert result[lane.tier] == "NOT_ESTABLISHED"
    return request, policy, evidence, certificate, result


def status(route: str, record: Record, **overrides: Any) -> str:
    return certify(route, record, **overrides)[4]["status"]


def details(route: str, record: Record) -> str:
    return certify(route, record)[4]["evaluation"]["details"]


def test_one_exact_record_passes_both_routes_with_separate_certificates() -> None:
    record = Record(COMPOSED)
    outcomes = {route: certify(route, record) for route in ROUTE_IDS}
    requests = [outcomes[route][0] for route in ROUTE_IDS]
    assert {request["object_digest"] for request in requests} == {record.subject.digest}
    assert {request["collection_digest"] for request in requests} == {record.collection_digest}
    assert [outcomes[route][4]["status"] for route in ROUTE_IDS] == ["PASS", "PASS"]
    certificates = [outcomes[route][3] for route in ROUTE_IDS]
    assert certificates[0] != certificates[1]
    for route in ROUTE_IDS:
        lane = ROUTES[route]
        request, policy, _, certificate, _ = outcomes[route]
        assert json.loads(certificate)["schema_version"] == lane.module.CERTIFICATE_VERSION
        report = routes.replay_current_object_certificate(
            certificate, semantic_version=lane.module.SEMANTIC_VERSION,
            objective=lane.module.COORDINATE, represented_kind="SIM",
            expected_request=request, policy=policy)
        assert report["computational_status"] == "PASS"
        assert report["native_result"]["scope"] == lane.module.SCOPE


def test_each_certificate_is_rechecked_only_by_its_own_route() -> None:
    record = Record(COMPOSED)
    outcomes = {route: certify(route, record) for route in ROUTE_IDS}
    for route in ROUTE_IDS:
        lane = ROUTES[route]
        request, policy = outcomes[route][0], outcomes[route][1]
        foreign_certificate = outcomes[lane.other][3]
        with pytest.raises(lane.error):
            lane.recheck(foreign_certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("failing", ROUTE_IDS)
def test_pass_in_one_route_does_not_imply_the_other(failing: str) -> None:
    record = Record(COMPOSED)
    contradiction = ({"expected_counts": {"states": 3, "transitions": 2}} if failing == "SIM-2.1"
                     else {"law_statement_digest": digest("A different declared law.")})
    assert status(failing, record, **contradiction) == "FAIL"
    assert status(ROUTES[failing].other, record) == "PASS"


@pytest.mark.parametrize("scope,passing", [(REPLAY, "SIM-2.1"), (LAW, "SIM-3.4")],
                         ids=["replay-scalar", "law-scalar"])
def test_legacy_scalar_scope_still_selects_exactly_one_route(scope: str, passing: str) -> None:
    record = Record(scope)
    assert status(passing, record) == "PASS"
    assert status(ROUTES[passing].other, record) == "FAIL"


@pytest.mark.parametrize("route", ROUTE_IDS)
def test_unknown_scalar_scope_still_fails(route: str) -> None:
    assert status(route, Record("unselected-scope")) == "FAIL"


def test_absent_scope_keeps_each_route_outcome() -> None:
    record = Record(ABSENT)
    assert status("SIM-2.1", record) == "FAIL"
    assert status("SIM-3.4", record) == "UNKNOWN"


def test_admitted_scope_members_agree_across_routes() -> None:
    members = sim_dynamics.SCOPE_MEMBERS
    assert members == sim_external_law.SCOPE_MEMBERS == (LAW, REPLAY)
    assert list(members) == sorted(set(members))
    assert sim_dynamics.PAYLOAD_SCOPE == REPLAY
    assert sim_external_law.PAYLOAD_SCOPE == LAW


def test_both_certificates_rebuild_byte_identically() -> None:
    record = Record(COMPOSED)
    for route in ROUTE_IDS:
        lane = ROUTES[route]
        request, policy, evidence = lane.select(record)
        first = lane.build(request, evidence, policy=policy)
        second = lane.build(deepcopy(request), bytes(evidence), policy=deepcopy(policy))
        assert first == second


# Eight-category negatives. Categories 1-3: exact subject, object and collection binding.

@pytest.mark.parametrize("field,value", [
    ("subject_id", "other-sim"), ("object_digest", ZERO), ("collection_digest", ZERO),
], ids=["wrong-subject", "wrong-object", "wrong-collection"])
@pytest.mark.parametrize("route", ROUTE_IDS)
def test_wrong_binding_fails_and_cannot_rebind_a_pass(route: str, field: str, value: str) -> None:
    record = Record(COMPOSED)
    assert status(route, record, **{field: value}) == "FAIL"
    lane = ROUTES[route]
    request, policy, _, certificate, result = certify(route, record)
    assert result["status"] == "PASS"
    rebound = deepcopy(request)
    rebound[field] = value
    with pytest.raises(lane.error):
        lane.recheck(certificate, expected_request=rebound, policy=policy)


def test_wrong_subject_naming_the_law_record_is_refused_before_evaluation() -> None:
    request, policy, evidence = external_law_selection(Record(COMPOSED), subject_id="law")
    with pytest.raises(sim_external_law.SimExternalLawError):
        sim_external_law.build_sim_external_law_certificate(request, evidence, policy=policy)


# Category 4: missing member.

@pytest.mark.parametrize("route", ROUTE_IDS)
def test_missing_member_fails_only_the_route_it_omits(route: str) -> None:
    lane = ROUTES[route]
    record = Record([ROUTES[lane.other].member])
    assert status(route, record) == "FAIL"
    assert status(lane.other, record) == "PASS"


# Category 5: unknown member.

@pytest.mark.parametrize("scope", [[LAW, REPLAY, "unselected-scope"], ["unselected-scope"]],
                         ids=["composed-plus-unknown", "unknown-only"])
@pytest.mark.parametrize("route", ROUTE_IDS)
def test_unknown_member_is_refuted_not_canonicalized(route: str, scope: list) -> None:
    record = Record(scope)
    assert status(route, record) == "FAIL"
    assert "unknown member" in details(route, record)


# Category 6: malformed or duplicate representation.

@pytest.mark.parametrize("scope,label", [
    ([LAW, LAW, REPLAY], "repeats"), ([LAW, REPLAY, REPLAY], "repeats"),
    ([REPLAY, LAW], "order"), ([], "nonempty"), ([LAW, 1], "string"),
    ([[LAW], [REPLAY]], "string"),
], ids=["repeat-law", "repeat-replay", "descending-order", "empty-list", "integer-member",
        "nested-lists"])
@pytest.mark.parametrize("route", ROUTE_IDS)
def test_malformed_list_is_refuted_not_canonicalized(route: str, scope: list, label: str) -> None:
    record = Record(scope)
    assert status(route, record) == "FAIL"
    assert label in details(route, record)


@pytest.mark.parametrize("scope", [{LAW: True, REPLAY: True}, True, 1],
                         ids=["object-form", "boolean", "integer"])
@pytest.mark.parametrize("route", ROUTE_IDS)
def test_non_list_non_string_scope_fails(route: str, scope: Any) -> None:
    assert status(route, Record(scope)) == "FAIL"


# Category 7: tampered certificate.

@pytest.mark.parametrize("tamper", ["result-status", "request-object-digest", "evidence-payload"])
@pytest.mark.parametrize("route", ROUTE_IDS)
def test_tampered_certificate_is_refused(route: str, tamper: str) -> None:
    lane = ROUTES[route]
    request, policy, _, certificate, result = certify(route, Record(COMPOSED))
    assert result["status"] == "PASS"
    forged = json.loads(certificate)
    if tamper == "result-status":
        forged["result"]["status"] = "FAIL"
    elif tamper == "request-object-digest":
        forged["request"]["object_digest"] = ZERO
    else:
        forged["evidence_payloads"] = {}
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(lane.error):
        lane.recheck(canonical_bytes(forged), expected_request=request, policy=policy)


# Category 8: foreign policy or digest.

@pytest.mark.parametrize("foreign", ["other-trust-root", "other-route-policy",
                                     "forged-mechanism-digest"])
@pytest.mark.parametrize("route", ROUTE_IDS)
def test_foreign_policy_or_digest_is_refused(route: str, foreign: str) -> None:
    lane = ROUTES[route]
    request, policy, evidence, certificate, _ = certify(route, Record(COMPOSED))
    if foreign == "other-trust-root":
        substitute = lane.policy(trust_roots=["foreign-root"])
    elif foreign == "other-route-policy":
        substitute = ROUTES[lane.other].policy(trust_roots=["cross-route-fixture"])
    else:
        substitute = {**policy, "mechanism_digest": ZERO}
    with pytest.raises(lane.error):
        lane.build(request, evidence, policy=substitute)
    with pytest.raises(lane.error):
        lane.recheck(certificate, expected_request=request, policy=substitute)
