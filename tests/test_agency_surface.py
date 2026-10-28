"""Executable BOT, ROBOT, and FINBOT agency-surface crosswalks.

Verifier Standard (VSTD); JavaScript Object Notation (JSON).  The fixtures are
retained bytes only: they do not run an agent, actuate hardware, or move money.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import json

import pytest

from verifier.domains.contracts import agency_surface
from verifier.runtime.tier_zero_profile import canonical_bytes
from test_added_kind_behavioral_mechanisms import (
    SOURCE_DIGEST,
    _finbot_certificate,
    _finbot_parts,
    _robot_certificate,
    _robot_parts,
)
from test_current_agent_checks import inputs as agent_inputs
from test_current_bot_checks import inputs as bot_inputs, specimen as bot_specimen


def _current_child(factory, check: str, role: str) -> dict:
    contract, request, policy, evidence = factory(check)
    if request["object_kind"] == "AGENT":
        certificate = contract.build_agent_checks_certificate(request, evidence, policy=policy)
    else:
        certificate = contract.build_bot_checks_certificate(request, evidence, policy=policy)
    return agency_surface.child_record(
        role=role, certificate=certificate, request=request, policy=policy)


def _agent_child(check: str, role: str) -> dict:
    """Select the exact AGENT retained by the BOT fixture, not a lookalike."""
    _, retained = bot_specimen()
    evidence = retained["agent_certificate"]["evidence"]
    return _current_child(
        lambda selected: agent_inputs(
            selected, artifact=evidence["artifact"], retained=evidence["inputs"]),
        check, role)


def _retained_child(kind: str, check: str, role: str) -> dict:
    factory = _robot_certificate if kind == "ROBOT" else _finbot_certificate
    _, certificate, request, policy, _ = factory(check)
    return agency_surface.child_record(
        role=role, certificate=certificate, request=request, policy=policy)


def _children(kind: str, tier: int, domains: list[str]) -> list[dict]:
    rows = [_agent_child("harness", "agent_harness")]
    if kind == "BOT":
        rows.append(_current_child(bot_inputs, "binding", "bot_binding"))
    elif kind == "ROBOT":
        rows.append(_retained_child("ROBOT", "path", "robot_binding"))
    else:
        rows.append(_retained_child("FINBOT", "authority", "finbot_binding"))
    if "REAL_PHYSICAL" in domains and kind != "ROBOT":
        rows.append(_retained_child("ROBOT", "path", "robot_binding"))
    if "REAL_FINANCIAL" in domains and kind != "FINBOT":
        rows.append(_retained_child("FINBOT", "authority", "finbot_binding"))
    if tier >= 2:
        rows.extend([
            _agent_child("trajectory", "agent_trajectory"),
            _agent_child("actions", "agent_actions"),
        ])
        if kind == "BOT":
            rows.extend([
                _current_child(bot_inputs, "alignment", "bot_alignment"),
                _current_child(bot_inputs, "observation", "bot_observation"),
                _current_child(bot_inputs, "actuation", "bot_actuation"),
            ])
        if "REAL_PHYSICAL" in domains:
            rows.append(_retained_child("ROBOT", "observation", "robot_trace"))
        if "REAL_FINANCIAL" in domains:
            rows.append(_retained_child("FINBOT", "exposure", "finbot_trace"))
    if tier >= 3:
        if "REAL_PHYSICAL" in domains:
            rows.append(_retained_child("ROBOT", "intervention", "robot_boundary"))
        if "REAL_FINANCIAL" in domains:
            rows.append(_retained_child("FINBOT", "reconciliation", "finbot_boundary"))
    return rows


def _domains(kind: str) -> list[str]:
    return {"BOT": ["SIMULATED"], "ROBOT": ["REAL_PHYSICAL"],
            "FINBOT": ["REAL_FINANCIAL"]}[kind]


def _links(domains: list[str]) -> list[dict]:
    effect = {"SIMULATED": "sim-transition:1", "REAL_PHYSICAL": "trace",
              "REAL_FINANCIAL": "effect"}
    return [{"domain": domain, "record_id": 1, "action_tool": "step_world",
             "effect_id": effect[domain]} for domain in domains]


def _boundary() -> dict:
    return {name: {"status": "NOT_ESTABLISHED",
                   "reason": "The retained crosswalk names this boundary but has no independent source mechanism that establishes it."}
            for name in ("limits", "intervention", "recovery", "confinement")}


def _case(kind: str, check: str, *, domains: list[str] | None = None) -> tuple[dict, bytes, dict, bytes]:
    route = agency_surface.route_for(kind, check)
    selected_domains = _domains(kind) if domains is None else domains
    evidence = agency_surface.agency_surface_evidence(
        kind=kind, subject_id="bot", source_digest=SOURCE_DIGEST,
        effect_domains=selected_domains,
        agency_join={"agent_id": "agent", "harness_id": "harness",
                     "trace_links": _links(selected_domains) if route.tier >= 2 else []},
        children=_children(kind, route.tier, selected_domains),
        consequence_bundle=(
            _robot_parts()[0] if kind == "ROBOT" else
            _finbot_parts()[0] if kind == "FINBOT" else None
        ),
        operational_boundary=_boundary() if route.tier >= 3 else None,
    )
    policy = agency_surface.agency_surface_policy(kind=kind, trust_roots=["retained-fixture"])
    request = agency_surface.agency_surface_request(
        kind=kind, check=check, subject_id="bot", source_digest=SOURCE_DIGEST,
        evidence_ref=agency_surface.agency_evidence_reference(evidence), policy=policy)
    certificate = agency_surface.build_agency_surface_certificate(
        request, evidence, policy=policy)
    return request, certificate, policy, evidence


@pytest.mark.parametrize("kind", ["BOT", "ROBOT", "FINBOT"])
@pytest.mark.parametrize("check", ["binding", "trace", "operational_boundary"])
def test_agency_surface_replays_cumulatively_without_promoting_external_claims(kind: str, check: str) -> None:
    request, certificate, policy, _ = _case(kind, check)
    result = agency_surface.recheck_agency_surface_certificate(
        certificate, expected_request=request, policy=policy)
    assert result["status"] == "PASS"
    assert result["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert result["authenticity"] == result["adequacy"] == "NOT_ESTABLISHED"
    assert result["successful_recovery"] == "NOT_ESTABLISHED"
    assert result["physical_safety"] == result["legal_authority"] == "NOT_ESTABLISHED"
    assert result["real_world_correspondence"] == "NOT_ESTABLISHED"
    assert result["evaluation"]["details"]["tier4_bot_containment_used"] is False


@pytest.mark.parametrize("kind", ["BOT", "ROBOT", "FINBOT"])
def test_cross_agent_or_harness_substitution_is_refuted(kind: str) -> None:
    request, _, policy, evidence = _case(kind, "binding")
    value = json.loads(evidence)
    value["agency_join"]["agent_id"] = "other-agent"
    forged = canonical_bytes(value)
    request = agency_surface.agency_surface_request(
        kind=kind, check="binding", subject_id="bot", source_digest=SOURCE_DIGEST,
        evidence_ref=agency_surface.agency_evidence_reference(forged), policy=policy)
    result = json.loads(agency_surface.build_agency_surface_certificate(
        request, forged, policy=policy))["result"]
    assert result["status"] == "FAIL"
    assert "different actual agent_id or harness_id" in result["evaluation"]["reason"]


@pytest.mark.parametrize("mutation", ["omit", "coordinate", "certificate"])
def test_child_omission_coordinate_substitution_and_certificate_forgery_fail(mutation: str) -> None:
    request, _, policy, evidence = _case("ROBOT", "trace")
    value = json.loads(evidence)
    if mutation == "omit":
        value["children"].pop()
    elif mutation == "coordinate":
        child = next(row for row in value["children"] if row["role"] == "agent_actions")
        replacement = _agent_child("trajectory", "agent_actions")
        child.update(replacement)
    else:
        child = next(row for row in value["children"] if row["role"] == "agent_actions")
        child["certificate_base64"] = child["certificate_base64"][:-4] + "AAAA"
    forged = canonical_bytes(value)
    request = agency_surface.agency_surface_request(
        kind="ROBOT", check="trace", subject_id="bot", source_digest=SOURCE_DIGEST,
        evidence_ref=agency_surface.agency_evidence_reference(forged), policy=policy)
    result = json.loads(agency_surface.build_agency_surface_certificate(
        request, forged, policy=policy))["result"]
    assert result["status"] == "FAIL"


@pytest.mark.parametrize("field,value", [
    ("record_id", 3), ("action_tool", "other"), ("effect_id", "other-effect")])
def test_decision_action_effect_substitution_is_refuted(field: str, value: object) -> None:
    request, _, policy, evidence = _case("FINBOT", "trace")
    document = json.loads(evidence)
    document["agency_join"]["trace_links"][0][field] = value
    forged = canonical_bytes(document)
    request = agency_surface.agency_surface_request(
        kind="FINBOT", check="trace", subject_id="bot", source_digest=SOURCE_DIGEST,
        evidence_ref=agency_surface.agency_evidence_reference(forged), policy=policy)
    result = json.loads(agency_surface.build_agency_surface_certificate(
        request, forged, policy=policy))["result"]
    assert result["status"] == "FAIL"


def test_valid_but_different_agent_selection_cannot_cross_join() -> None:
    request, _, policy, evidence = _case("ROBOT", "trace")
    document = json.loads(evidence)
    replacement = _current_child(agent_inputs, "actions", "agent_actions")
    index = next(index for index, row in enumerate(document["children"])
                 if row["role"] == "agent_actions")
    document["children"][index] = replacement
    forged = canonical_bytes(document)
    request = agency_surface.agency_surface_request(
        kind="ROBOT", check="trace", subject_id="bot", source_digest=SOURCE_DIGEST,
        evidence_ref=agency_surface.agency_evidence_reference(forged), policy=policy)
    result = json.loads(agency_surface.build_agency_surface_certificate(
        request, forged, policy=policy))["result"]
    assert result["status"] == "FAIL"
    assert "select different retained subjects" in result["evaluation"]["reason"]


@pytest.mark.parametrize("missing", ["limits", "intervention", "recovery", "confinement"])
def test_operational_boundary_omission_is_refuted(missing: str) -> None:
    request, _, policy, evidence = _case("ROBOT", "operational_boundary")
    document = json.loads(evidence)
    del document["operational_boundary"][missing]
    forged = canonical_bytes(document)
    request = agency_surface.agency_surface_request(
        kind="ROBOT", check="operational_boundary", subject_id="bot",
        source_digest=SOURCE_DIGEST,
        evidence_ref=agency_surface.agency_evidence_reference(forged), policy=policy)
    result = json.loads(agency_surface.build_agency_surface_certificate(
        request, forged, policy=policy))["result"]
    assert result["status"] == "FAIL"


def test_bot_real_effects_accumulate_robot_and_finbot_children() -> None:
    domains = ["REAL_FINANCIAL", "REAL_PHYSICAL", "SIMULATED"]
    request, certificate, policy, _ = _case("BOT", "operational_boundary", domains=domains)
    result = agency_surface.recheck_agency_surface_certificate(
        certificate, expected_request=request, policy=policy)
    assert result["status"] == "PASS"
    assert result["evaluation"]["details"]["effect_domains"] == domains
    assert result["evaluation"]["details"]["child_certificates"] == 13


def test_bot_real_effect_cannot_omit_accumulated_role_route() -> None:
    domains = ["REAL_PHYSICAL", "SIMULATED"]
    request, _, policy, evidence = _case("BOT", "trace", domains=domains)
    document = json.loads(evidence)
    document["children"] = [row for row in document["children"] if row["role"] != "robot_trace"]
    forged = canonical_bytes(document)
    request = agency_surface.agency_surface_request(
        kind="BOT", check="trace", subject_id="bot", source_digest=SOURCE_DIGEST,
        evidence_ref=agency_surface.agency_evidence_reference(forged), policy=policy)
    result = json.loads(agency_surface.build_agency_surface_certificate(
        request, forged, policy=policy))["result"]
    assert result["status"] == "FAIL"
    assert "child set differs" in result["evaluation"]["reason"]


def test_package_catalog_preserves_exact_readable_coordinates_and_replay() -> None:
    assert [row["coordinate"] for row in agency_surface.catalog()] == [
        "BOT-1.7", "BOT-2.6", "BOT-3.5", "ROBOT-1.2", "ROBOT-2.2", "ROBOT-3.2",
        "FINBOT-1.2", "FINBOT-2.2", "FINBOT-3.2",
    ]
    request, certificate, policy, _ = _case("ROBOT", "trace")
    route = next(row for row in agency_surface.catalog() if row["coordinate"] == "ROBOT-2.2")
    result = agency_surface.recheck_package_certificate(
        route, certificate, expected_request=request, policy=policy)
    assert result["status"] == "PASS"
    assert route["obligation_id"] == "ROBOT-2.2-agency-surface-trace"


def test_missing_evidence_is_unknown_not_exempt() -> None:
    request, _, policy, _ = _case("BOT", "binding")
    missing_request = agency_surface.agency_surface_request(
        kind="BOT", check="binding", subject_id="bot", source_digest=SOURCE_DIGEST,
        evidence_ref="sha256:" + "0" * 64, policy=policy)
    certificate = agency_surface.build_agency_surface_certificate(
        missing_request, None, policy=policy)
    result = agency_surface.recheck_agency_surface_certificate(
        certificate, expected_request=missing_request, policy=policy)
    assert result["status"] == "UNKNOWN"
    assert result["evaluation"]["reason"] == "selected retained evidence is unavailable"


def test_package_profiles_include_all_nine_agency_routes_without_catalog_drift() -> None:
    from verifier.runtime import package_contract_profiles

    assert package_contract_profiles.required_coordinates("BOT", 3)[-3:] == (
        "BOT-2.6", "BOT-3.1", "BOT-3.5")
    assert package_contract_profiles.required_coordinates("ROBOT", 3)[-3:] == (
        "ROBOT-2.2", "ROBOT-3.1", "ROBOT-3.2")
    assert package_contract_profiles.required_coordinates("FINBOT", 3)[-3:] == (
        "FINBOT-2.2", "FINBOT-3.1", "FINBOT-3.2")
    matrix = package_contract_profiles.contract_coverage_matrix()
    rows = list(matrix["kinds"].values())
    routes = [route for row in rows for route in row["routes"]]
    # The 293-route denominator is the disjoint union of four route types.
    assert Counter(route["route_type"] for route in routes) == {
        "SOURCE_ADAPTER": 114,
        "NATIVE_RECHECKER": 113,
        "PACKAGE_EXECUTION_ADAPTER": 45,
        "ADDED_KIND_BEHAVIORAL": 21,
    }
    coordinates = [route["coordinate"] for route in routes]
    assert len(coordinates) == len(set(coordinates))
    assert len(coordinates) == matrix["route_denominator"] == 293
    agency = {row["coordinate"] for row in agency_surface.catalog()}
    assert len(agency) == 9
    agency_routes = [route for route in routes if route["coordinate"] in agency]
    assert {route["coordinate"] for route in agency_routes} == agency
    assert {route["route_type"] for route in agency_routes} == {"ADDED_KIND_BEHAVIORAL"}
    assert {route["adapter"] for route in agency_routes} == {
        "verifier-retained-agency-surface-1"
    }
    # The 364 defined obligations are the disjoint union of route obligations,
    # profile obligations, and repository-admission obligations.
    route_ids = {route["obligation_id"] for route in routes}
    profile_ids = {
        obligation["obligation_id"]
        for row in rows
        for obligation in row["profile_obligations"]
    }
    admission_ids = {
        row["obligation_id"] for row in matrix["repository_admission_obligations"]
    }
    assert len(route_ids) == 293
    assert len(profile_ids) == 62
    assert len(admission_ids) == 9
    assert not (route_ids & profile_ids)
    assert not (route_ids & admission_ids)
    assert not (profile_ids & admission_ids)
    assert len(route_ids | profile_ids | admission_ids) == 364
    assert matrix["defined_obligation_denominator"] == 364
    assert matrix["findings"] == []
