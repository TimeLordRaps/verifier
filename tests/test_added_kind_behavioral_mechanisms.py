"""Executable retained checks for MARKET, ROBOT, and FINBOT refinements.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). These fixtures never trade, move money, or actuate
hardware. They exercise deterministic retained evidence and its claim limits.
"""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from verifier.domains.contracts import finbot_checks, market_checks, robot_checks
from verifier.runtime import added_kind_behavioral_routes as behavioral
from verifier.runtime.tier_zero_profile import (
    applicability_digest,
    canonical_bytes,
    validate_applicability_binding,
    value_digest,
)


SOURCE_DIGEST = "sha256:" + "1" * 64
SOURCE_EVIDENCE = [{"path": "subject.py", "sha256": "sha256:" + "a" * 64}]


def _behavioral_catalog() -> list[dict]:
    """Select the original nine routes; agency crosswalks have their own suite."""
    return [row for row in behavioral.catalog() if row["adapter"] == behavioral.ADAPTER]


def test_modules_expose_three_cumulative_routes_each() -> None:
    assert tuple(market_checks.CHECKS.values()) == (
        "MARKET-1.1-order-access-lifecycle",
        "MARKET-2.1-matching-pricing-allocation",
        "MARKET-3.1-settlement-failure-disruption",
    )
    assert tuple(robot_checks.CHECKS.values()) == (
        "ROBOT-1.1-agent-harness-controller-actuator-path",
        "ROBOT-2.1-physical-reach-and-observation",
        "ROBOT-3.1-hazards-intervention-and-safe-state-or-continuity",
    )
    assert tuple(finbot_checks.CHECKS.values()) == (
        "FINBOT-1.1-agent-harness-and-financial-authority",
        "FINBOT-2.1-real-financial-endpoint-and-exposure",
        "FINBOT-3.1-decision-effect-retry-intervention-and-reconciliation",
    )


def _market_parts() -> tuple[dict, dict, dict]:
    orders = [
        {"order_id": "buy", "participant_id": "buyer", "side": "BUY",
         "quantity_units": 5, "limit_price_units": 110, "priority_sequence": 1,
         "lifecycle": ["SUBMITTED", "ACCEPTED", "FILLED"]},
        {"order_id": "sell", "participant_id": "seller", "side": "SELL",
         "quantity_units": 5, "limit_price_units": 100, "priority_sequence": 2,
         "lifecycle": ["SUBMITTED", "ACCEPTED", "FILLED"]},
    ]
    matches = [{"match_id": "match", "buy_order_id": "buy", "sell_order_id": "sell",
        "price_units": 105, "quantity_units": 5, "allocation_sequence": 1}]
    order_access = {"trace_complete": True,
        "participants": [{"participant_id": "buyer", "access": "ALLOWED"},
                         {"participant_id": "seller", "access": "ALLOWED"}],
        "orders": orders}
    matching = {"trace_complete": True, "matches": matches,
        "replay_digest": value_digest({"orders": orders, "matches": matches}),
        "manipulation_rules": [_manipulation_rule()]}
    settlement = {"trace_complete": True, "settlements": [{"settlement_id": "settlement",
        "match_id": "match", "quantity_units": 5, "cash_units": 525, "status": "FINAL"}],
        "disruptions": [], "participant_failures": []}
    return order_access, matching, settlement


def _manipulation_rule(rule_id: str = "rule-wash", result: str = "NO_VIOLATION_RETAINED") -> dict:
    return {"rule_id": rule_id, "evidence_digest": "sha256:" + "e" * 64, "result": result}


def _market_certificate(check: str, *, order_access: dict | None = None,
                        matching: dict | None = None, settlement: dict | None = None,
                        evidence_kind: str = "MARKET", request_source: str = SOURCE_DIGEST):
    default_order, default_matching, default_settlement = _market_parts()
    evidence = market_checks.market_checks_evidence(subject_id="market", source_digest=SOURCE_DIGEST,
        order_access=default_order if order_access is None else order_access,
        matching_allocation=default_matching if matching is None else matching,
        settlement_disruption=default_settlement if settlement is None else settlement)
    if evidence_kind != "MARKET":
        value = json.loads(evidence)
        value["object_kind"] = evidence_kind
        evidence = canonical_bytes(value)
    policy = market_checks.market_checks_policy(trust_roots=["retained-fixture"])
    request = market_checks.market_checks_request(check=check, subject_id="market",
        source_digest=request_source, evidence_ref=market_checks.market_evidence_reference(evidence),
        policy=policy)
    certificate = market_checks.build_market_checks_certificate(request, evidence, policy=policy)
    return market_checks.recheck_market_checks_certificate(certificate,
        expected_request=request, policy=policy), certificate, request, policy, evidence


def _consequence_bundle() -> dict:
    kinds = {"bot": "BOT", "agent": "AGENT", "harness": "HARNESS",
        "controller": "OBJECT", "actuator": "OBJECT", "ledger": "OBJECT"}
    specializations = {"controller": ["CONTROLLER"], "actuator": ["ACTUATOR"],
                       "ledger": ["LEDGER"]}
    operands = {"bot": {"agent": ["agent"]}, "agent": {"harness": ["harness"]}}
    rows = [{"object_id": identifier, "kind": kind,
        "specializations": specializations.get(identifier, []), "classification": {},
        "surfaces": ["surface:" + identifier], "operands": operands.get(identifier, {})}
        for identifier, kind in kinds.items()]
    graph = {"schema_version": "verifier-consequence-graph-1", "edges": [], "effects": []}
    for source, relation, target in [("agent", "controls", "controller"),
            ("controller", "actuates", "actuator"), ("agent", "decides", "ledger")]:
        graph["edges"].append({"source": source, "relation": relation, "target": target,
            "reason": "The inert retained fixture declares this exact consequence path.",
            "evidence": SOURCE_EVIDENCE})
    for target, domain in [("actuator", "REAL_PHYSICAL"), ("ledger", "REAL_FINANCIAL")]:
        graph["effects"].append({"object_id": target, "domain": domain,
            "reason": "The inert retained fixture declares this endpoint; it proves no execution.",
            "evidence": SOURCE_EVIDENCE})
    observed = {"surfaces": [{"surface_id": "surface:" + identifier, "path": "subject.py",
        "source_kinds": [], "hints": [], "unresolved_marker": False} for identifier in kinds],
        "census": {"files": SOURCE_EVIDENCE}}
    return {"rows": rows, "observed": observed, "graph": graph}


def _crossing(crossing_id: str = "crossing", trace_id: str = "trace") -> dict:
    return {"crossing_id": crossing_id, "trace_id": trace_id, "actuator_id": "actuator",
            "from_domain": "SOFTWARE_COMMAND", "to_domain": "REAL_PHYSICAL"}


def _confinement(claim_type: str = "SOFTWARE_ENVELOPE", authenticity: str = "NOT_ESTABLISHED") -> dict:
    return {"confinement_id": "confinement", "actuator_id": "actuator", "claim_type": claim_type,
            "authenticity": authenticity,
            "reason": "The inert retained fixture declares this confinement type only."}


def _robot_parts() -> tuple[dict, dict, dict, dict]:
    bundle = _consequence_bundle()
    path = {"trace_complete": True, "agent_id": "agent", "harness_id": "harness",
        "controller_ids": ["controller"], "actuator_ids": ["actuator"]}
    observations = {"trace_complete": True, "traces": [{"trace_id": "trace",
        "agent_id": "agent", "controller_id": "controller", "actuator_id": "actuator",
        "command_sequence": 1, "observation_sequence": 2,
        "retained_effect_digest": "sha256:" + "b" * 64}],
        "crossings": [_crossing()], "confinements": [_confinement()]}
    hazards = {"trace_complete": True, "hazards": [{"hazard_id": "hazard",
        "actuator_id": "actuator", "operating_limit_units": 10,
        "intervention_id": "intervention"}], "interventions": [{
            "intervention_id": "intervention", "hazard_id": "hazard",
            "trigger_trace_id": "trace", "mode": "CONTINUITY",
            "reason": "Immediate shutdown would violate the declared continuity boundary."}]}
    return bundle, path, observations, hazards


def _robot_certificate(check: str, *, bundle: dict | None = None,
                       path: dict | None = None, observations: dict | None = None,
                       hazards: dict | None = None):
    default_bundle, default_path, default_observations, default_hazards = _robot_parts()
    evidence = robot_checks.robot_checks_evidence(subject_id="bot", source_digest=SOURCE_DIGEST,
        consequence_bundle=default_bundle if bundle is None else bundle,
        path=default_path if path is None else path,
        observations=default_observations if observations is None else observations,
        hazards=default_hazards if hazards is None else hazards)
    policy = robot_checks.robot_checks_policy(trust_roots=["retained-fixture"])
    request = robot_checks.robot_checks_request(check=check, subject_id="bot",
        source_digest=SOURCE_DIGEST, evidence_ref=robot_checks.robot_evidence_reference(evidence),
        policy=policy)
    certificate = robot_checks.build_robot_checks_certificate(request, evidence, policy=policy)
    return robot_checks.recheck_robot_checks_certificate(certificate,
        expected_request=request, policy=policy), certificate, request, policy, evidence


def _scope(**overrides: object) -> dict[str, object]:
    scope: dict[str, object] = {"agent_id": "agent", "harness_id": "harness",
                                "financial_endpoint_id": "ledger"}
    scope.update(overrides)
    return scope


def _finbot_parts() -> tuple[dict, dict, dict, dict]:
    bundle = _consequence_bundle()
    authority = {"trace_complete": True, "agent_id": "agent", "harness_id": "harness",
        "decision_scope": _scope(), "financial_authority_boundary": "declaration-only"}
    exposures = {"trace_complete": True, "asset_registry": ["asset"], "party_registry": ["party"],
        "exposures": [{"exposure_id": "exposure",
        "endpoint_id": "ledger", "asset_id": "asset", "party_id": "party",
        "amount_units": 7, "limit_units": 10}]}
    reconciliation = {"trace_complete": True, "decisions": [{"decision_id": "decision",
        "exposure_id": "exposure", "effect_id": "effect", "idempotency_key": "key",
        "attempt": 1, "outcome": "APPLIED", "intervention_id": "intervention",
        "reconciliation_id": "reconciliation"}], "interventions": [{
            "intervention_id": "intervention", "decision_id": "decision", "action": "review",
            "reason": "The retained decision requires an explicit intervention record."}],
        "reconciliations": [{"reconciliation_id": "reconciliation", "effect_id": "effect",
            "status": "RECONCILED", "evidence_digest": "sha256:" + "c" * 64}]}
    return bundle, authority, exposures, reconciliation


def _finbot_certificate(check: str, *, bundle: dict | None = None,
                        authority: dict | None = None, exposures: dict | None = None,
                        reconciliation: dict | None = None):
    default_bundle, default_authority, default_exposures, default_reconciliation = _finbot_parts()
    evidence = finbot_checks.finbot_checks_evidence(subject_id="bot", source_digest=SOURCE_DIGEST,
        consequence_bundle=default_bundle if bundle is None else bundle,
        authority=default_authority if authority is None else authority,
        exposures=default_exposures if exposures is None else exposures,
        reconciliation=default_reconciliation if reconciliation is None else reconciliation)
    policy = finbot_checks.finbot_checks_policy(trust_roots=["retained-fixture"])
    request = finbot_checks.finbot_checks_request(check=check, subject_id="bot",
        source_digest=SOURCE_DIGEST, evidence_ref=finbot_checks.finbot_evidence_reference(evidence),
        policy=policy)
    certificate = finbot_checks.build_finbot_checks_certificate(request, evidence, policy=policy)
    return finbot_checks.recheck_finbot_checks_certificate(certificate,
        expected_request=request, policy=policy), certificate, request, policy, evidence


@pytest.mark.parametrize("check", list(market_checks.CHECKS))
def test_market_routes_pass_cumulatively_and_keep_external_claims_unestablished(check: str) -> None:
    result, *_ = _market_certificate(check)
    assert result["status"] == "PASS"
    assert result["venue_authority"] == "NOT_ESTABLISHED"
    assert result["fairness"] == "NOT_ESTABLISHED"
    assert result["manipulation_absence"] == "NOT_ESTABLISHED"
    assert result["real_settlement"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("check", list(robot_checks.CHECKS))
def test_robot_routes_pass_cumulatively_through_installed_consequence_engine(check: str) -> None:
    result, *_ = _robot_certificate(check)
    assert result["status"] == "PASS"
    assert result["physical_actuation"] == "NOT_ESTABLISHED"
    assert result["runtime_correspondence"] == "NOT_ESTABLISHED"
    assert result["external_confinement"] == "NOT_ESTABLISHED"
    assert result["safety"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("check", list(finbot_checks.CHECKS))
def test_finbot_routes_pass_cumulatively_without_real_money_claims(check: str) -> None:
    result, *_ = _finbot_certificate(check)
    assert result["status"] == "PASS"
    assert result["legal_authority"] == "NOT_ESTABLISHED"
    assert result["real_balance"] == "NOT_ESTABLISHED"
    assert result["real_money_effect"] == "NOT_ESTABLISHED"
    assert result["authorized_settlement"] == "NOT_ESTABLISHED"


def test_every_route_has_a_reason_obligation_and_explicit_exclusions() -> None:
    assert len(behavioral.routes()) == 9
    for route in behavioral.routes():
        record = behavioral.registration(route.kind, route.check)
        assert record["reason"] and record["obligation_id"].startswith(route.kind + "-0.")
        assert record["prerequisites"] and record["exclusions"]


def test_absent_evidence_is_unknown_and_rechecks_exactly() -> None:
    policy = market_checks.market_checks_policy(trust_roots=["retained-fixture"])
    request = market_checks.market_checks_request(check="settlement", subject_id="market",
        source_digest=SOURCE_DIGEST, evidence_ref="sha256:" + "0" * 64, policy=policy)
    certificate = market_checks.build_market_checks_certificate(request, None, policy=policy)
    result = market_checks.recheck_market_checks_certificate(certificate,
        expected_request=request, policy=policy)
    assert result["status"] == "UNKNOWN"
    assert result["evaluation"]["reason"] == "selected retained evidence is unavailable"


def test_counterfeit_evidence_reference_is_rejected_before_replay() -> None:
    _, _, request, policy, evidence = _market_certificate("lifecycle")
    with pytest.raises(market_checks.MarketChecksError, match="selected byte reference"):
        market_checks.build_market_checks_certificate(request, evidence + b" ", policy=policy)


def test_wrong_kind_and_stale_source_are_fail_not_pass() -> None:
    wrong_kind, *_ = _market_certificate("lifecycle", evidence_kind="OBJECT")
    stale, *_ = _market_certificate("lifecycle", request_source="sha256:" + "2" * 64)
    assert wrong_kind["status"] == "FAIL"
    assert "object kind differs" in wrong_kind["evaluation"]["reason"]
    assert stale["status"] == "FAIL"
    assert "stale or substituted" in stale["evaluation"]["reason"]


def test_certificate_tampering_is_rejected() -> None:
    _, certificate, request, policy, _ = _market_certificate("lifecycle")
    value = json.loads(certificate)
    value["result"]["status"] = "UNKNOWN"
    tampered = canonical_bytes(value)
    with pytest.raises(market_checks.MarketChecksError, match="digest differs"):
        market_checks.recheck_market_checks_certificate(tampered,
            expected_request=request, policy=policy)


@pytest.mark.parametrize("mutation", ["float_price", "overallocate", "duplicate_order", "bad_lifecycle"])
def test_market_matching_refutes_integer_and_conservation_attacks(mutation: str) -> None:
    order_access, matching, settlement = _market_parts()
    if mutation == "float_price":
        matching["matches"][0]["price_units"] = 105.0
    elif mutation == "overallocate":
        matching["matches"][0]["quantity_units"] = 6
    elif mutation == "duplicate_order":
        order_access["orders"].append(deepcopy(order_access["orders"][0]))
    else:
        order_access["orders"][0]["lifecycle"] = ["SUBMITTED", "FILLED"]
    matching["replay_digest"] = value_digest({"orders": order_access["orders"],
        "matches": matching["matches"]})
    result, *_ = _market_certificate("allocation", order_access=order_access,
        matching=matching, settlement=settlement)
    assert result["status"] == "FAIL"


def test_market_settlement_duplicate_finality_and_unhandled_failure_do_not_pass() -> None:
    order_access, matching, settlement = _market_parts()
    duplicate = deepcopy(settlement["settlements"][0])
    duplicate["settlement_id"] = "other"
    settlement["settlements"].append(duplicate)
    result, *_ = _market_certificate("settlement", order_access=order_access,
        matching=matching, settlement=settlement)
    assert result["status"] == "FAIL"
    settlement = _market_parts()[2]
    settlement["settlements"][0].update(status="UNCERTAIN", quantity_units=0, cash_units=0)
    result, *_ = _market_certificate("settlement", settlement=settlement)
    assert result["status"] == "UNKNOWN"
    assert "lacks a disruption response" in result["evaluation"]["reason"]


def test_robot_bypass_remains_unresolved_and_simulated_effect_cannot_replace_physical() -> None:
    bundle, path, observations, hazards = _robot_parts()
    edge = deepcopy(bundle["graph"]["edges"][0])
    edge.update(source="bot", relation="influences", target="actuator")
    bundle["graph"]["edges"].append(edge)
    result, *_ = _robot_certificate("path", bundle=bundle, path=path,
        observations=observations, hazards=hazards)
    assert result["status"] == "UNKNOWN"
    bundle, path, observations, hazards = _robot_parts()
    bundle["graph"]["effects"][0]["domain"] = "SIMULATED"
    result, *_ = _robot_certificate("path", bundle=bundle, path=path,
        observations=observations, hazards=hazards)
    assert result["status"] != "PASS"


def test_robot_requires_every_actuator_observation_and_explicit_intervention_mode() -> None:
    bundle, path, observations, hazards = _robot_parts()
    observations["traces"] = []
    result, *_ = _robot_certificate("observation", bundle=bundle, path=path,
        observations=observations, hazards=hazards)
    assert result["status"] == "UNKNOWN"
    bundle, path, observations, hazards = _robot_parts()
    hazards["interventions"][0]["mode"] = "SHUTDOWN"
    result, *_ = _robot_certificate("intervention", bundle=bundle, path=path,
        observations=observations, hazards=hazards)
    assert result["status"] == "FAIL"


def test_finbot_refutes_excess_exposure_and_duplicate_applied_retry() -> None:
    bundle, authority, exposures, reconciliation = _finbot_parts()
    exposures["exposures"][0]["amount_units"] = 11
    result, *_ = _finbot_certificate("exposure", bundle=bundle, authority=authority,
        exposures=exposures, reconciliation=reconciliation)
    assert result["status"] == "FAIL"
    bundle, authority, exposures, reconciliation = _finbot_parts()
    retry = deepcopy(reconciliation["decisions"][0])
    retry.update(decision_id="retry", attempt=2, intervention_id="retry-intervention",
                 reconciliation_id="retry-reconciliation")
    reconciliation["decisions"].append(retry)
    reconciliation["interventions"].append({"intervention_id": "retry-intervention",
        "decision_id": "retry", "action": "review", "reason": "Retained retry review."})
    reconciliation["reconciliations"].append({"reconciliation_id": "retry-reconciliation",
        "effect_id": "effect", "status": "RECONCILED", "evidence_digest": "sha256:" + "d" * 64})
    result, *_ = _finbot_certificate("reconciliation", bundle=bundle, authority=authority,
        exposures=exposures, reconciliation=reconciliation)
    assert result["status"] == "FAIL"
    assert "multiple applied" in result["evaluation"]["reason"]


def test_finbot_financial_endpoint_must_stay_typed_and_real() -> None:
    bundle, authority, exposures, reconciliation = _finbot_parts()
    next(row for row in bundle["rows"] if row["object_id"] == "ledger")["specializations"] = []
    result, *_ = _finbot_certificate("authority", bundle=bundle, authority=authority,
        exposures=exposures, reconciliation=reconciliation)
    assert result["status"] == "UNKNOWN"
    bundle, authority, exposures, reconciliation = _finbot_parts()
    bundle["graph"]["effects"][1]["domain"] = "SIMULATED"
    result, *_ = _finbot_certificate("authority", bundle=bundle, authority=authority,
        exposures=exposures, reconciliation=reconciliation)
    assert result["status"] != "PASS"


def test_package_catalog_has_exact_short_coordinates_and_full_obligation_ids() -> None:
    rows = _behavioral_catalog()
    assert len(rows) == 9
    assert [row["coordinate"] for row in rows] == [
        "MARKET-1.1", "MARKET-2.1", "MARKET-3.1",
        "ROBOT-1.1", "ROBOT-2.1", "ROBOT-3.1",
        "FINBOT-1.1", "FINBOT-2.1", "FINBOT-3.1",
    ]
    assert [row["obligation_id"] for row in rows] == [route.coordinate
        for route in behavioral.routes()]
    assert len({row["obligation_id"] for row in rows}) == len(rows)
    assert all(behavioral.is_route(row) for row in rows)


def test_package_catalog_encodes_cumulative_tier_dependencies() -> None:
    by_kind = {kind: [row for row in _behavioral_catalog() if row["object_kind"] == kind]
               for kind in ("MARKET", "ROBOT", "FINBOT")}
    for kind, rows in by_kind.items():
        assert [row["tier"] for row in rows] == [1, 2, 3]
        assert [row["prerequisite_coordinates"] for row in rows] == [
            [], [kind + "-1.1"], [kind + "-1.1", kind + "-2.1"]]


def test_package_catalog_makes_applicability_reasons_and_boundaries_explicit() -> None:
    required_boundaries = {
        "MARKET": {"venue authority", "fairness", "manipulation absence", "real settlement",
                   "runtime correspondence", "whole MARKET conformance"},
        "ROBOT": {"runtime correspondence", "external confinement", "physical actuation",
                  "observation authenticity", "causal attribution", "safety",
                  "whole ROBOT conformance"},
        "FINBOT": {"runtime correspondence", "external confinement", "legal authority",
                   "asset backing", "real balance", "real-money effect",
                   "authorized settlement", "recovery success", "whole FINBOT conformance"},
    }
    for row in _behavioral_catalog():
        assert row["reason"].strip()
        assert row["predicate"].strip() == row["exact_claim"].strip()
        assert row["applicability"]["mode"] == "CONDITIONAL"
        assert row["applicability"]["when_condition_met"] == "NECESSARY"
        assert row["applicability"]["unknown_condition"] == "NOT_EXEMPT"
        assert row["applicability"]["reason"].strip()
        assert row["applicability_digest"] == applicability_digest(
            row["applicability"]
        )
        assert validate_applicability_binding(row) == row["applicability"]
        assert row["runtime_dependencies"] == []
        assert row["adapter"] == behavioral.ADAPTER
        assert row["not_established"]
        assert all(boundary["claim"].strip() and boundary["status"] == "NOT_ESTABLISHED"
                   for boundary in row["not_established"])
        assert required_boundaries[row["object_kind"]] <= {
            boundary["claim"] for boundary in row["not_established"]}


def test_package_catalog_digests_bind_exact_proposition_and_checker_sources() -> None:
    modules = {"MARKET": market_checks, "ROBOT": robot_checks, "FINBOT": finbot_checks}
    for row in _behavioral_catalog():
        route = behavioral.routes(row["object_kind"])[row["tier"] - 1]
        assert row["proposition_digest"] == value_digest(
            behavioral.registration(route.kind, route.check))
        assert row["mechanism_digest"] == modules[row["object_kind"]].mechanism_digest()
        changed = deepcopy(row)
        changed["proposition_digest"] = "sha256:" + "0" * 64
        assert not behavioral.is_route(changed)
        changed = deepcopy(row)
        changed["mechanism_digest"] = "sha256:" + "0" * 64
        assert not behavioral.is_route(changed)


def test_package_catalog_rejects_applicability_binding_forgery() -> None:
    row = _behavioral_catalog()[0]

    wrong_digest = deepcopy(row)
    wrong_digest["applicability_digest"] = "sha256:" + "0" * 64
    assert not behavioral.is_route(wrong_digest)

    coordinated_forgery = deepcopy(row)
    coordinated_forgery["applicability"]["condition"] = (
        "A caller-authored condition that is not the installed route contract."
    )
    coordinated_forgery["applicability_digest"] = applicability_digest(
        coordinated_forgery["applicability"]
    )
    assert not behavioral.is_route(coordinated_forgery)


def _catalog_row(kind: str, tier: int) -> dict:
    return next(row for row in _behavioral_catalog()
                if row["object_kind"] == kind and row["tier"] == tier)


def _claims(row: dict) -> set[str]:
    return {boundary["claim"] for boundary in row["not_established"]}


def test_route_prose_matches_the_evidence_2_mechanisms_without_external_overclaim() -> None:
    assert behavioral.SEMANTIC_VERSION == "verifier-added-kind-behavioral-routes-2"

    market_allocation = _catalog_row("MARKET", 2)
    assert market_allocation["exact_claim"] == (
        "The tier-1 trace and every retained match replay with integer price and "
        "quantity units, unique priority, compatible sides and prices, and quantity "
        "conservation; retained manipulation-control records are sorted and unique, "
        "carry canonical evidence digests, and record no retained violation."
    )
    assert {"absence of manipulation", "manipulation-control rule coverage"} <= _claims(
        market_allocation
    )

    market_settlement = _catalog_row("MARKET", 3)
    assert "retained settlement, disruption, and participant-failure records" in (
        market_settlement["exact_claim"]
    )
    assert {
        "real settlement",
        "participant failure completeness",
        "absence of unretained participant failures",
        "external settlement dependency completeness",
    } <= _claims(market_settlement)

    robot_observation = _catalog_row("ROBOT", 2)
    assert robot_observation["exact_claim"] == (
        "The tier-1 path and finite retained command/effect/observation records bind "
        "each trace to one ordered SOFTWARE_COMMAND-to-REAL_PHYSICAL crossing, a unique "
        "canonical retained-effect digest, and one typed confinement claim per selected "
        "actuator whose authenticity is NOT_ESTABLISHED."
    )
    assert {
        "observation authenticity",
        "physical causal attribution",
        "physical actuation",
        "external confinement",
        "confinement evidence authenticity",
    } <= _claims(robot_observation)

    row = _catalog_row("FINBOT", 1)
    assert row["exact_claim"] == (
        "The installed consequence engine accepts the selected retained AGENT-HARNESS "
        "path to a typed real-financial endpoint, and the retained authority record has "
        "a structured decision scope whose agent_id, harness_id, and "
        "financial_endpoint_id exactly equal that bound path plus a non-empty "
        "financial-authority boundary."
    )
    assert "decision-scope binding to agent, harness, and endpoint" not in _claims(row)
    assert {"legal authority", "account ownership", "identity"} <= _claims(row)

    finbot_exposure = _catalog_row("FINBOT", 2)
    assert "correspond to sorted unique identifiers in the retained asset and party registries" in (
        finbot_exposure["exact_claim"]
    )
    assert "external asset and party registry correspondence" in _claims(finbot_exposure)
    assert "asset and party registry correspondence" not in _claims(finbot_exposure)


def test_market_settlement_route_bounds_participant_failure() -> None:
    # participant_failure has no retained record, so its absence must stay an explicit boundary.
    assert "participant failure completeness" in _claims(_catalog_row("MARKET", 3))


def test_market_matching_route_bounds_manipulation_controls() -> None:
    # manipulation_controls is boundary-only; rule coverage must stay an explicit boundary.
    assert "manipulation-control rule coverage" in _claims(_catalog_row("MARKET", 2))


def test_robot_observation_route_bounds_confinement_evidence() -> None:
    # confinement_evidence is boundary-only; its authenticity must stay NOT_ESTABLISHED.
    assert "confinement evidence authenticity" in _claims(_catalog_row("ROBOT", 2))


def test_finbot_reconciliation_route_bounds_independent_limit_enforcement() -> None:
    # limit_enforcement is partial; independent enforcement must stay an explicit boundary.
    assert "independent limit enforcement" in _claims(_catalog_row("FINBOT", 3))


def test_finbot_exposure_route_bounds_assets_and_parties() -> None:
    # Retained correspondence is mechanized; external identity and backing remain bounded.
    claims = _claims(_catalog_row("FINBOT", 2))
    assert "external asset and party registry correspondence" in claims
    assert {"asset backing", "party identity"} <= claims


def test_finbot_structured_scope_bound_to_same_agent_harness_and_endpoint_passes() -> None:
    bundle, authority, exposures, reconciliation = _finbot_parts()
    authority["decision_scope"] = _scope()
    result, *_ = _finbot_certificate("authority", bundle=bundle, authority=authority,
                                     exposures=exposures, reconciliation=reconciliation)
    assert result["status"] == "PASS"


def test_finbot_scope_naming_another_agent_is_refuted() -> None:
    bundle, authority, exposures, reconciliation = _finbot_parts()
    authority["decision_scope"] = "agent=other-agent harness=other-harness"
    result, *_ = _finbot_certificate("authority", bundle=bundle, authority=authority,
                                     exposures=exposures, reconciliation=reconciliation)
    assert result["status"] == "FAIL"


def test_robot_replayed_effect_digest_across_traces_is_refuted() -> None:
    bundle, path, observations, hazards = _robot_parts()
    replay = deepcopy(observations["traces"][0])
    replay.update(trace_id="replay", command_sequence=3, observation_sequence=4)
    observations["traces"].append(replay)
    result, *_ = _robot_certificate("observation", bundle=bundle, path=path,
                                    observations=observations, hazards=hazards)
    assert result["status"] == "FAIL"


@pytest.mark.parametrize(("mutation", "reason"), [
    ("reordered_observation", "not strictly ordered after commands"),
    ("aliased_trace", "trace identifier is duplicated"),
    ("cross_object_agent", "differs from the selected path"),
    ("unknown_trace_field", "trace fields differ"),
    ("bool_as_sequence", "requires a plain integer"),
])
def test_robot_adversarial_observation_mutations_are_refuted(mutation: str, reason: str) -> None:
    bundle, path, observations, hazards = _robot_parts()
    trace = observations["traces"][0]
    if mutation == "reordered_observation":
        second = deepcopy(trace)
        second.update(trace_id="second", command_sequence=5, observation_sequence=1)
        observations["traces"].append(second)
    elif mutation == "aliased_trace":
        second = deepcopy(trace)
        second.update(command_sequence=5, observation_sequence=6)
        observations["traces"].append(second)
    elif mutation == "cross_object_agent":
        trace["agent_id"] = "other-agent"
    elif mutation == "unknown_trace_field":
        trace["unreviewed"] = True
    else:
        trace["command_sequence"] = True
    result, *_ = _robot_certificate("observation", bundle=bundle, path=path,
                                    observations=observations, hazards=hazards)
    assert result["status"] == "FAIL"
    assert reason in result["evaluation"]["reason"]


@pytest.mark.parametrize(("mutation", "reason"), [
    ("swapped_endpoint", "endpoint differs from the assessed financial path"),
    ("duplicate_exposure_id", "exposure identifier is duplicated"),
])
def test_finbot_adversarial_exposure_mutations_are_refuted(mutation: str, reason: str) -> None:
    bundle, authority, exposures, reconciliation = _finbot_parts()
    row = exposures["exposures"][0]
    if mutation == "swapped_endpoint":
        row["endpoint_id"] = "agent"
    else:
        exposures["exposures"].append(deepcopy(row))
    result, *_ = _finbot_certificate("exposure", bundle=bundle, authority=authority,
                                     exposures=exposures, reconciliation=reconciliation)
    assert result["status"] == "FAIL"
    assert reason in result["evaluation"]["reason"]


@pytest.mark.parametrize(("mutation", "expected", "reason"), [
    ("asset_absent", "FAIL", "absent from the retained asset registry"),
    ("party_absent", "FAIL", "absent from the retained party registry"),
    ("registry_unsorted", "FAIL", "must be sorted and unique"),
    ("registry_aliased", "FAIL", "must be sorted and unique"),
    ("registry_empty", "UNKNOWN", "asset registry is empty"),
    ("exposure_unknown_field", "FAIL", "FINBOT exposure fields differ"),
])
def test_finbot_exposure_assets_and_parties_correspond_to_retained_registries(
        mutation: str, expected: str, reason: str) -> None:
    bundle, authority, exposures, reconciliation = _finbot_parts()
    row = exposures["exposures"][0]
    if mutation == "asset_absent":
        row["asset_id"] = "ghost-asset"
    elif mutation == "party_absent":
        row["party_id"] = "ghost-party"
    elif mutation == "registry_unsorted":
        exposures["asset_registry"] = ["zeta-asset", "asset"]
    elif mutation == "registry_aliased":
        exposures["asset_registry"] = ["asset", "asset"]
    elif mutation == "registry_empty":
        exposures["asset_registry"] = []
    else:
        row["unreviewed"] = True
    result, *_ = _finbot_certificate("exposure", bundle=bundle, authority=authority,
                                     exposures=exposures, reconciliation=reconciliation)
    assert result["status"] == expected
    assert reason in result["evaluation"]["reason"]


@pytest.mark.parametrize(("scope", "reason"), [
    ("retained-risk-limit", "FINBOT decision scope fields differ"),
    ({"agent_id": "agent", "harness_id": "harness"}, "FINBOT decision scope fields differ"),
    (_scope(extra="unreviewed"), "FINBOT decision scope fields differ"),
    (_scope(harness_id="other-harness"), "differs from the bound agent, harness, or financial endpoint"),
    (_scope(agent_id="other-agent"), "differs from the bound agent, harness, or financial endpoint"),
    (_scope(financial_endpoint_id="agent"), "differs from the bound agent, harness, or financial endpoint"),
    (_scope(financial_endpoint_id=7), "differs from the bound agent, harness, or financial endpoint"),
])
def test_finbot_decision_scope_must_bind_exact_identifiers(scope: object, reason: str) -> None:
    bundle, authority, exposures, reconciliation = _finbot_parts()
    authority["decision_scope"] = scope
    result, *_ = _finbot_certificate("authority", bundle=bundle, authority=authority,
                                     exposures=exposures, reconciliation=reconciliation)
    assert result["status"] == "FAIL"
    assert reason in result["evaluation"]["reason"]


@pytest.mark.parametrize(("status_value", "expected", "reason"), [
    ("DISPUTED", "FAIL", "retained reconciliation is disputed"),
    ("UNAVAILABLE", "UNKNOWN", "retained reconciliation is unavailable"),
    ("BOGUS", "FAIL", "reconciliation status is invalid"),
])
def test_finbot_reconciliation_status_gates_the_reconciliation_route(
        status_value: str, expected: str, reason: str) -> None:
    bundle, authority, exposures, reconciliation = _finbot_parts()
    reconciliation["reconciliations"][0]["status"] = status_value
    result, *_ = _finbot_certificate("reconciliation", bundle=bundle, authority=authority,
                                     exposures=exposures, reconciliation=reconciliation)
    assert result["status"] == expected
    assert reason in result["evaluation"]["reason"]


@pytest.mark.parametrize(("mutation", "reason"), [
    ("missing_reconciliation", "decision reconciliation binding differs"),
    ("forged_reconciliation_effect", "decision reconciliation binding differs"),
    ("cross_object_intervention", "decision intervention binding differs"),
    ("aliased_reconciliation", "reconciliation identifier is duplicated"),
    ("reordered_retry", "retry attempts are duplicated, unordered"),
    ("unknown_decision_field", "FINBOT decision fields differ"),
])
def test_finbot_reconciliation_adversarial_mutations_are_refuted(mutation: str, reason: str) -> None:
    bundle, authority, exposures, reconciliation = _finbot_parts()
    decision = reconciliation["decisions"][0]
    if mutation == "missing_reconciliation":
        reconciliation["reconciliations"] = []
    elif mutation == "forged_reconciliation_effect":
        reconciliation["reconciliations"][0]["effect_id"] = "other-effect"
    elif mutation == "cross_object_intervention":
        reconciliation["interventions"].append({"intervention_id": "foreign", "decision_id": "elsewhere",
            "action": "review", "reason": "Foreign intervention record."})
        decision["intervention_id"] = "foreign"
    elif mutation == "aliased_reconciliation":
        reconciliation["reconciliations"].append(deepcopy(reconciliation["reconciliations"][0]))
    elif mutation == "reordered_retry":
        retry = deepcopy(decision)
        retry.update(decision_id="retry", attempt=2, outcome="REFUSED",
                     intervention_id="retry-intervention", reconciliation_id="retry-reconciliation")
        reconciliation["decisions"] = [retry, decision]
        reconciliation["interventions"].append({"intervention_id": "retry-intervention",
            "decision_id": "retry", "action": "review", "reason": "Retained retry review."})
        reconciliation["reconciliations"].append({"reconciliation_id": "retry-reconciliation",
            "effect_id": "effect", "status": "RECONCILED", "evidence_digest": "sha256:" + "d" * 64})
    else:
        decision["unreviewed"] = True
    result, *_ = _finbot_certificate("reconciliation", bundle=bundle, authority=authority,
                                     exposures=exposures, reconciliation=reconciliation)
    assert result["status"] == "FAIL"
    assert reason in result["evaluation"]["reason"]


@pytest.mark.parametrize(("mutation", "expected", "reason"), [
    ("missing", "UNKNOWN", "lacks a domain crossing record"),
    ("reordered", "FAIL", "domain crossings are not in trace order"),
    ("duplicate_trace", "FAIL", "more than one domain crossing"),
    ("aliased_id", "FAIL", "domain crossing identifier is duplicated"),
    ("forged_trace", "FAIL", "domain crossing trace is absent"),
    ("cross_object_actuator", "FAIL", "domain crossing actuator differs from its trace"),
    ("simulated_target", "FAIL", "must run from SOFTWARE_COMMAND to REAL_PHYSICAL"),
    ("unknown_field", "FAIL", "ROBOT domain crossing fields differ"),
])
def test_robot_domain_crossings_bind_each_trace_in_order(mutation: str, expected: str, reason: str) -> None:
    bundle, path, observations, hazards = _robot_parts()
    crossing = observations["crossings"][0]
    if mutation == "missing":
        observations["crossings"] = []
    elif mutation == "reordered":
        second = deepcopy(observations["traces"][0])
        second.update(trace_id="second", command_sequence=5, observation_sequence=6,
                      retained_effect_digest="sha256:" + "c" * 64)
        observations["traces"].append(second)
        observations["crossings"] = [_crossing("second-crossing", "second"), crossing]
    elif mutation == "duplicate_trace":
        observations["crossings"].append(_crossing("other-crossing"))
    elif mutation == "aliased_id":
        observations["crossings"].append(_crossing())
    elif mutation == "forged_trace":
        crossing["trace_id"] = "ghost"
    elif mutation == "cross_object_actuator":
        crossing["actuator_id"] = "other-actuator"
    elif mutation == "simulated_target":
        crossing["to_domain"] = "SIMULATED"
    else:
        crossing["unreviewed"] = True
    result, *_ = _robot_certificate("observation", bundle=bundle, path=path,
                                    observations=observations, hazards=hazards)
    assert result["status"] == expected
    assert reason in result["evaluation"]["reason"]


@pytest.mark.parametrize(("mutation", "expected", "reason"), [
    ("missing", "UNKNOWN", "lacks a typed confinement claim"),
    ("authenticated", "FAIL", "authenticity claim is outside this mechanism"),
    ("unknown_type", "FAIL", "confinement claim type is invalid"),
    ("duplicate_actuator", "FAIL", "more than one confinement claim"),
    ("outside_path", "FAIL", "names an actuator outside the selected path"),
    ("blank_reason", "FAIL", "confinement claim reason is required"),
    ("unknown_field", "FAIL", "ROBOT confinement claim fields differ"),
])
def test_robot_confinement_claims_are_typed_and_never_upgraded(mutation: str, expected: str, reason: str) -> None:
    bundle, path, observations, hazards = _robot_parts()
    claim = observations["confinements"][0]
    if mutation == "missing":
        observations["confinements"] = []
    elif mutation == "authenticated":
        claim["authenticity"] = "VERIFIED"
    elif mutation == "unknown_type":
        claim["claim_type"] = "SAFE"
    elif mutation == "duplicate_actuator":
        observations["confinements"].append(dict(_confinement(), confinement_id="other"))
    elif mutation == "outside_path":
        claim["actuator_id"] = "other-actuator"
    elif mutation == "blank_reason":
        claim["reason"] = " "
    else:
        claim["unreviewed"] = True
    result, *_ = _robot_certificate("observation", bundle=bundle, path=path,
                                    observations=observations, hazards=hazards)
    assert result["status"] == expected
    assert reason in result["evaluation"]["reason"]


def test_robot_declared_absence_of_confinement_is_typed_and_still_not_established() -> None:
    bundle, path, observations, hazards = _robot_parts()
    observations["confinements"] = [_confinement("NONE_DECLARED")]
    result, *_ = _robot_certificate("observation", bundle=bundle, path=path,
                                    observations=observations, hazards=hazards)
    assert result["status"] == "PASS"
    assert result["external_confinement"] == "NOT_ESTABLISHED"
    assert result["evaluation"]["details"]["confinement_claims"] == 1


@pytest.mark.parametrize(("mutation", "expected", "reason"), [
    ("unknown_field", "FAIL", "manipulation-control rule fields differ"),
])
def test_market_manipulation_rule_records_are_closed(mutation: str, expected: str, reason: str) -> None:
    order_access, matching, settlement = _market_parts()
    matching["manipulation_rules"][0][mutation] = True
    result, *_ = _market_certificate("allocation", order_access=order_access,
                                     matching=matching, settlement=settlement)
    assert result["status"] == expected
    assert reason in result["evaluation"]["reason"]


@pytest.mark.parametrize(("rules", "expected", "reason"), [
    ([], "UNKNOWN", "no manipulation-control rule evidence is retained"),
    ([_manipulation_rule("rule-b"), _manipulation_rule("rule-a")], "FAIL", "must be sorted and unique"),
    ([_manipulation_rule("rule-a"), _manipulation_rule("rule-a")], "FAIL", "must be sorted and unique"),
    ([_manipulation_rule(result="CLEAN")], "FAIL", "manipulation-control result is invalid"),
    ([_manipulation_rule(result="VIOLATION_RETAINED")], "FAIL", "records a violation"),
    ([{"rule_id": "rule-a", "evidence_digest": "sha256:" + "E" * 64, "result": "NO_VIOLATION_RETAINED"}],
     "FAIL", "canonical SHA-256"),
])
def test_market_manipulation_rules_must_be_retained_sorted_and_clean(
        rules: list, expected: str, reason: str) -> None:
    order_access, matching, settlement = _market_parts()
    matching["manipulation_rules"] = rules
    result, *_ = _market_certificate("allocation", order_access=order_access,
                                     matching=matching, settlement=settlement)
    assert result["status"] == expected
    assert reason in result["evaluation"]["reason"]


@pytest.mark.parametrize(("status_value", "participant", "expected", "reason"), [
    ("RECOVERED", "ghost", "FAIL", "names an absent participant"),
    ("UNRECOVERED", "buyer", "UNKNOWN", "lacks a recovery record"),
    ("CLEARED", "buyer", "FAIL", "participant failure status is invalid"),
])
def test_market_participant_failure_records_are_bound_and_gate_settlement(
        status_value: str, participant: str, expected: str, reason: str) -> None:
    order_access, matching, settlement = _market_parts()
    settlement["participant_failures"] = [{"failure_id": "failure", "participant_id": participant,
        "status": status_value, "evidence_digest": "sha256:" + "f" * 64}]
    result, *_ = _market_certificate("settlement", order_access=order_access,
                                     matching=matching, settlement=settlement)
    assert result["status"] == expected
    assert reason in result["evaluation"]["reason"]


def test_market_recovered_participant_failure_keeps_settlement_dependencies_partial() -> None:
    order_access, matching, settlement = _market_parts()
    settlement["participant_failures"] = [{"failure_id": "failure", "participant_id": "buyer",
        "status": "RECOVERED", "evidence_digest": "sha256:" + "f" * 64}]
    result, *_ = _market_certificate("settlement", order_access=order_access,
                                     matching=matching, settlement=settlement)
    assert result["status"] == "PASS"
    assert result["evaluation"]["details"]["participant_failures"] == 1
    assert result["evaluation"]["details"]["external_dependencies"] == "NOT_ESTABLISHED"
