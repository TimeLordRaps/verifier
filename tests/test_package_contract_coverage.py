"""Independent package-contract coverage regressions for Verifier Standard (VSTD).

Terminology: identifier (ID).

Fresh instance execution remains the responsibility of each installed checker.
These tests challenge the aggregation boundary, not a substitute subject model.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_package_polish import declared_package
from test_package_kind_requirements import prepare
from verifier.runtime import package_polish as package
from verifier.runtime import package_contract_coverage as coverage_checker
from verifier.runtime import (
    manifest_gate,
    package_contract_profiles,
    package_execution,
    package_source_contracts,
)
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.runtime.namespace_contracts import namespace_registry
from verifier.runtime.package_kind_requirements import KindRequirements
from verifier.runtime.tier_zero_profile import value_digest


CONSEQUENCE_OBLIGATIONS = {
    "MARKET-0.1-orders-and-access",
    "MARKET-0.2-matching-and-allocation",
    "MARKET-0.3-settlement-and-disruption",
    "ROBOT-0.1-agent-to-actuator-binding",
    "ROBOT-0.2-physical-reach-and-observation",
    "ROBOT-0.3-consequences-and-intervention",
    "FINBOT-0.1-agent-and-financial-authority",
    "FINBOT-0.2-financial-exposure-and-dependencies",
    "FINBOT-0.3-decisions-effects-and-recovery",
}


def validate_coverage(report: dict) -> None:
    import jsonschema
    schema = json.loads((Path(coverage_checker.__file__).parents[1] /
        "schemas/verifier-package-contract-coverage-2.schema.json").read_bytes())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(report)


def test_package_assesses_contract_coverage_after_actual_instance_selection(declared_package):
    root, retained, _ = declared_package
    prepare(root, retained)
    report = package.assess_package_polish(3, root)
    coverage = report["kind_requirements"].get("contract_coverage")
    assert coverage is not None, "Package conformance needs an assessed contract denominator, not a blanket UNKNOWN"
    assert coverage["schema_version"] == "verifier-package-contract-coverage-2"
    assert coverage["denominator_status"] == "PASS"
    assert coverage["expected_instance_count"] == len(report["obligation_instances"])
    assert coverage["normative_coverage"] == "NOT_ESTABLISHED"
    assert coverage["status"] == "UNKNOWN"
    assessed_kinds = {row["kind"] for row in coverage["contracts"]}
    assert assessed_kinds >= {"ROBOT", "FINBOT"}
    # This fixture no longer falsely labels a process-launch surface ACTUATOR.
    # The kind remains in the exact package profile denominator even when this
    # selected package has no source-established ACTUATOR carrier.
    assert "ACTUATOR" not in assessed_kinds
    assert set(package_contract_profiles.document()["profiles"]) \
        == set(namespace_registry())
    assert {"BOT-1.7", "BOT-2.6", "BOT-3.5"} <= {
        clause["coordinate"]
        for contract in coverage["contracts"]
        if contract["kind"] == "BOT"
        for clause in contract["clauses"]
    }
    assert all(row["residual_requirements"] for row in coverage["contracts"])
    verifier_contract = next(
        row for row in coverage["contracts"]
        if row["object_id"] == report["verifier_execution"]["object_id"]
        and row["kind"] == "VERIFIER"
    )
    global_residuals = {
        row["source_id"] for row in verifier_contract["residual_requirements"]
        if row["mechanism"] == (
            "verifier.runtime.package_contract_profiles."
            "reconcile_package_instance_applicability"
        )
    }
    # ROBOT and FINBOT have effective source-bound carriers in this package, so
    # their routes remain in the ordinary instance denominator.  MARKET is
    # source-bound NECESSARY globally but has no effective package carrier and
    # therefore remains in the verifier-bound reconciliation ledger.
    assert global_residuals == {
        value for value in CONSEQUENCE_OBLIGATIONS
        if value.startswith("MARKET-")
    }
    validate_coverage(coverage)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unexpected", "object", "proposition", "mechanism", "tier", "verifier", "specimen"])
def test_package_refutes_omitted_or_substituted_instance_rows(declared_package, monkeypatch, mutation):
    root, retained, _ = declared_package
    prepare(root, retained)
    original = package._instance_obligations

    def altered(*args, **kwargs):
        rows = deepcopy(original(*args, **kwargs))
        if mutation == "missing":
            rows.pop()
        elif mutation == "duplicate":
            rows.append(deepcopy(rows[0]))
        elif mutation == "unexpected":
            rows[0]["coordinate"] = "OBJECT-1.999"
        else:
            field, value = {
                "object": ("object_digest", "sha256:" + "0" * 64),
                "proposition": ("proposition_digest", "sha256:" + "0" * 64),
                "mechanism": ("checking_mechanism", "unregistered.check"),
                # Keep the row structurally admissible to the self-polish graph
                # so contract coverage, the system under test here, observes and
                # refutes the substituted tier binding itself.
                "tier": ("tier", 4),
                "verifier": ("verifier_id", "another-verifier"),
                "specimen": ("native_specimen_is_instance_evidence", True),
            }[mutation]
            rows[0][field] = value
        return rows

    monkeypatch.setattr(package, "_instance_obligations", altered)
    report = package.assess_package_polish(3, root)
    coverage = report["kind_requirements"].get("contract_coverage")
    assert coverage is not None
    assert coverage["status"] == coverage["denominator_status"] == "FAIL"
    assert report["status"] == "FAIL"
    assert "PACKAGE_CONTRACT_DENOMINATOR_REFUTED" in report["blockers"]
    assert any(row["code"].startswith("PACKAGE_CONTRACT_") for row in coverage["findings"])
    assert any(row["gate_id"] == "contract-denominator" for row in report["findings"])
    assert all(row["rerun_argv"] == ["vstd", "polish", "3"] for row in coverage["findings"])
    validate_coverage(coverage)
    legacy = deepcopy(coverage)
    for finding in legacy["findings"]:
        finding["rerun_argv"] = (["vstd", "gate", "--object", finding["object_id"],
                                  "--obligation", finding["obligation_id"]] if finding["obligation_id"] else None)
    validate_coverage(legacy)  # Earlier diagnostic receipts keep their shape.


def test_all_kinds_and_local_extensions_keep_their_semantic_remainders(declared_package):
    root, retained, _ = declared_package
    document = prepare(root, retained)
    document["namespace"].pop("consequence_graph")
    from test_package_kind_requirements import save
    from verifier.runtime.namespace_contracts import namespace_registry, registry_document

    registry = namespace_registry()
    # Every kind is a source requirement on one generic subject. No cast or
    # example execution can supply the absent typed representations.
    (root / "subject.py").write_text("__vstd_kinds__ = " + repr(sorted(registry)) + "\n", encoding="utf-8")
    document["namespace"]["extensions"] = [{"kind": "LOCALPOLICY", "extends": "POLICY", "version": "1",
        "reason": "Additional local enforcement conditions cannot vanish behind inherited checks.",
        "obligations": [{"id": "LOCALPOLICY-0.1-extra-constraint", "name": "Extra constraint",
            "reason": "An extra effect constraint must remain explicit.", "evidence_requirement": "Current implementation evidence."}]}]
    registry = namespace_registry(document["namespace"]["extensions"])
    document["namespace"]["registry_digest"] = registry_document(registry)["digest"]
    external = next(row for row in document["namespace"]["objects"] if row["object_id"] == "external")
    external["specializations"] = ["LOCALPOLICY"]
    save(root, document)
    report = package.assess_package_polish(3, root)
    coverage = report["kind_requirements"]["contract_coverage"]
    contracts = {row["kind"]: row for row in coverage["contracts"] if row["object_id"] == "external"}
    assert set(contracts) == set(registry) and len(contracts) == 39
    assert coverage["denominator_status"] == "PASS"
    assert all(row["status"] == "UNKNOWN" and row["residual_requirements"] for row in contracts.values())
    assert contracts["LOCALPOLICY"]["finite_check_status"] == "UNKNOWN"
    assert contracts["LOCALPOLICY"]["clauses"] == []  # Empty is not a vacuous PASS.
    for kind in ("ROBOT", "FINBOT", "POLICY", "LOCALPOLICY"):
        required = {row.id for row in registry[kind].obligations}
        assert required <= {row["source_id"] for row in contracts[kind]["residual_requirements"]}
    assert len([row for row in contracts["AGENT"]["residual_requirements"]
                if row["source"] == "native-slot-planning-context"]) == 3
    assert coverage["assessment_digest"] == value_digest({key: value for key, value in coverage.items() if key != "assessment_digest"})
    validate_coverage(coverage)

    objects = package.package_manifest.validate_bridge(document)
    selected = KindRequirements(root, document["namespace"])
    rows = deepcopy(report["obligation_instances"])
    # This is a hostile internal result set, not a portable evidence interface.
    # Even perfectly shaped green metadata cannot close semantic completeness.
    for row in rows:
        row.update(status="PASS", checker_status="PASS", blockers=[], selected_package_check={"status": "PASS"},
            applicability={"status": "PASS", "classification": "NECESSARY", "assessment_required": True,
                           "reason": "Supposed result from a selected checker."})
    assessed = coverage_checker.assess(3, objects, selected, rows,
                                      verifier_id=report["verifier_execution"]["object_id"])
    assert assessed["status"] == "FAIL" and assessed["normative_coverage"] == "NOT_ESTABLISHED"
    assert assessed["denominator_status"] == "FAIL"
    assert next(row for row in assessed["contracts"] if row["object_id"] == "external"
                and row["kind"] == "LOCALPOLICY")["finite_check_status"] == "UNKNOWN"


def test_applicability_and_checker_contradictions_cannot_be_counted_as_pass(declared_package):
    root, retained, _ = declared_package
    document = prepare(root, retained)
    report = package.assess_package_polish(1, root)
    objects = package.package_manifest.validate_bridge(document)
    selected = KindRequirements(root, document["namespace"])
    for field, value in (("checker_status", "UNKNOWN"), ("blockers", ["MISSING"]),
                         ("selected_package_check", None), ("applicability", {"status": "PASS", "classification": "OPTIONAL"})):
        rows = deepcopy(report["obligation_instances"])
        rows[0].update(status="PASS", checker_status="PASS", blockers=[], selected_package_check={"status": "PASS"},
            applicability={"status": "PASS", "classification": "NECESSARY", "assessment_required": True,
                           "reason": "A required finite check."})
        rows[0][field] = value
        assessed = coverage_checker.assess(1, objects, selected, rows,
                                          verifier_id=report["verifier_execution"]["object_id"])
        assert assessed["status"] == "FAIL"
        assert any(row["code"] == "PACKAGE_CONTRACT_VERDICT_CONTRADICTION" for row in assessed["findings"])


def test_executable_source_route_not_nonowned_implementation_discharges_family(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Current-source execution, not an implementation non-trigger, closes ASSET."""
    subject = NamespaceObject.create("other-asset", "OBJECT", {"variant": "other"})
    verifier = NamespaceObject.create("verifier", "VERIFIER", {})
    objects = (subject, verifier)
    collection_digest = composition_digest(objects)
    source_route = next(row for row in package_source_contracts.catalog()
                        if row["coordinate"] == "ASSET-1.90")
    behavioral_route = next(row for row in package_execution.catalog()
                            if row["coordinate"] == "ASSET-1.1")
    monkeypatch.setattr(
        manifest_gate,
        "obligation_catalog",
        lambda: [source_route, behavioral_route],
    )
    monkeypatch.setattr(
        package_source_contracts,
        "applies_to",
        lambda item, _declaration, route, _kinds: (
            item.object_id == subject.object_id
            and package_source_contracts.is_route(route)
        ),
    )
    declaration = {
        "kind": "OBJECT",
        "surfaces": ["file:other_asset.py"],
        "classification": {},
    }
    kinds = SimpleNamespace(
        registry=namespace_registry(),
        objects={item.object_id: item for item in objects},
        declarations={subject.object_id: declaration, verifier.object_id: {
            "kind": "VERIFIER", "surfaces": [], "classification": {},
        }},
        execution_mechanisms={
            subject.object_id: frozenset(), verifier.object_id: frozenset(),
        },
        report={"source_census_digest": "sha256:" + "2" * 64},
        kinds=lambda identifier: (
            {"ASSET"} if identifier == subject.object_id else set()
        ),
        basis=lambda _identifier, kind: {
            "kind": kind,
            "declared": True,
            "necessity": "NECESSARY",
            "reasons": ["The current source graph has an applicable ASSET role."],
            "source_census_digest": "sha256:" + "2" * 64,
        },
    )

    def instance(route: dict, selected: dict, checker_status: str,
                 classification: str) -> dict:
        identity = {
            "object_id": subject.object_id,
            "object_digest": subject.digest,
            "coordinate": route["coordinate"],
            "tier": route["tier"],
            "proposition_digest": route["proposition_digest"],
        }
        return {
            **identity,
            "instance_digest": value_digest(identity),
            "object_kind": route["object_kind"],
            "verifier_id": verifier.object_id,
            "checking_mechanism": route["checking_mechanism"],
            "scope": route["scope"],
            "native_specimen_is_instance_evidence": False,
            "status": "PASS",
            "checker_status": checker_status,
            "blockers": [],
            "applicability": {
                "status": "PASS",
                "classification": classification,
                "assessment_required": True,
                "reason": "Current source-bound applicability was assessed.",
            },
            "selected_package_check": selected,
        }

    source_check = {
        "status": "PASS",
        "adapter": package_source_contracts.ADAPTER,
        "coordinate": source_route["coordinate"],
        "object_id": subject.object_id,
        "object_digest": subject.digest,
        "collection_digest": collection_digest,
    }
    source_check["result_digest"] = value_digest(source_check)
    conditional_check = {
        "status": "PASS",
        "evidence_origin": "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW",
        "applicability_established": True,
        "applicability_classification": "CONDITION_NOT_MET",
        "fulfillment_required": False,
        "object_id": subject.object_id,
        "object_digest": subject.digest,
        "collection_digest": collection_digest,
        "native_coordinate": behavioral_route["coordinate"],
        "conditional_coordinate": behavioral_route["coordinate"],
        "adaptation_obligation_id": source_route["obligation_id"],
        "adaptation_result_digest": value_digest(source_check),
            "condition": behavioral_route["applicability"]["condition"],
        "applicability_digest": behavioral_route["applicability_digest"],
        "condition_status": "NOT_TRIGGERED",
    }
    conditional_check["result_digest"] = value_digest(conditional_check)
    assessed = coverage_checker.assess(
        1,
        objects,
        kinds,
        [
            instance(source_route, source_check, "PASS", "NECESSARY"),
            instance(
                behavioral_route,
                conditional_check,
                "NOT_REQUIRED",
                "CONDITION_NOT_MET",
            ),
        ],
        verifier_id=verifier.object_id,
    )

    contract = next(row for row in assessed["contracts"]
                    if row["object_id"] == subject.object_id
                    and row["kind"] == "ASSET")
    assert contract["finite_check_status"] == "PASS"
    assert contract["status"] == "UNKNOWN"
    assert contract["profile_status"] == "UNKNOWN"
    future = {
        row["source_id"]: row for row in contract["residual_requirements"]
    }
    # The executable source route closes only source representation. ASSET-0.1
    # identity and rights are PARTIAL, so the family must stay open with the
    # exact field-level reason and its tier-1 polish action.
    assert set(future) == {
        "ASSET-0.1-identity-and-quantity",
        "ASSET-0.2-issuance-and-redemption",
        "ASSET-0.3-custody-and-encumbrance",
    }
    identity = future["ASSET-0.1-identity-and-quantity"]
    assert identity["status"] == "UNKNOWN"
    assert identity["source"] == "admission-contract-semantic-remainder"
    assert identity["tier"] == 1
    assert identity["reason"] == (
        "Identical numbers can denote different assets, rights or units "
        "and must not be interchangeable."
    )
    assert "identity=PARTIAL, rights=PARTIAL" in identity["question"]
    assert identity["boundary"].startswith(
        "Route PASS cannot close non-mechanized declaration fields: "
        "identity=PARTIAL, rights=PARTIAL"
    )
    assert identity["next_action"] == ["vstd", "polish", "1"]
    assert future["ASSET-0.2-issuance-and-redemption"]["tier"] == 2
    assert future["ASSET-0.3-custody-and-encumbrance"]["tier"] == 3
    assert all("not an exemption" in future[source_id]["question"]
               for source_id in ("ASSET-0.2-issuance-and-redemption",
                                 "ASSET-0.3-custody-and-encumbrance"))
    validate_coverage(assessed)

    # Challenge the aggregation rule directly: if both routes look closed but
    # the executable source route is no longer a NECESSARY execution, the
    # implementation-specific non-trigger must not carry the family.
    clauses = deepcopy(contract["clauses"])
    source_clause = next(row for row in clauses
                         if row["coordinate"] == source_route["coordinate"])
    source_clause["checker_status"] = "NOT_REQUIRED"
    source_clause["applicability"]["classification"] = "CONDITION_NOT_MET"
    source_clause["fulfillment_required"] = False
    # Shipped state: the semantic field PARTIAL is still the reason, so the
    # non-trigger cannot replace that residual with an implementation-only one.
    residuals = coverage_checker._residuals("ASSET", 1, kinds, {}, clauses)
    residual = next(row for row in residuals
                    if row["source_id"] == "ASSET-0.1-identity-and-quantity")
    assert residual["source"] == "admission-contract-semantic-remainder"
    assert residual["status"] == "UNKNOWN"
    assert residual["next_action"] == ["vstd", "polish", "1"]
    assert "Add and source-bind" in residual["question"]

    # Counterfactual with the semantic blocker removed: the non-trigger still
    # cannot close the family, and the residual must say so exactly.
    monkeypatch.setattr(
        package_contract_profiles, "semantic_mapping_blocker", lambda _obligation: None,
    )
    residuals = coverage_checker._residuals("ASSET", 1, kinds, {}, clauses)
    residual = next(row for row in residuals
                    if row["source_id"] == "ASSET-0.1-identity-and-quantity")
    assert residual["source"] == "installed-package-variant-profile"
    assert "implementation-specific" in residual["boundary"]
    assert residual["next_action"] == [
        "vstd", "gate", "--object", "{object_id}",
        "--obligation", source_route["obligation_id"],
    ]
    assert "Implement or register and source-bind" in residual["question"]

    necessary_route = deepcopy(behavioral_route)
    necessary_applicability = dict(necessary_route["applicability"])
    necessary_applicability["mode"] = "NECESSARY"
    necessary_route["applicability"] = necessary_applicability
    necessary_route["applicability_digest"] = value_digest(necessary_applicability)
    forged = deepcopy(conditional_check)
    forged["applicability_digest"] = necessary_route["applicability_digest"]
    forged["result_digest"] = value_digest({
        key: value for key, value in forged.items() if key != "result_digest"
    })
    refused = coverage_checker._clause_metadata(
        necessary_route,
        instance(necessary_route, forged, "NOT_REQUIRED", "CONDITION_NOT_MET"),
        object_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=collection_digest,
    )
    assert refused["closure_status"] == "UNKNOWN"

    source_clause["closure_status"] = "UNKNOWN"
    coordinate_residuals = coverage_checker._residuals(
        "ASSET", 1, kinds, {}, clauses,
    )
    exact = next(row for row in coordinate_residuals
                 if row["source_id"] == source_route["coordinate"])
    assert exact["next_action"] == [
        "vstd", "gate", "--object", "{object_id}",
        "--obligation", source_route["obligation_id"],
    ]


def test_conditional_clause_accepts_the_subjects_declared_kind_source_adapter() -> None:
    """A DATA hint on an ARCH source binds ARCH adaptation, not fictitious DATA."""

    route = next(
        row for row in manifest_gate.obligation_catalog()
        if row["coordinate"] == "DATA-1.1"
    )
    source_route = next(
        row for row in package_source_contracts.catalog()
        if row["coordinate"] == "ARCH-1.90"
    )
    object_id = "architecture-source"
    object_digest = "sha256:" + "1" * 64
    collection_digest = "sha256:" + "2" * 64
    selected = {
        "status": "PASS",
        "evidence_origin": "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW",
        "applicability_established": True,
        "applicability_classification": "CONDITION_NOT_MET",
        "fulfillment_required": False,
        "object_id": object_id,
        "object_digest": object_digest,
        "collection_digest": collection_digest,
        "native_coordinate": route["coordinate"],
        "conditional_coordinate": route["coordinate"],
        "adaptation_obligation_id": source_route["obligation_id"],
        "adaptation_result_digest": "sha256:" + "3" * 64,
        "condition": route["applicability"]["condition"],
        "applicability_digest": route["applicability_digest"],
        "condition_status": "NOT_TRIGGERED",
    }
    selected["result_digest"] = value_digest(selected)
    row = {
        "status": "PASS",
        "checker_status": "NOT_REQUIRED",
        "applicability": {
            "status": "PASS",
            "classification": "CONDITION_NOT_MET",
            "assessment_required": True,
            "reason": "The exact source-bound condition was not triggered.",
        },
        "selected_package_check": selected,
    }

    metadata = coverage_checker._clause_metadata(
        route,
        row,
        object_id=object_id,
        object_digest=object_digest,
        collection_digest=collection_digest,
        installed_route=route,
    )

    assert metadata["closure_status"] == "PASS"
    assert metadata["applicability"]["classification"] == "CONDITION_NOT_MET"


ADDED_KINDS = (
    "LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR",
    "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY", "ROBOT", "FINBOT",
)


def _installed_routes() -> dict[str, str]:
    """Map each installed route coordinate to its exact gate obligation."""
    from verifier.runtime import manifest_gate

    catalog = manifest_gate.obligation_catalog()
    coordinates = [row["coordinate"] for row in catalog]
    assert len(set(coordinates)) == len(coordinates)
    return {row["coordinate"]: row["obligation_id"] for row in catalog}


def _clause(coordinate: str, routes: dict[str, str], *, closure: str = "PASS") -> dict:
    return {
        "coordinate": coordinate,
        "obligation_id": routes.get(coordinate, coordinate + "-foreign"),
        "closure_status": closure,
        "checker_status": "PASS",
        "checking_mechanism": "installed.check",
        "applicability": {"classification": "NECESSARY"},
        "fulfillment_required": True,
    }


def _open_coordinates(rows: list[dict]) -> dict[str, dict]:
    return {
        row["source_id"]: row for row in rows
        if row["source"] == "installed-package-variant-profile"
    }


@pytest.mark.parametrize("tier", [1, 2, 3])
def test_every_profiled_kind_without_source_clause_keeps_installed_coordinates_open(tier: int) -> None:
    """A missing KIND-1.90 clause must not erase the installed denominator."""
    routes = _installed_routes()
    kinds = SimpleNamespace(registry=namespace_registry())
    for kind in sorted(kinds.registry):
        required = package_contract_profiles.required_coordinates(kind, tier)
        rows = coverage_checker._residuals(kind, tier, kinds, {}, [],
                                           route_obligations=routes)
        assert set(_open_coordinates(rows)) == set(required), kind


@pytest.mark.parametrize("mutation", [
    "none", "omitted", "substituted", "no_source_unknown", "no_source_pass",
])
@pytest.mark.parametrize("kind", ADDED_KINDS)
def test_installed_coordinates_stay_open_under_omission_and_count_preserving_substitution(
    kind: str,
    mutation: str,
) -> None:
    routes = _installed_routes()
    kinds = SimpleNamespace(registry=namespace_registry())
    required = list(package_contract_profiles.required_coordinates(kind, 3))
    sources = set(package_contract_profiles.profile(kind)["source_routes"].values())
    behavioral = [coordinate for coordinate in required if coordinate not in sources]
    target = behavioral[0]
    if mutation == "none":
        clauses = [_clause(coordinate, routes) for coordinate in required]
        expected_open: set[str] = set()
    elif mutation == "omitted":
        clauses = [_clause(coordinate, routes) for coordinate in required
                   if coordinate != target]
        expected_open = {target}
    elif mutation == "substituted":
        # Same clause count, one required behavioral route replaced by a foreign one.
        clauses = ([_clause(coordinate, routes) for coordinate in required
                    if coordinate != target]
                   + [_clause("FOREIGN-9.1", routes)])
        expected_open = {target}
    elif mutation == "no_source_unknown":
        clauses = [_clause(coordinate, routes, closure="UNKNOWN")
                   for coordinate in behavioral]
        expected_open = set(required)
    else:
        clauses = [_clause(coordinate, routes) for coordinate in behavioral]
        expected_open = sources

    rows = coverage_checker._residuals(kind, 3, kinds, {}, clauses,
                                       route_obligations=routes)
    open_rows = _open_coordinates(rows)
    assert set(open_rows) == expected_open
    for coordinate, row in open_rows.items():
        assert row["status"] == "UNKNOWN"
        clause = next((item for item in clauses if item["coordinate"] == coordinate), None)
        obligation = clause["obligation_id"] if clause is not None else routes[coordinate]
        assert row["next_action"] == [
            "vstd", "gate", "--object", "{object_id}", "--obligation", obligation,
        ]


def test_route_presence_and_callable_mechanism_are_not_conformance() -> None:
    """Catalog presence and a callable checker name are not closure or execution."""
    matrix = package_contract_profiles.contract_coverage_matrix()
    routes = [route for row in matrix["kinds"].values() for route in row["routes"]]
    assert len(routes) == 293
    assert {route["catalog_presence"] for route in routes} == {"PRESENT_NOT_CONFORMANCE"}
    assert {route["mechanism_status"] for route in routes} == {"CALLABLE"}
    assert {route["package_instance_execution_status"] for route in routes} == {"NOT_ASSESSED"}
    assert matrix["status"] == "UNKNOWN"

    routes_by_coordinate = _installed_routes()
    kinds = SimpleNamespace(registry=namespace_registry())
    rows = coverage_checker._residuals("ASSET", 1, kinds, {}, [
        _clause("ASSET-1.90", routes_by_coordinate),
        _clause("ASSET-1.1", routes_by_coordinate, closure="UNKNOWN"),
    ], route_obligations=routes_by_coordinate)
    # The callable behavioral checker stays open until its closure is PASS.
    assert set(_open_coordinates(rows)) == {"ASSET-1.1"}


def test_future_added_declarations_remain_unknown_in_lower_polish_tiers() -> None:
    """Polish 1 must retain LEDGER declarations first executable at 2 and 3."""
    kinds = SimpleNamespace(registry=namespace_registry())
    clauses = [
        {
            "coordinate": coordinate,
            "closure_status": "PASS",
            "checking_mechanism": "selected.check",
            "checker_status": "PASS",
            "applicability": {"classification": "NECESSARY"},
            "fulfillment_required": True,
        }
        for coordinate in package_contract_profiles.required_coordinates("LEDGER", 1) or ()
    ]

    residuals = coverage_checker._residuals("LEDGER", 1, kinds, {}, clauses)
    by_id = {row["source_id"]: row for row in residuals}

    assert set(by_id) == {
        "LEDGER-0.1-authoritative-history",
        "LEDGER-0.2-accounting-invariants",
        "LEDGER-0.3-correction-and-recovery",
    }
    assert by_id["LEDGER-0.1-authoritative-history"]["tier"] == 1
    assert by_id["LEDGER-0.1-authoritative-history"]["next_action"] == [
        "vstd", "polish", "1",
    ]
    assert by_id["LEDGER-0.2-accounting-invariants"]["tier"] == 2
    assert by_id["LEDGER-0.2-accounting-invariants"]["next_action"] == [
        "vstd", "polish", "2",
    ]
    assert by_id["LEDGER-0.3-correction-and-recovery"]["tier"] == 3
    assert by_id["LEDGER-0.3-correction-and-recovery"]["next_action"] == [
        "vstd", "polish", "3",
    ]
    assert all(
        row["source"] == "admission-contract-semantic-remainder"
        and row["status"] == "UNKNOWN"
        for row in by_id.values()
    )
    assert all(
        "stays UNKNOWN" in by_id[obligation_id]["boundary"]
        for obligation_id in (
            "LEDGER-0.2-accounting-invariants",
            "LEDGER-0.3-correction-and-recovery",
        )
    )


def test_all_protocol_routes_pass_cannot_hide_unmapped_declaration_fields() -> None:
    kinds = SimpleNamespace(registry=namespace_registry())
    coordinates = package_contract_profiles.required_coordinates("PROTOCOL", 2)
    assert coordinates is not None
    clauses = [
        {
            "coordinate": coordinate,
            "closure_status": "PASS",
            "checking_mechanism": "selected.check",
            "checker_status": "PASS",
            "applicability": {"classification": "NECESSARY"},
            "fulfillment_required": True,
            "obligation_id": coordinate + "-synthetic-pass",
        }
        for coordinate in coordinates
    ]
    matrix = package_contract_profiles.contract_coverage_matrix()
    matrix_obligations = {
        row["obligation_id"]: row
        for row in matrix["kinds"]["PROTOCOL"]["profile_obligations"]
    }

    residuals = coverage_checker._residuals(
        "PROTOCOL", 2, kinds, {}, clauses, matrix_obligations
    )
    target = next(
        row for row in residuals
        if row["source_id"] == "PROTOCOL-0.2-ordering-and-replay"
    )
    assert target["source"] == "admission-contract-semantic-remainder"
    assert "message_authority=BOUNDARY_EXCLUDED" in target["question"]
    assert "ordering=MISSING" in target["question"]
    assert "compatibility=MISSING" in target["question"]
    assert "Route PASS cannot close" in target["boundary"]
    assert not any(
        row["source_id"] in coordinates
        for row in residuals
    ), "Every finite route passed; this residual is specifically field-semantic."

    boundary = next(
        row for row in matrix_obligations[
            "PROTOCOL-0.2-ordering-and-replay"
        ]["unmapped_declaration_fields"]
        if row["field"] == "message_authority"
    )
    assert boundary["status"] == "BOUNDARY_EXCLUDED"


def test_source_bound_carriers_are_distinct_from_semantic_mapping_gaps() -> None:
    """Current-package applicability and mechanism coverage remain separate facts."""
    expected = {
        "MARKET": {
            "MARKET-0.1-orders-and-access",
            "MARKET-0.2-matching-and-allocation",
            "MARKET-0.3-settlement-and-disruption",
        },
        "ROBOT": {
            "ROBOT-0.1-agent-to-actuator-binding",
            "ROBOT-0.2-physical-reach-and-observation",
            "ROBOT-0.3-consequences-and-intervention",
        },
        "FINBOT": {
            "FINBOT-0.1-agent-and-financial-authority",
            "FINBOT-0.2-financial-exposure-and-dependencies",
            "FINBOT-0.3-decisions-effects-and-recovery",
        },
    }
    matrix = package_contract_profiles.contract_coverage_matrix()
    blockers = {
        row["obligation_id"]
        for row in matrix["package_instance_applicability_blockers"]
    }
    obligations = {
        obligation["obligation_id"]: obligation
        for row in matrix["kinds"].values()
        for obligation in row["profile_obligations"]
    }
    assert blockers == set()
    for kind, obligation_ids in expected.items():
        assessment = matrix["package_instance_applicability_assessments"][kind]
        assert assessment["status"] == "NECESSARY"
        assert assessment["object_denominator"] == assessment["reviewed_object_count"] == 468
        assert assessment["carrier_count"] > 0
        assert assessment["invalid_count"] == 0
        assert assessment["source_binding_digest"].startswith("sha256:")
        assert all(
            obligations[obligation_id]["package_instance_applicability_status"]
            == "NECESSARY_SOURCE_BOUND_PACKAGE_CARRIER"
            and obligations[obligation_id][
                "package_instance_applicability_evidence"
            ]["status"] == "NECESSARY"
            and obligations[obligation_id][
                "package_instance_applicability_blocker"
            ] is None
            for obligation_id in obligation_ids
        )
        for obligation_id in obligation_ids:
            obligation = obligations[obligation_id]
            if obligation["unmapped_declaration_fields"]:
                assert obligation["semantic_mapping_status"] == "UNKNOWN"
                assert obligation["semantic_mapping_blocker"] is not None
            else:
                assert obligation["semantic_mapping_status"] \
                    == "SOURCE_BOUND_EXECUTABLE_MAPPING_NOT_CONFORMANCE"
                assert obligation["semantic_mapping_blocker"] is None


def _consequence_assessment(family: str, status: str) -> dict:
    marker = {
        "MARKET": "REAL_MARKET",
        "ROBOT": "REAL_PHYSICAL",
        "FINBOT": "REAL_FINANCIAL",
    }[family]
    necessary = status == "NECESSARY"
    condition_not_met = status == "SOURCE_BOUND_CONDITION_NOT_MET"
    body = {
        "kind": family,
        "status": status,
        "reason": "Exact synthetic source-bound consequence assessment.",
        "effect_domain": marker,
        "object_denominator": 1,
        "reviewed_object_count": 1,
        "applies_count": 1 if necessary else 0,
        "does_not_apply_count": 1 if condition_not_met else 0,
        "unresolved_count": 0 if necessary or condition_not_met else 1,
        "invalid_count": 0,
        "carrier_count": 1 if necessary else 0,
        "carriers": ([{
            "object_id": "subject",
            "basis": "DECLARED_" + marker + "_EFFECT",
        }] if necessary else []),
        "next_unresolved": None if necessary or condition_not_met else "subject",
        "missing_object_ids": [],
        "extra_object_ids": [],
        "checker_or_specimen_execution_is_carrier_evidence": False,
        "source_binding_digest": "sha256:" + "4" * 64,
        "source_bound_refutation_count": 1 if condition_not_met else 0,
    }
    return {**body, "evidence_digest": value_digest(body)}


def _consequence_matrix(statuses: dict[str, str]) -> dict:
    selected = {
        "MARKET": "SOURCE_BOUND_CONDITION_NOT_MET",
        "ROBOT": "SOURCE_BOUND_CONDITION_NOT_MET",
        "FINBOT": "SOURCE_BOUND_CONDITION_NOT_MET",
        **statuses,
    }
    return {
        "package_instance_applicability_assessments": {
            family: _consequence_assessment(family, status)
            for family, status in selected.items()
        },
        # The production helper must recover the installed declaration IDs if
        # matrix kind rows are missing or malformed; omission cannot erase a
        # package-global obligation.
        "kinds": {},
        "findings": [],
    }


def test_package_global_applicability_state_controls_zero_role_closure() -> None:
    subject = NamespaceObject.create("subject", "OBJECT", {})
    no_roles = SimpleNamespace(kinds=lambda _identifier: {"OBJECT"})
    robot_role = SimpleNamespace(kinds=lambda _identifier: {"OBJECT", "ROBOT"})

    unknown = coverage_checker._package_global_applicability_residuals(
        _consequence_matrix({"ROBOT": "UNKNOWN"}),
        {},
        no_roles,
        verifier_id="verifier",
    )
    assert {row["source_id"] for row in unknown} == {
        value for value in CONSEQUENCE_OBLIGATIONS if value.startswith("ROBOT-")
    }
    assert all(row["next_action"][:4] == [
        "vstd", "gate", "--object", "verifier",
    ] for row in unknown)

    condition_not_met = coverage_checker._package_global_applicability_residuals(
        _consequence_matrix({"ROBOT": "SOURCE_BOUND_CONDITION_NOT_MET"}),
        {},
        no_roles,
        verifier_id="verifier",
    )
    assert condition_not_met == []

    necessary_without_role = coverage_checker._package_global_applicability_residuals(
        _consequence_matrix({"ROBOT": "NECESSARY"}),
        {},
        no_roles,
        verifier_id="verifier",
    )
    assert len(necessary_without_role) == 3
    necessary_with_role = coverage_checker._package_global_applicability_residuals(
        _consequence_matrix({"ROBOT": "NECESSARY"}),
        {"subject": subject},
        robot_role,
        verifier_id="verifier",
    )
    assert necessary_with_role == []

    contradicted_refutation = coverage_checker._package_global_applicability_residuals(
        _consequence_matrix({"ROBOT": "SOURCE_BOUND_CONDITION_NOT_MET"}),
        {"subject": subject},
        robot_role,
        verifier_id="verifier",
    )
    assert len(contradicted_refutation) == 3


def test_malformed_or_forged_promotion_receipt_remains_unknown() -> None:
    subject = NamespaceObject.create("subject", "OBJECT", {})
    robot_role = SimpleNamespace(kinds=lambda _identifier: {"OBJECT", "ROBOT"})
    matrix = _consequence_matrix({"ROBOT": "NECESSARY"})
    matrix["package_instance_applicability_assessments"]["ROBOT"][
        "forged_real_effect_fields"
    ] = {"effect_domains": "REAL_PHYSICAL"}
    residuals = coverage_checker._package_global_applicability_residuals(
        matrix,
        {"subject": subject},
        robot_role,
        verifier_id="verifier",
    )
    assert len(residuals) == 3
    assert all("UNKNOWN applicability" in row["question"] for row in residuals)

    stale_refutation = _consequence_matrix({
        "ROBOT": "SOURCE_BOUND_CONDITION_NOT_MET",
    })
    stale_refutation["package_instance_applicability_assessments"]["ROBOT"][
        "source_bound_refutation_count"
    ] = 0
    residuals = coverage_checker._package_global_applicability_residuals(
        stale_refutation,
        {},
        robot_role,
        verifier_id="verifier",
    )
    assert len(residuals) == 3


def test_zero_effective_family_objects_keep_package_global_residuals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = NamespaceObject.create("verifier", "VERIFIER", {})
    objects = (verifier,)
    source_digest = "sha256:" + "5" * 64
    kinds = SimpleNamespace(
        registry=namespace_registry(),
        objects={verifier.object_id: verifier},
        declarations={
            verifier.object_id: {
                "kind": "VERIFIER", "surfaces": [], "classification": {},
            },
        },
        execution_mechanisms={verifier.object_id: frozenset()},
        report={"source_census_digest": source_digest},
        kinds=lambda _identifier: {"VERIFIER"},
        basis=lambda _identifier, kind: {
            "kind": kind,
            "declared": True,
            "necessity": "NECESSARY",
            "reasons": ["Synthetic zero-family package role basis."],
            "source_census_digest": source_digest,
        },
    )
    matrix = _consequence_matrix({
        "MARKET": "UNKNOWN",
        "ROBOT": "UNKNOWN",
        "FINBOT": "UNKNOWN",
    })
    monkeypatch.setattr(manifest_gate, "obligation_catalog", lambda: [])
    monkeypatch.setattr(
        package_contract_profiles,
        "contract_coverage_matrix",
        lambda: deepcopy(matrix),
    )

    report = coverage_checker.assess(
        1, objects, kinds, [], verifier_id=verifier.object_id
    )
    assert report["denominator_status"] == "PASS"
    assert report["expected_instance_count"] == 0
    assert report["status"] == "UNKNOWN"
    assert report["normative_coverage"] == "NOT_ESTABLISHED"
    contract = next(row for row in report["contracts"]
                    if row["object_id"] == verifier.object_id)
    residuals = {
        row["source_id"]: row for row in contract["residual_requirements"]
        if row["mechanism"] == (
            "verifier.runtime.package_contract_profiles."
            "reconcile_package_instance_applicability"
        )
    }
    assert set(residuals) == CONSEQUENCE_OBLIGATIONS
    assert all(
        row["next_action"][:4] == ["vstd", "gate", "--object", "verifier"]
        and "zero objects" in row["boundary"]
        for row in residuals.values()
    )
    validate_coverage(report)


def test_original_core_production_shape_uses_cell_bound_fresh_refutation(
    declared_package,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cell kind/tier now bind a conditional native route without widening it."""
    root, retained, _ = declared_package
    document = prepare(root, retained)
    objects = package.package_manifest.validate_bridge(document)
    kinds = KindRequirements(root, document["namespace"])
    source = package_source_contracts.SourceContractAssessment(root, objects, kinds)
    inventory = package.core_tier_progression.installed_core_route_inventory()
    declarations = package.core_tier_progression.installed_core_route_declarations()
    cell = next(
        row for row in inventory["family_cells"]
        if row["object_kind"] == "DATA" and row["tier"] == 1
    )
    membership = next(
        row for row in cell["registered_route_memberships"]
        if row["coordinate"] == "DATA-1.2"
    )
    production_route = {
        **membership,
        **declarations[("DATA", 1, "DATA-1.2")],
    }

    # This is the exact route mapping passed by production evaluation. The
    # containing cell, not caller-authored route fields, owns kind and tier.
    assert "object_kind" not in production_route
    assert "tier" not in production_route
    core_routes, _ = source._installed_core_runtime_routes()
    assert len(core_routes[("DATA", 1, "DATA-1.2")]) == 1
    item = next(row for row in objects if row.object_id == "vstd-data")
    # Isolate the repaired route-shape boundary from this old fixture's stale
    # source-review bytes. Production may reach this branch only after these
    # two predicates have independently established current adaptation PASS.
    monkeypatch.setattr(package_source_contracts, "applies_to", lambda *args: True)
    monkeypatch.setattr(
        source,
        "evaluate",
        lambda *args: {
            "status": "PASS",
            "result_digest": "sha256:" + "1" * 64,
        },
    )
    refutation = source.refute_native_runtime_variant(
        item,
        production_route,
        object_kind="DATA",
        tier=1,
    )
    assert refutation is not None
    assert refutation["status"] == "PASS"
    assert refutation["applicability_classification"] == "CONDITION_NOT_MET"
    assert refutation["fulfillment_required"] is False
    assert refutation["native_coordinate"] == "DATA-1.2"

    matrix = package_contract_profiles.contract_coverage_matrix()
    matrix_route = next(
        row for row in matrix["kinds"]["DATA"]["routes"]
        if row["coordinate"] == "DATA-1.2"
    )
    assert matrix_route["route_type"] == "NATIVE_RECHECKER"
    assert matrix_route["package_graph_reachability"] == "REQUIRES_FRESH_INSTANCE"
    assert matrix_route["package_instance_execution_status"] == "NOT_ASSESSED"
    assert matrix_route["source_variant_refutation_reachability"] \
        == "SOURCE_BOUND_CONDITION_NOT_MET_AVAILABLE_AFTER_FRESH_SOURCE_ADAPTATION"
    assert matrix_route["native_specimen_is_instance_evidence"] is False

    necessary = next(
        row for row in matrix["kinds"]["OBJECT"]["routes"]
        if row["coordinate"] == "OBJECT-1.1"
    )
    assert necessary["source_variant_refutation_reachability"] \
        == "PROHIBITED_FOR_NECESSARY"


def test_missing_accumulated_base_role_fails_with_object_kind_focus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = NamespaceObject.create("asset", "OBJECT", {"variant": "asset"})
    verifier = NamespaceObject.create("verifier", "VERIFIER", {})
    objects = (subject, verifier)
    registry = namespace_registry()
    kinds = SimpleNamespace(
        registry=registry,
        objects={subject.object_id: {}, verifier.object_id: {}},
        declarations={
            subject.object_id: {"kind": "ASSET", "surfaces": [], "classification": {}},
            verifier.object_id: {"kind": "VERIFIER", "surfaces": [], "classification": {}},
        },
        execution_mechanisms={
            subject.object_id: frozenset(), verifier.object_id: frozenset(),
        },
        report={"source_census_digest": "sha256:" + "3" * 64},
        kinds=lambda identifier: (
            {"ASSET"} if identifier == subject.object_id else {"VERIFIER"}
        ),
        basis=lambda _identifier, kind: {
            "kind": kind,
            "declared": True,
            "necessity": "NECESSARY",
            "reasons": ["Exact synthetic role basis for denominator challenge."],
            "source_census_digest": "sha256:" + "3" * 64,
        },
    )
    monkeypatch.setattr(package_source_contracts, "applies_to", lambda *args: False)
    monkeypatch.setattr(
        package_execution, "requires_route_assessment", lambda *args, **kwargs: False
    )
    monkeypatch.setattr(coverage_checker, "accepts_subject", lambda *args: False)

    assessed = coverage_checker.assess(
        1, objects, kinds, [], verifier_id=verifier.object_id
    )

    finding = next(
        row for row in assessed["findings"]
        if row["code"] == "PACKAGE_CONTRACT_ACCUMULATED_ROLE_MISSING"
    )
    assert assessed["status"] == assessed["denominator_status"] == "FAIL"
    assert finding["object_id"] == subject.object_id
    assert finding["obligation_id"] == "ASSET-ROLE-ACCUMULATION"
    assert "OBJECT" in finding["explanation"]
