"""Adversarial package-variant closure-profile regressions."""
from __future__ import annotations

from copy import deepcopy
from collections import Counter
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from verifier.core.namespace import ObjectKind
from verifier.runtime import package_contract_coverage as coverage
from verifier.runtime import package_contract_profiles as profiles
from verifier.runtime.namespace_contracts import namespace_registry, requirements_for
from verifier.runtime.tier_zero_profile import value_digest


ADDED = {
    "LEDGER", "TRANSACTION", "ASSET", "MARKET", "MEASUREMENT", "SENSOR",
    "CONTROLLER", "ACTUATOR", "PROTOCOL", "POLICY", "ROBOT", "FINBOT",
}
BASE_CORE = {kind.value for kind in ObjectKind}

# Literal per-module counts are the independent package-object denominator. They
# are written here rather than read back from the assessment under test, so an
# omitted or added review object changes a count and fails the comparison.
EXPECTED_REVIEW_MODULE_COUNTS = {
    "package_namespace_review": 8,
    "package_semantic_review_records": 13,
    "package_semantic_review_operations": 19,
    "package_semantic_review_subjects": 9,
    "package_semantic_review_verifier": 8,
    "package_semantic_review_scripts": 6,
    "package_semantic_review_admission": 13,
    "package_semantic_review_commands": 13,
    "package_semantic_review_hardware_cli": 5,
    "package_semantic_review_partitions": 319,
    "package_semantic_review_polish": 18,
    "package_semantic_review_self_polish": 14,
    "package_original_review_people": 7,
    "package_original_review_systems": 7,
    "package_original_review_computation": 7,
    "package_semantic_review_core": 1,
    "package_semantic_review_package_object": 1,
}
EXPECTED_REVIEW_OBJECT_TOTAL = 468

# The generic fallback that an added kind would silently inherit if it had no
# explicit exclusion table entry.
GENERIC_EXCLUSIONS = (
    "runtime-domain truth beyond the selected finite routes",
    "external authority",
    "release and deployment",
)


def _consequence_review(
    statuses: dict[str, str],
    *,
    kind: str = "ROBOT",
) -> dict[str, dict]:
    """Build a tiny source-owned review denominator for reconciliation tests."""
    registry = namespace_registry()
    review_kinds = tuple(
        selected for selected, contract in registry.items() if contract.obligations
    )
    result = {}
    for object_id, status in statuses.items():
        classification = {
            selected: {
                "status": "UNRESOLVED",
                "reason": object_id + " retains " + selected + " for review.",
                "evidence_paths": [],
            }
            for selected in review_kinds
        }
        classification[kind] = {
            "status": status,
            "reason": object_id + " has a source-specific " + status + " decision.",
            "evidence_paths": (
                [object_id + ".py"] if status != "UNRESOLVED" else []
            ),
        }
        declarations = {}
        if status == "APPLIES":
            for obligation in requirements_for(registry, (kind,)):
                if obligation["kind"] == kind:
                    declarations[obligation["id"]] = {
                        field: object_id + " declares " + field + "."
                        for field in obligation["declaration_fields"]
                    }
        result[object_id] = {
            "primary_kind": "OBJECT",
            "owned_paths": [object_id + ".py"],
            "classification": classification,
            "declarations": declarations,
            "claim_boundary": "Synthetic exact review boundary.",
        }
    return result


def _consequence_source_inventory(rows: dict[str, dict]) -> dict[str, str]:
    return {
        path: "sha256:" + "1" * 64
        for row in rows.values()
        for path in row["owned_paths"]
    }


def test_package_applicability_requires_exact_all_object_refutation() -> None:
    rows = _consequence_review({"a": "DOES_NOT_APPLY", "b": "DOES_NOT_APPLY"})
    expected = frozenset(rows)

    refuted = profiles.reconcile_package_instance_applicability(
        "ROBOT",
        rows,
        expected_object_ids=expected,
        source_inventory=_consequence_source_inventory(rows),
    )
    assert refuted["status"] == "SOURCE_BOUND_CONDITION_NOT_MET"
    assert refuted["object_denominator"] == 2
    assert refuted["does_not_apply_count"] == 2
    assert refuted["source_bound_refutation_count"] == 2
    assert refuted["carrier_count"] == 0
    assert refuted["source_binding_digest"].startswith("sha256:")

    missing = deepcopy(rows)
    missing.pop("b")
    reopened = profiles.reconcile_package_instance_applicability(
        "ROBOT",
        missing,
        expected_object_ids=expected,
        source_inventory=_consequence_source_inventory(missing),
    )
    assert reopened["status"] == "UNKNOWN"
    assert reopened["reason"].startswith("The exact package object denominator differs")


def test_package_applicability_applies_or_real_effect_selects_carrier() -> None:
    rows = _consequence_review({"a": "DOES_NOT_APPLY", "b": "APPLIES"})
    expected = frozenset(rows)
    selected = profiles.reconcile_package_instance_applicability(
        "ROBOT",
        rows,
        expected_object_ids=expected,
        source_inventory=_consequence_source_inventory(rows),
    )
    assert selected["status"] == "NECESSARY"
    assert selected["carriers"] == [
        {"object_id": "b", "basis": "SOURCE_CLASSIFICATION_APPLIES"}
    ]

    effect_rows = _consequence_review(
        {"a": "DOES_NOT_APPLY", "b": "DOES_NOT_APPLY"}
    )
    effect_rows["a"]["classification"]["ACTUATOR"] = {
        "status": "APPLIES",
        "reason": "a applies the simulated actuator role.",
        "evidence_paths": ["a.py"],
    }
    for obligation in requirements_for(namespace_registry(), ("ACTUATOR",)):
        if obligation["kind"] == "ACTUATOR":
            effect_rows["a"]["declarations"][obligation["id"]] = {
                field: "a declares " + field + "."
                for field in obligation["declaration_fields"]
            }
    effect_rows["a"]["declarations"]["ACTUATOR-0.1-command-to-effect"] = {
        "commands": "a declares commands.",
        "targets": "a declares targets.",
        "effect_domains": "REAL_PHYSICAL",
        "authority": "a declares authority.",
    }
    selected = profiles.reconcile_package_instance_applicability(
        "ROBOT",
        effect_rows,
        expected_object_ids=expected,
        source_inventory=_consequence_source_inventory(effect_rows),
    )
    assert selected["status"] == "NECESSARY"
    assert selected["carriers"] == [
        {"object_id": "a", "basis": "DECLARED_REAL_PHYSICAL_EFFECT"}
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        "extra-row-key",
        "unknown-obligation",
        "wrong-kind-obligation",
        "wrong-tier-obligation",
        "missing-declaration-field",
        "extra-declaration-field",
        "non-string-declaration",
        "blank-declaration",
        "duplicate-owned-path",
        "dependency-target-missing",
        "dependency-target-duplicated",
        "dependency-local-path-unowned",
        "dependency-evidence-path-unknown",
    ],
)
def test_malformed_review_rows_cannot_support_condition_not_met(
    mutation: str,
) -> None:
    rows = _consequence_review({"a": "DOES_NOT_APPLY", "b": "DOES_NOT_APPLY"})
    selected = rows["a"]
    if mutation == "extra-row-key":
        selected["forged_real_effect_fields"] = {
            "effect_domains": "REAL_PHYSICAL"
        }
    elif mutation == "unknown-obligation":
        selected["declarations"]["FORGED-0.1"] = {
            "effect_domains": "REAL_PHYSICAL"
        }
    elif mutation == "wrong-kind-obligation":
        obligation = next(
            row for row in requirements_for(namespace_registry(), ("MARKET",))
            if row["kind"] == "MARKET"
        )
        selected["declarations"][obligation["id"]] = {
            field: "forged" for field in obligation["declaration_fields"]
        }
    elif mutation == "wrong-tier-obligation":
        selected["declarations"]["ROBOT-1.1"] = {"agent": "forged"}
    else:
        selected["classification"]["ACTUATOR"] = {
            "status": "APPLIES",
            "reason": "a applies ACTUATOR.",
            "evidence_paths": ["a.py"],
        }
        for obligation in requirements_for(namespace_registry(), ("ACTUATOR",)):
            if obligation["kind"] == "ACTUATOR":
                selected["declarations"][obligation["id"]] = {
                    field: "a declares " + field + "."
                    for field in obligation["declaration_fields"]
                }
        declaration = selected["declarations"][
            "ACTUATOR-0.1-command-to-effect"
        ]
        if mutation == "missing-declaration-field":
            declaration.pop("authority")
        elif mutation == "extra-declaration-field":
            declaration["REAL_PHYSICAL"] = "forged"
        elif mutation == "non-string-declaration":
            declaration["effect_domains"] = ["REAL_PHYSICAL"]
        elif mutation == "blank-declaration":
            declaration["effect_domains"] = ""
        elif mutation == "duplicate-owned-path":
            selected["owned_paths"].append("a.py")
        else:
            selected["dependency_operands"] = {
                "protocol_exchange": {
                    "local_endpoint_paths": ["a.py"],
                    "target_evidence_paths": ["b.py"],
                    "targets": ["b"],
                    "reason": "Exact synthetic dependency.",
                }
            }
            dependency = selected["dependency_operands"]["protocol_exchange"]
            if mutation == "dependency-target-missing":
                dependency["targets"] = ["missing"]
            elif mutation == "dependency-target-duplicated":
                dependency["targets"] = ["b", "b"]
            elif mutation == "dependency-local-path-unowned":
                dependency["local_endpoint_paths"] = ["unowned.py"]
            elif mutation == "dependency-evidence-path-unknown":
                dependency["target_evidence_paths"] = ["unknown.py"]

    result = profiles.reconcile_package_instance_applicability(
        "ROBOT",
        rows,
        expected_object_ids=frozenset(rows),
        source_inventory=_consequence_source_inventory(rows),
    )

    assert result["status"] == "UNKNOWN"
    assert result["invalid_count"] == 1
    assert result["next_unresolved"] == "a"


def test_checker_or_specimen_execution_is_never_carrier_evidence() -> None:
    rows = _consequence_review({"a": "DOES_NOT_APPLY"})
    rows["a"]["native_specimen_execution_status"] = "PASS"
    rows["a"]["checking_mechanism"] = "example.passing_checker"

    result = profiles.reconcile_package_instance_applicability(
        "ROBOT",
        rows,
        expected_object_ids=frozenset(rows),
        source_inventory=_consequence_source_inventory(rows),
    )

    # Execution metadata is outside the exact review-row schema. It cannot
    # promote a carrier or support a family-wide refutation.
    assert result["status"] == "UNKNOWN"
    assert result["invalid_count"] == 1
    assert result["carrier_count"] == 0


def test_valid_dependency_operands_do_not_change_subject_applicability() -> None:
    rows = _consequence_review({"a": "DOES_NOT_APPLY", "b": "DOES_NOT_APPLY"})
    rows["a"]["dependency_operands"] = {
        "protocol_exchange": {
            "local_endpoint_paths": ["a.py"],
            "target_evidence_paths": ["b.py"],
            "targets": ["b"],
            "reason": "Exact synthetic dependency without role transfer.",
        }
    }

    result = profiles.reconcile_package_instance_applicability(
        "ROBOT",
        rows,
        expected_object_ids=frozenset(rows),
        source_inventory=_consequence_source_inventory(rows),
    )

    assert result["status"] == "SOURCE_BOUND_CONDITION_NOT_MET"
    assert result["invalid_count"] == 0
    assert result["carrier_count"] == 0


def test_duplicate_owned_coordinate_across_objects_stays_unknown() -> None:
    rows = _consequence_review({"a": "DOES_NOT_APPLY", "b": "DOES_NOT_APPLY"})
    rows["b"]["owned_paths"] = ["a.py"]
    rows["b"]["classification"]["ROBOT"]["evidence_paths"] = ["a.py"]

    result = profiles.reconcile_package_instance_applicability(
        "ROBOT",
        rows,
        expected_object_ids=frozenset(rows),
        source_inventory=_consequence_source_inventory(rows),
    )

    assert result["status"] == "UNKNOWN"
    assert result["invalid_count"] == 2
    assert result["source_bound_refutation_count"] == 0


def test_duplicate_object_id_across_review_modules_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import package_manifest_migration as migration

    rows = _consequence_review({"dup": "DOES_NOT_APPLY"})
    first = SimpleNamespace(review_document=lambda: deepcopy(rows))
    second = SimpleNamespace(review_document=lambda: deepcopy(rows))
    monkeypatch.setattr(migration, "_PACKAGE_REVIEW_MODULES", (first, second))

    with pytest.raises(
        ValueError,
        match="PACKAGE_INSTANCE_APPLICABILITY_REVIEW_OVERLAP:dup",
    ):
        profiles._source_owned_package_review()


def test_graph_hashing_occurs_only_at_applicability_promotion_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def snapshot(_root, rows):
        calls.append(tuple(sorted(rows)))
        return _consequence_source_inventory(rows)

    monkeypatch.setattr(profiles, "_package_review_source_snapshot", snapshot)
    unresolved = _consequence_review({"a": "UNRESOLVED", "b": "UNRESOLVED"})
    monkeypatch.setattr(
        profiles, "_source_owned_package_review", lambda: deepcopy(unresolved)
    )
    result = profiles._package_instance_applicability_assessments()
    assert calls == []
    assert {row["status"] for row in result.values()} == {"UNKNOWN"}

    refuted = _consequence_review(
        {"a": "DOES_NOT_APPLY", "b": "DOES_NOT_APPLY"}
    )
    monkeypatch.setattr(
        profiles, "_source_owned_package_review", lambda: deepcopy(refuted)
    )
    result = profiles._package_instance_applicability_assessments()
    assert len(calls) == 2
    assert result["ROBOT"]["status"] == "SOURCE_BOUND_CONDITION_NOT_MET"

    calls.clear()
    carrier = _consequence_review({"a": "APPLIES", "b": "UNRESOLVED"})
    monkeypatch.setattr(
        profiles, "_source_owned_package_review", lambda: deepcopy(carrier)
    )
    result = profiles._package_instance_applicability_assessments()
    assert len(calls) == 2
    assert result["ROBOT"]["status"] == "NECESSARY"


def test_changed_opening_and_closing_source_binding_reopens_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    carrier = _consequence_review({"a": "APPLIES", "b": "UNRESOLVED"})
    calls = []

    def changing_snapshot(_root, rows):
        calls.append(None)
        digit = "1" if len(calls) == 1 else "2"
        return {
            path: "sha256:" + digit * 64
            for row in rows.values()
            for path in row["owned_paths"]
        }

    monkeypatch.setattr(
        profiles, "_source_owned_package_review", lambda: deepcopy(carrier)
    )
    monkeypatch.setattr(
        profiles, "_package_review_source_snapshot", changing_snapshot
    )

    result = profiles._package_instance_applicability_assessments()

    assert len(calls) == 2
    assert {row["status"] for row in result.values()} == {"UNKNOWN"}


def test_family_refutation_without_current_source_binding_stays_unknown() -> None:
    rows = _consequence_review({"a": "DOES_NOT_APPLY"})

    result = profiles.reconcile_package_instance_applicability(
        "ROBOT", rows, expected_object_ids=frozenset(rows)
    )

    assert result["status"] == "UNKNOWN"
    assert result["does_not_apply_count"] == 1
    assert result["invalid_count"] == 1
    assert result["source_bound_refutation_count"] == 0
    assert result["source_binding_digest"] is None


def test_profile_registry_is_exactly_38_kinds_and_self_bound() -> None:
    document = profiles.document()
    assert document["schema_version"] == profiles.SCHEMA
    assert set(document["profiles"]) == set(namespace_registry())
    assert len(document["profiles"]) == 38
    assert document["document_digest"] == value_digest({
        key: value for key, value in document.items() if key != "document_digest"
    })
    assert {kind for kind, row in document["profiles"].items()
            if len(row["family_obligation_route_mapping"]) == 3} == ADDED
    assert sum(len(routes) for row in document["profiles"].values()
               for routes in row["behavioral_routes"].values()) == 179


def test_base_core_and_package_kind_denominators_are_an_exact_partition() -> None:
    """The 26-kind wire registry is a base partition, never total package scope."""
    document = profiles.document()
    denominators = document["kind_denominators"]

    assert profiles.BASE_CORE_KIND_COUNT == 26
    assert profiles.PACKAGE_ADDED_KIND_COUNT == 12
    assert profiles.PACKAGE_KIND_COUNT == 38
    assert set(denominators["base_core_kinds"]) == BASE_CORE
    assert set(denominators["package_added_kinds"]) == ADDED
    assert set(denominators["package_kinds"]) == BASE_CORE | ADDED
    assert not (BASE_CORE & ADDED)
    assert denominators == {
        "base_core_kind_count": 26,
        "base_core_kind_scope": "RETAINED_OBJECT_KIND_WIRE",
        "base_core_kinds": sorted(BASE_CORE),
        "package_added_kind_count": 12,
        "package_added_kinds": sorted(ADDED),
        "package_kind_count": 38,
        "package_kind_scope": "INSTALLED_PACKAGE_NAMESPACE",
        "package_kinds": sorted(BASE_CORE | ADDED),
        "partition_status": "EXACT_DISJOINT_UNION",
    }

    matrix = profiles.contract_coverage_matrix()
    assert matrix["kind_denominators"] == denominators
    assert matrix["base_core_route_denominator"] == 194
    assert matrix["package_added_route_denominator"] == 99
    assert matrix["route_denominator"] == 293


def test_profile_constructor_rejects_object_kind_enum_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A self-consistent profile table cannot silently replace the core enum."""
    substituted = [SimpleNamespace(value=kind) for kind in sorted(BASE_CORE)]
    substituted[-1] = SimpleNamespace(value="SUBSTITUTED_CORE_KIND")
    monkeypatch.setattr(profiles, "ObjectKind", substituted)

    with pytest.raises(
        ValueError,
        match="PACKAGE_CONTRACT_PROFILE_OBJECT_KIND_ENUM_DIFFERS",
    ):
        profiles.document()


def test_package_review_observer_receipt_binds_exact_source_coordinate() -> None:
    receipt = profiles._PACKAGE_REVIEW_COORDINATE_RECEIPT
    root = Path(profiles.__file__).resolve().parents[3]

    assert receipt["expected_source_coordinate_digest"] == (
        "sha256:734ee3544cb81511d9abe4c8e0a8dc5d3675fd5c01dd6e125b3e61d32fc1b0be"
    )
    for relative, expected in receipt["source_digests"].items():
        assert "sha256:" + sha256((root / relative).read_bytes()).hexdigest() == expected
    assert len(profiles._source_owned_package_review()) == EXPECTED_REVIEW_OBJECT_TOTAL


def test_checking_mechanism_resolution_is_the_closed_installed_graph() -> None:
    runtime = "verifier.runtime.tier_zero.assess_tier_zero"
    native = (
        "verifier.domains.contracts.object_facets."
        "recheck_object_facets_certificate"
    )
    added = (
        "verifier.domains.contracts.agency_surface."
        "recheck_agency_surface_certificate"
    )
    assert callable(profiles._checking_mechanism_callable(runtime))
    assert callable(profiles._checking_mechanism_callable(native))
    assert callable(profiles._checking_mechanism_callable(added))
    assert profiles._checking_mechanism_callable("json.loads") is None
    assert profiles._checking_mechanism_callable("selected.module.call") is None
    assert profiles._callable_mechanism("json.loads") is False


def test_package_review_observer_coordinate_drift_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        profiles._PACKAGE_REVIEW_COORDINATE_RECEIPT,
        "expected_source_coordinate_digest",
        "sha256:" + "0" * 64,
    )

    with pytest.raises(
        ValueError,
        match="PACKAGE_INSTANCE_APPLICABILITY_REVIEW_COORDINATE_DIFFERS",
    ):
        profiles._source_owned_package_review()


@pytest.mark.parametrize("partition", ["base_core_kinds", "package_added_kinds"])
def test_count_preserving_kind_partition_substitution_fails_closed(
    partition: str,
) -> None:
    candidate = deepcopy(profiles.contract_coverage_matrix())
    selected = candidate["kind_denominators"][partition]
    selected[-1] = (
        "ASSET" if partition == "base_core_kinds" else "OBJECT"
    )

    audited = profiles.audit_contract_coverage_matrix(candidate)

    assert audited["status"] == "FAIL"
    assert any(
        finding["code"] == "PACKAGE_CONTRACT_MATRIX_KIND_PARTITION_DIFFERS"
        for finding in audited["findings"]
    )


def test_cumulative_coordinates_never_drop_lower_tiers() -> None:
    for kind in namespace_registry():
        previous: set[str] = set()
        for tier in (1, 2, 3):
            current = set(profiles.required_coordinates(kind, tier) or ())
            assert previous < current
            assert {f"{kind}-{depth}.90" for depth in range(1, tier + 1)} <= current
            assert all(int(value.split("-", 1)[1].split(".", 1)[0]) <= tier
                       for value in current)
            previous = current


def test_source_prefix_alone_cannot_erase_behavioral_routes() -> None:
    kinds = SimpleNamespace(registry=namespace_registry())
    for kind in namespace_registry():
        clauses = [{"coordinate": f"{kind}-{tier}.90", "closure_status": "PASS",
                    "checking_mechanism": "source"} for tier in (1, 2, 3)]
        residuals = coverage._residuals(kind, 3, kinds, {}, clauses)
        required_behavior = set(profiles.required_coordinates(kind, 3) or ()) - {
            f"{kind}-{tier}.90" for tier in (1, 2, 3)
        }
        assert required_behavior
        route_residuals = [
            row for row in residuals
            if row["source"] == "installed-package-variant-profile"
        ]
        assert {row["source_id"] for row in route_residuals} == required_behavior
        assert all(row["status"] == "UNKNOWN" for row in route_residuals)


def test_unprofiled_local_extension_is_not_borrowed() -> None:
    assert profiles.profile("LOCALPOLICY") is None
    assert profiles.required_coordinates("LOCALPOLICY", 3) is None


def test_added_obligation_mapping_is_tier_exact() -> None:
    registry = namespace_registry()
    for kind in ADDED:
        profile = profiles.profile(kind)
        assert profile is not None
        obligations = [row.id for row in registry[kind].obligations]
        assert list(profile["family_obligation_route_mapping"]) == obligations
        for tier, obligation in enumerate(obligations, start=1):
            assert profile["family_obligation_route_mapping"][obligation] \
                == [profile["source_routes"][str(tier)],
                    *profile["behavioral_routes"][str(tier)]]


def test_every_source_mapping_uses_the_exact_gate_obligation_identifier() -> None:
    """A reported mapping key must select one real gate row, not a tier-collapsed alias."""
    from verifier.runtime import package_source_contracts

    source_rows = {
        row["coordinate"]: row for row in package_source_contracts.catalog()
    }
    assert len(source_rows) == 114
    for kind in namespace_registry():
        selected = profiles.profile(kind)
        assert selected is not None
        assert len(selected["obligation_route_mapping"]) == 3
        for obligation_id, coordinates in selected["obligation_route_mapping"].items():
            assert len(coordinates) == 1
            coordinate = coordinates[0]
            assert source_rows[coordinate]["obligation_id"] == obligation_id


def test_count_preserving_source_gate_identifier_substitution_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import package_source_contracts

    original = package_source_contracts.catalog

    def substituted() -> list[dict]:
        rows = deepcopy(original())
        rows[0]["obligation_id"] = "SUBSTITUTED-SOURCE-GATE-OBLIGATION"
        return rows

    monkeypatch.setattr(package_source_contracts, "catalog", substituted)
    with pytest.raises(
        ValueError,
        match="PACKAGE_CONTRACT_PROFILE_SOURCE_GATE_MAPPING_DIFFERS",
    ):
        profiles.document()


def test_contract_matrix_binds_exact_tier_zero_through_three_denominator() -> None:
    matrix = profiles.contract_coverage_matrix()

    assert matrix["status"] == "UNKNOWN"
    assert matrix["findings"] == []
    assert matrix["kind_denominator"] == 38
    assert matrix["repository_admission_obligation_denominator"] == 9
    assert matrix["profile_obligation_denominator"] == 62
    assert matrix["family_obligation_denominator"] == 71
    assert matrix["defined_obligation_denominator"] == 364
    assert matrix["route_denominator"] == 293
    assert set(matrix["kinds"]) == set(namespace_registry())
    assert sum(len(row["profile_obligations"])
               for row in matrix["kinds"].values()) == 62
    routes = [route for row in matrix["kinds"].values()
              for route in row["routes"]]
    assert len(routes) == 293
    repository_admission = matrix["repository_admission_obligations"]
    assert [row["coordinate"] for row in repository_admission] == [
        f"VSTD-T0.{index}" for index in range(1, 10)
    ]
    assert all(
        row["tier"] == 0
        and row["reason"].strip()
        and row["mechanism_status"] == "CALLABLE"
        and row["applicability"]["mode"] == "NECESSARY"
        and row["applicability"]["unknown_condition"] == "NOT_EXEMPT"
        and row["package_graph_reachability"]
            == "REQUIRES_FRESH_POLISH_0_REPOSITORY_ADMISSION"
        and row["native_specimen_is_instance_evidence"] is False
        for row in repository_admission
    )
    family_obligation_ids = {
        row["obligation_id"] for row in repository_admission
    } | {
        obligation["obligation_id"]
        for row in matrix["kinds"].values()
        for obligation in row["profile_obligations"]
    }
    route_obligation_ids = {route["obligation_id"] for route in routes}
    assert len(family_obligation_ids) == 71
    assert len(route_obligation_ids) == 293
    assert len(family_obligation_ids | route_obligation_ids) == 364
    assert sum(route["route_type"] == "SOURCE_ADAPTER" for route in routes) == 114
    assert Counter(route["route_type"] for route in routes) == {
        "SOURCE_ADAPTER": 114,
        "NATIVE_RECHECKER": 113,
        "PACKAGE_EXECUTION_ADAPTER": 45,
        "ADDED_KIND_BEHAVIORAL": 21,
    }
    assert all(route["catalog_presence"] == "PRESENT_NOT_CONFORMANCE"
               and route["mechanism_status"] == "CALLABLE"
               and route["package_graph_reachability"] == "REQUIRES_FRESH_INSTANCE"
               and route["package_instance_execution_status"] == "NOT_ASSESSED"
               and route["native_specimen_is_instance_evidence"] is False
               and route["reason"].strip()
               and route["applicability"]["mode"] in {"NECESSARY", "CONDITIONAL"}
               and route["applicability"]["reason"].strip()
               for route in routes)
    assert all(
        route["refutation_route"]["status"]
        == ("SOURCE_BOUND_CONDITION_NOT_MET" if route["applicability"]["mode"] == "CONDITIONAL"
            else "PROHIBITED_FOR_NECESSARY")
        for route in routes
    )
    assert matrix["semantic_mapping_status"] == "UNKNOWN"
    established = {
        "LEDGER-0.2-accounting-invariants",
        "MEASUREMENT-0.2-units-time-and-uncertainty",
        "SENSOR-0.2-calibration-and-envelope",
        "CONTROLLER-0.3-intervention-and-failure",
        "PROTOCOL-0.1-participants-and-states",
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
    obligations = {
        obligation["obligation_id"]: obligation
        for row in matrix["kinds"].values()
        for obligation in row["profile_obligations"]
    }
    field_rows = [
        field
        for obligation in obligations.values()
        if obligation["declaration_field_evidence"] is not None
        for field in obligation["declaration_field_evidence"]["field_bindings"]
    ]
    assert len(field_rows) == 145
    audited_field_counts = Counter(
        binding["status"]
        for fields in profiles._DECLARATION_FIELD_BINDINGS.values()
        for binding in fields.values()
    )
    # POLICY reconciliation: scope M->P (route scope is fixture-bound), and four
    # MISSING POLICY fields become PARTIAL with the route self-declarations.
    assert audited_field_counts == {
        "MECHANIZED": 78,
        "PARTIAL": 31,
        "PRESENCE_ONLY": 2,
        "BOUNDARY_EXCLUDED": 14,
        "MISSING": 20,
    }
    # Concurrent checker edits deliberately reopen pinned M rows rather than
    # silently inheriting the prior audit.  The static adjudication denominator
    # stays exact while current evidence separates still-bound M from drift.
    current_field_counts = Counter(row["status"] for row in field_rows)
    assert current_field_counts["MECHANIZED"] \
        + current_field_counts["UNKNOWN_SOURCE_OR_ROUTE_DRIFT"] == 78
    assert {
        status: current_field_counts[status]
        for status in ("PARTIAL", "PRESENCE_ONLY", "BOUNDARY_EXCLUDED", "MISSING")
    } == {
        "PARTIAL": 31,
        "PRESENCE_ONLY": 2,
        "BOUNDARY_EXCLUDED": 14,
        "MISSING": 20,
    }
    field_unknowns = {
        obligation_id for obligation_id, obligation in obligations.items()
        if obligation["unmapped_declaration_fields"]
    }
    audited_field_unknowns = {
        obligation_id
        for obligation_id, fields in profiles._DECLARATION_FIELD_BINDINGS.items()
        if any(binding["status"] != "MECHANIZED" for binding in fields.values())
    }
    assert len(audited_field_unknowns) == 30
    assert audited_field_unknowns <= field_unknowns
    for obligation_id in field_unknowns - audited_field_unknowns:
        assert "UNKNOWN_SOURCE_OR_ROUTE_DRIFT" in {
            row["status"] for row in obligations[obligation_id][
                "unmapped_declaration_fields"
            ]
        }
    assert {
        row["obligation_id"] for row in matrix["semantic_mapping_blockers"]
    } == field_unknowns
    for obligation_id in established:
        evidence = obligations[obligation_id]["semantic_mapping_evidence"]
        expected_status = (
            "UNKNOWN"
            if (
                obligation_id in field_unknowns
                or evidence["status"] == "UNKNOWN"
            )
            else "SOURCE_BOUND_EXECUTABLE_MAPPING_NOT_CONFORMANCE"
        )
        assert obligations[obligation_id]["semantic_mapping_status"] \
            == expected_status
        assert evidence["status"] in {
            "UNKNOWN",
            "SOURCE_BOUND_EXECUTABLE_MAPPING_NOT_CONFORMANCE",
        }
        assert evidence["route_coordinate"].split("-", 1)[0] \
            == obligation_id.split("-", 1)[0]
        assert evidence["route_binding_digest"].startswith("sha256:")
        assert evidence["source_binding_digest"].startswith("sha256:")
        assert evidence["evidence_digest"] == value_digest({
            key: value for key, value in evidence.items()
            if key != "evidence_digest"
        })
    applicability_obligations = {
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
    assert matrix["package_instance_applicability_status"] == "NECESSARY"
    assert matrix["package_instance_applicability_blockers"] == []
    assert all(
        obligations[obligation_id]["package_instance_applicability_status"]
        == "NECESSARY_SOURCE_BOUND_PACKAGE_CARRIER"
        for obligation_id in applicability_obligations
    )
    assessments = matrix["package_instance_applicability_assessments"]
    assert set(assessments) == {"MARKET", "ROBOT", "FINBOT"}
    expected_counts = {
        "MARKET": (15, 15, 363, 90),
        "ROBOT": (15, 15, 363, 90),
        "FINBOT": (16, 16, 364, 88),
    }
    for kind, assessment in assessments.items():
        assert assessment["kind"] == kind
        assert assessment["status"] == "NECESSARY"
        assert assessment["object_denominator"] == EXPECTED_REVIEW_OBJECT_TOTAL
        assert assessment["object_denominator"] == (
            assessment["reviewed_object_count"] + assessment["invalid_count"]
        )
        assert assessment["reviewed_object_count"] == (
            assessment["applies_count"]
            + assessment["does_not_apply_count"]
            + assessment["unresolved_count"]
        )
        assert (
            assessment["applies_count"],
            assessment["carrier_count"],
            assessment["does_not_apply_count"],
            assessment["unresolved_count"],
        ) == expected_counts[kind]
        assert assessment["invalid_count"] == 0
        assert assessment["evidence_digest"] == value_digest({
            key: value for key, value in assessment.items()
            if key != "evidence_digest"
        })
    assert matrix["production_preflight_status"] \
        == "BOUNDED_ROUTE_BINDING_AVAILABLE"
    assert matrix["production_preflight_blockers"] == []
    assert matrix["production_preflight_route_summary"] == {
        "native_route_count": 113,
        "conditional_source_refutation_available": 112,
        "necessary_source_refutation_prohibited": 1,
        "necessary_coordinate": "OBJECT-1.1",
        "claim_boundary": matrix["production_preflight_route_summary"][
            "claim_boundary"
        ],
    }
    assert matrix["production_preflight_route_summary"]["claim_boundary"].strip()
    assert sum(
        route["source_variant_refutation_reachability"]
        == "SOURCE_BOUND_CONDITION_NOT_MET_AVAILABLE_AFTER_FRESH_SOURCE_ADAPTATION"
        for route in routes
    ) == 112
    necessary_native = [
        route for route in routes
        if route["route_type"] == "NATIVE_RECHECKER"
        and route["source_variant_refutation_reachability"]
            == "PROHIBITED_FOR_NECESSARY"
    ]
    assert [route["coordinate"] for route in necessary_native] == ["OBJECT-1.1"]
    assert matrix["matrix_digest"] == value_digest({
        key: value for key, value in matrix.items() if key != "matrix_digest"
    })


def _review_module_counts(modules: tuple | None = None) -> dict[str, int]:
    """Count each review module's objects directly, not through the assessment."""
    from verifier.runtime import package_manifest_migration

    selected = (
        package_manifest_migration._PACKAGE_REVIEW_MODULES
        if modules is None else modules
    )
    return {
        module.__name__.rsplit(".", 1)[-1]: len(module.review_document())
        for module in selected
    }


def test_package_review_denominator_matches_literal_module_counts() -> None:
    counts = _review_module_counts()
    assert counts == EXPECTED_REVIEW_MODULE_COUNTS
    assert sum(counts.values()) == EXPECTED_REVIEW_OBJECT_TOTAL == 468


@pytest.mark.parametrize("mutation", ["omit", "add"])
def test_review_denominator_check_detects_omission_and_addition(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    from verifier.runtime import package_manifest_migration

    module = package_manifest_migration.package_semantic_review_core
    original = module.review_document()
    if mutation == "omit":
        candidate = {}
    else:
        candidate = {**original, "synthetic-added-review-object": next(iter(original.values()))}
    monkeypatch.setattr(module, "review_document", lambda: candidate)

    counts = _review_module_counts()
    assert counts != EXPECTED_REVIEW_MODULE_COUNTS
    assert sum(counts.values()) != EXPECTED_REVIEW_OBJECT_TOTAL


def test_every_added_kind_has_explicit_bounded_exclusions_not_generic_fallback() -> None:
    for kind in sorted(ADDED):
        assert kind in profiles._EXCLUSIONS, kind
        row = profiles.profile(kind)
        assert row is not None, kind
        assert row["bounded_exclusions"] == list(profiles._EXCLUSIONS[kind]), kind
        assert row["bounded_exclusions"] != list(GENERIC_EXCLUSIONS), kind


def test_transaction_exclusions_bound_external_authority_atomicity_retry_and_money() -> None:
    """Each nonclaim is grounded in TRANSACTION's declared effect, failure and retry semantics."""
    exclusions = " ".join(profiles._EXCLUSIONS["TRANSACTION"]).lower()
    for phrase in (
        "external legal authorization",
        "real external atomicity",
        "finality",
        "compensation",
        "rollback",
        "retry",
        "backoff",
        "exhaustion",
        "real-money",
        "settlement",
        "accumulated financial role",
    ):
        assert phrase in exclusions, phrase
    assert "not promoted" in profiles.profile("TRANSACTION")["claim_boundary"]


def test_every_route_is_necessary_or_conditional_and_added_kinds_keep_object_base() -> None:
    matrix = profiles.contract_coverage_matrix()
    routes = [route for row in matrix["kinds"].values() for route in row["routes"]]
    modes = Counter(route["applicability"]["mode"] for route in routes)
    assert sum(modes.values()) == 293
    assert set(modes) <= {"NECESSARY", "CONDITIONAL"}
    assert modes["OPTIONAL"] == 0
    for kind in sorted(ADDED):
        roles = matrix["kinds"][kind]["accumulated_roles"]
        assert roles[0] == kind and roles[-1] == "OBJECT", kind


@pytest.mark.parametrize(
    ("drift", "expected_phrase"),
    [("route", "route binding"), ("source", "selected source differs")],
)
def test_semantic_mapping_source_drift_reopens_exact_unknown(
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
    expected_phrase: str,
) -> None:
    """A declaration family cannot retain credit after its audited route drifts."""
    obligation_id = "LEDGER-0.2-accounting-invariants"
    binding = profiles._SEMANTIC_MAPPING_BINDINGS[obligation_id]
    if drift == "route":
        monkeypatch.setitem(
            binding,
            "route_binding_digest",
            "sha256:" + "0" * 64,
        )
    else:
        path = "src/verifier/runtime/local_ledger_execution.py"
        monkeypatch.setitem(
            binding["source_digests"],
            path,
            "sha256:" + "0" * 64,
        )

    matrix = profiles.contract_coverage_matrix()
    obligation = next(
        row for row in matrix["kinds"]["LEDGER"]["profile_obligations"]
        if row["obligation_id"] == obligation_id
    )
    blocker = next(
        row for row in matrix["semantic_mapping_blockers"]
        if row["obligation_id"] == obligation_id
    )

    assert profiles.semantic_mapping_blocker(obligation_id) == blocker["reason"]
    assert obligation["semantic_mapping_status"] == "UNKNOWN"
    assert obligation["semantic_mapping_evidence"]["status"] == "UNKNOWN"
    assert expected_phrase in blocker["reason"].lower()


_COMPOSITION_OBLIGATION = "ROBOT-0.1-agent-to-actuator-binding"
_MAPPING_DRIFT = "MAPPING-DRIFT-REASON"
_FIELD_DRIFT = "FIELD-DRIFT-REASON"


@pytest.mark.parametrize(
    ("mapping_drift", "field_drift", "expected"),
    [
        (False, False, None),
        (True, False, _MAPPING_DRIFT),
        (False, True, _FIELD_DRIFT),
        (True, True, _MAPPING_DRIFT + " " + _FIELD_DRIFT),
    ],
)
def test_semantic_blocker_composes_mapping_then_field_like_the_matrix(
    monkeypatch: pytest.MonkeyPatch,
    mapping_drift: bool,
    field_drift: bool,
    expected: str | None,
) -> None:
    """The public helper and the matrix share one order and never drop a reason."""
    real_mapping = profiles._semantic_mapping_evidence
    real_fields = profiles.declaration_field_evidence

    def mapping(target: str, *args: object, **kwargs: object):
        if target != _COMPOSITION_OBLIGATION:
            return real_mapping(target, *args, **kwargs)
        if mapping_drift:
            return {"status": "UNKNOWN", "reason": _MAPPING_DRIFT}
        return {
            "status": "SOURCE_BOUND_EXECUTABLE_MAPPING_NOT_CONFORMANCE",
            "reason": "clean mapping",
        }

    def fields(target: str, *args: object, **kwargs: object):
        if target != _COMPOSITION_OBLIGATION:
            return real_fields(target, *args, **kwargs)
        if field_drift:
            return {
                "status": "UNKNOWN",
                "reason": _FIELD_DRIFT,
                "unmapped_declaration_fields": [],
            }
        return {
            "status": "BOUNDED",
            "reason": "clean fields",
            "unmapped_declaration_fields": [],
        }

    monkeypatch.setattr(profiles, "_semantic_mapping_evidence", mapping)
    monkeypatch.setattr(profiles, "declaration_field_evidence", fields)
    matrix = profiles.contract_coverage_matrix()
    matrix_blockers = {
        row["obligation_id"]: row["reason"]
        for row in matrix["semantic_mapping_blockers"]
    }

    assert profiles.semantic_mapping_blocker(_COMPOSITION_OBLIGATION) == expected
    assert matrix_blockers.get(_COMPOSITION_OBLIGATION) == expected


def test_semantic_blocker_helper_equals_matrix_for_every_obligation() -> None:
    """Both public surfaces read one composition, so no obligation can diverge."""
    matrix = profiles.contract_coverage_matrix()
    matrix_blockers = {
        row["obligation_id"]: row["reason"]
        for row in matrix["semantic_mapping_blockers"]
    }
    obligation_ids = {
        obligation.id
        for contract in namespace_registry().values()
        for obligation in contract.obligations
    } | set(profiles._SEMANTIC_MAPPING_BINDINGS)

    assert sorted(
        obligation_id for obligation_id in obligation_ids
        if profiles.semantic_mapping_blocker(obligation_id)
        != matrix_blockers.get(obligation_id)
    ) == []


def test_denominator_diagnostics_name_the_exact_current_counts() -> None:
    candidate = deepcopy(profiles.contract_coverage_matrix())
    candidate["kinds"]["ASSET"]["routes"].pop(0)

    audited = profiles.audit_contract_coverage_matrix(candidate)
    findings = {row["code"]: row["reason"] for row in audited["findings"]}
    routes = profiles.MATRIX_ROUTE_DENOMINATOR
    defined = profiles.MATRIX_DEFINED_OBLIGATION_DENOMINATOR

    assert (routes, defined) == (293, 364)
    assert findings["PACKAGE_CONTRACT_MATRIX_ROUTE_DENOMINATOR_DIFFERS"] == (
        f"The exact {routes} Tier 1-3 coordinates are not unique and complete."
    )
    assert findings["PACKAGE_CONTRACT_MATRIX_ROUTE_OBLIGATION_DENOMINATOR_DIFFERS"] == (
        f"The exact {routes} numbered route-obligation identifiers are not unique and complete."
    )
    assert findings["PACKAGE_CONTRACT_MATRIX_DEFINED_OBLIGATION_DENOMINATOR_DIFFERS"] == (
        f"The exact {defined} repository, family, and numbered route obligations "
        "are not unique and complete."
    )
    diagnostic_texts = [
        findings[code] for code in (
            "PACKAGE_CONTRACT_MATRIX_ROUTE_DENOMINATOR_DIFFERS",
            "PACKAGE_CONTRACT_MATRIX_ROUTE_OBLIGATION_DENOMINATOR_DIFFERS",
            "PACKAGE_CONTRACT_MATRIX_DEFINED_OBLIGATION_DENOMINATOR_DIFFERS",
        )
    ]
    assert not any("290" in text or "361" in text for text in diagnostic_texts)


@pytest.mark.parametrize(
    "path",
    [
        "src/verifier/runtime/package_execution.py",
        "src/verifier/runtime/local_ledger_execution.py",
        "src/verifier/runtime/local_ledger_control_checks.py",
        "src/verifier/runtime/local_ledger_controls.py",
        "src/verifier/runtime/local_ledger_worker.py",
        "src/verifier/runtime/polish_invocation_ledger.py",
    ],
)
def test_ledger_semantic_mapping_binds_every_executed_source(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    """Every producer, predicate, worker, envelope and subject pin is live."""
    obligation_id = "LEDGER-0.2-accounting-invariants"
    binding = profiles._SEMANTIC_MAPPING_BINDINGS[obligation_id]
    monkeypatch.setitem(binding["source_digests"], path, "sha256:" + "0" * 64)

    evidence = profiles._semantic_mapping_evidence(obligation_id)

    assert evidence is not None
    assert evidence["status"] == "UNKNOWN"
    assert "selected source differs: " + path in evidence["reason"]


@pytest.mark.parametrize(
    ("pin", "expected_phrase"),
    [
        ("proposition_digest", "proposition digest differs"),
        ("catalog_mechanism_digest", "catalog mechanism digest differs"),
    ],
)
def test_ledger_semantic_claim_and_mechanism_pins_reopen_unknown(
    monkeypatch: pytest.MonkeyPatch,
    pin: str,
    expected_phrase: str,
) -> None:
    obligation_id = "LEDGER-0.2-accounting-invariants"
    binding = profiles._SEMANTIC_MAPPING_BINDINGS[obligation_id]
    monkeypatch.setitem(binding, pin, "sha256:" + "0" * 64)

    evidence = profiles._semantic_mapping_evidence(obligation_id)

    assert evidence is not None
    assert evidence["status"] == "UNKNOWN"
    assert expected_phrase in evidence["reason"]


def test_declaration_field_bindings_match_every_exact_installed_field() -> None:
    registry = namespace_registry()
    expected = {
        obligation.id: set(obligation.declaration_fields)
        for kind in profiles._ADDED_ROUTES
        for obligation in registry[kind].obligations
    }
    assert len(expected) == 36
    assert sum(len(fields) for fields in expected.values()) == 145
    assert set(profiles._DECLARATION_FIELD_BINDINGS) == set(expected)
    assert all(
        set(profiles._DECLARATION_FIELD_BINDINGS[obligation_id]) == fields
        for obligation_id, fields in expected.items()
    )


def test_transaction_retry_limits_are_mechanized_by_all_four_tier_three_routes() -> None:
    """No Tier-2 retry probe or status-table edit can substitute for all Tier-3 routes."""
    obligation_id = "TRANSACTION-0.3-retry-and-replay"
    evidence = profiles.declaration_field_evidence(obligation_id)

    assert evidence is not None
    assert evidence["status"] == "BOUNDED"
    assert evidence["status_counts"] == {"MECHANIZED": 4}
    assert evidence["unmapped_declaration_fields"] == []
    retry = next(row for row in evidence["field_bindings"]
                 if row["field"] == "retry_limits")
    assert retry["status"] == "MECHANIZED"
    assert set(retry["route_coordinates"]) == {
        "TRANSACTION-3.1", "TRANSACTION-3.2",
        "TRANSACTION-3.3", "TRANSACTION-3.4",
    }
    assert "outside these fresh bounded processes remain unestablished" in retry["reason"]
    assert {
        row["path"] for row in evidence["supporting_source_bindings"]
    } == {
        "src/verifier/runtime/local_ledger_controls.py",
        "src/verifier/runtime/local_ledger_worker.py",
        "src/verifier/runtime/manifest_write_worker.py",
        "src/verifier/runtime/namespace_admission.py",
        "src/verifier/runtime/namespace_cli.py",
        "src/verifier/runtime/package_execution.py",
        "src/verifier/runtime/polish_invocation_ledger.py",
    }


def test_measurement_observation_vs_estimate_is_mechanized_without_claiming_physical_truth() -> None:
    """The software-counter boundary closes while the open SIM identity seam stays explicit."""
    obligation_id = "MEASUREMENT-0.1-phenomenon-and-method"
    evidence = profiles.declaration_field_evidence(obligation_id)

    assert evidence is not None
    assert evidence["status"] == "BOUNDED"
    assert evidence["status_counts"] == {"MECHANIZED": 4}
    assert evidence["unmapped_declaration_fields"] == []
    observation = next(
        row for row in evidence["field_bindings"]
        if row["field"] == "observation_vs_estimate"
    )
    assert observation["status"] == "MECHANIZED"
    assert observation["route_coordinates"] == ["MEASUREMENT-1.1"]
    assert "OBSERVATION_OF_SOFTWARE_COUNTERS" in observation["reason"]
    assert "physical accuracy" in observation["reason"]
    assert {
        row["path"] for row in evidence["supporting_source_bindings"]
    } == {
        "src/verifier/domains/contracts/sim_fresh_bootstrap.py",
        "src/verifier/domains/contracts/sim_fresh_worker.py",
        "src/verifier/domains/contracts/sim_resource_fresh.py",
        "src/verifier/runtime/package_execution.py",
        "src/verifier/runtime/resource_measurement_worker.py",
    }
    receipts = profiles._SOURCE_CHANGE_RECEIPTS
    for path in (
        "src/verifier/domains/contracts/sim_fresh_bootstrap.py",
        "src/verifier/domains/contracts/sim_fresh_worker.py",
        "src/verifier/domains/contracts/sim_resource_fresh.py",
    ):
        assert receipts[path]["decision"] == "ACCEPTED"
    assert any(
        "SIM-2.4" in boundary
        for boundary in receipts[
            "src/verifier/domains/contracts/sim_resource_fresh.py"
        ]["not_established"]
    )


def test_missing_binding_stays_unknown_and_bogus_field_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    obligation_id = "PROTOCOL-0.2-ordering-and-replay"
    monkeypatch.delitem(profiles._DECLARATION_FIELD_BINDINGS, obligation_id)
    missing = profiles.declaration_field_evidence(obligation_id)
    assert missing is not None
    assert missing["status"] == "UNKNOWN"
    assert {row["status"] for row in missing["unmapped_declaration_fields"]} \
        == {"DECLARATION_FIELDS_UNBOUND"}

    monkeypatch.setitem(
        profiles._DECLARATION_FIELD_BINDINGS,
        obligation_id,
        {
            **profiles._expand_declaration_field_bindings()[obligation_id],
            "forged_effect_field": {
                "status": "MECHANIZED",
                "reason": "Forged field must not widen the declaration.",
                "route_coordinates": ["PROTOCOL-2.1", "PROTOCOL-2.2"],
                "evidence_selector": "ROUTE_CHECKING_MECHANISM_SOURCE",
            },
        },
    )
    with pytest.raises(
        ValueError,
        match="PACKAGE_CONTRACT_DECLARATION_FIELD_KEYS_DIFFER",
    ):
        profiles.declaration_field_evidence(obligation_id)


@pytest.mark.parametrize("drift", ["route", "source"])
def test_declaration_field_source_or_route_drift_reopens_mechanized_fields(
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    obligation_id = "MARKET-0.1-orders-and-access"
    if drift == "route":
        monkeypatch.setitem(
            profiles._DECLARATION_FIELD_ROUTE_DIGESTS,
            obligation_id,
            "sha256:" + "0" * 64,
        )
    else:
        path = "src/verifier/domains/contracts/market_checks.py"
        monkeypatch.setitem(
            profiles._DECLARATION_FIELD_SOURCE_DIGESTS,
            path,
            "sha256:" + "0" * 64,
        )
    evidence = profiles.declaration_field_evidence(obligation_id)
    assert evidence is not None
    assert evidence["status"] == "UNKNOWN"
    assert {row["status"] for row in evidence["field_bindings"]} \
        == {"UNKNOWN_SOURCE_OR_ROUTE_DRIFT"}
    assert evidence["unmapped_declaration_fields"] == evidence["field_bindings"]


@pytest.mark.parametrize(
    "path",
    [
        "src/verifier/runtime/package_execution.py",
        "src/verifier/runtime/local_ledger_execution.py",
        "src/verifier/runtime/local_ledger_control_checks.py",
        "src/verifier/runtime/local_ledger_controls.py",
        "src/verifier/runtime/local_ledger_worker.py",
        "src/verifier/runtime/polish_invocation_ledger.py",
    ],
)
@pytest.mark.parametrize(
    "obligation_id",
    [
        "LEDGER-0.1-authoritative-history",
        "LEDGER-0.2-accounting-invariants",
        "LEDGER-0.3-correction-and-recovery",
    ],
)
def test_ledger_field_audit_binds_every_transitive_execution_source(
    monkeypatch: pytest.MonkeyPatch,
    obligation_id: str,
    path: str,
) -> None:
    monkeypatch.setitem(
        profiles._DECLARATION_FIELD_SOURCE_DIGESTS,
        path,
        "sha256:" + "0" * 64,
    )

    evidence = profiles.declaration_field_evidence(obligation_id)

    assert evidence is not None
    assert evidence["status"] == "UNKNOWN"
    assert any(
        row["path"] == path and row["required_sha256"] == "sha256:" + "0" * 64
        for row in evidence["supporting_source_bindings"]
    ) or path == "src/verifier/runtime/local_ledger_execution.py"
    assert all(
        row["status"] == "UNKNOWN_SOURCE_OR_ROUTE_DRIFT"
        for row in evidence["field_bindings"]
        if profiles._DECLARATION_FIELD_BINDINGS[obligation_id][row["field"]][
            "status"
        ] == "MECHANIZED"
    )
    assert all(
        row["status"] == profiles._DECLARATION_FIELD_BINDINGS[obligation_id][
            row["field"]
        ]["status"]
        for row in evidence["field_bindings"]
        if profiles._DECLARATION_FIELD_BINDINGS[obligation_id][row["field"]][
            "status"
        ] != "MECHANIZED"
    )


@pytest.mark.parametrize(
    ("kind", "obligation_id"),
    [
        ("MARKET", "MARKET-0.2-matching-and-allocation"),
        ("ROBOT", "ROBOT-0.2-physical-reach-and-observation"),
        ("FINBOT", "FINBOT-0.2-financial-exposure-and-dependencies"),
    ],
)
@pytest.mark.parametrize(
    ("mutation", "expected_phrase"),
    [
        ("route", "route binding digest differs"),
        ("proposition", "proposition digest differs"),
        ("mechanism", "catalog mechanism digest differs"),
        ("source", "selected source differs"),
    ],
)
def test_consequential_semantic_mapping_pins_reopen_unknown_on_drift(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    obligation_id: str,
    mutation: str,
    expected_phrase: str,
) -> None:
    """Repinning changed bytes cannot promote them into semantic proof."""
    binding = profiles._SEMANTIC_MAPPING_BINDINGS[obligation_id]
    if mutation == "route":
        monkeypatch.setitem(binding, "route_binding_digest", "sha256:" + "0" * 64)
    elif mutation == "proposition":
        monkeypatch.setitem(binding, "proposition_digest", "sha256:" + "0" * 64)
    elif mutation == "mechanism":
        monkeypatch.setitem(binding, "catalog_mechanism_digest", "sha256:" + "0" * 64)
    else:
        checker_path = next(iter(profiles._ADDED_KIND_CHECKER_SOURCE_DIGESTS[kind]))
        monkeypatch.setitem(binding["source_digests"], checker_path, "sha256:" + "0" * 64)

    evidence = profiles._semantic_mapping_evidence(obligation_id)

    assert evidence is not None
    assert evidence["status"] == "UNKNOWN"
    assert expected_phrase in evidence["reason"]


def test_consequential_field_statuses_preserve_external_unknowns() -> None:
    """Retained-record coverage remains distinct from real-world truth."""
    expected = {
        "MARKET-0.2-matching-and-allocation": {
            "matching": "MECHANIZED",
            "price_formation": "PARTIAL",
            "allocation": "MECHANIZED",
            "manipulation_controls": "PARTIAL",
        },
        "MARKET-0.3-settlement-and-disruption": {
            "settlement_dependencies": "PARTIAL",
            "finality": "MECHANIZED",
            "participant_failure": "PARTIAL",
            "disruption": "MECHANIZED",
        },
        "ROBOT-0.2-physical-reach-and-observation": {
            "physical_reach": "PARTIAL",
            "observations": "PARTIAL",
            "domain_crossings": "MECHANIZED",
            "confinement_evidence": "BOUNDARY_EXCLUDED",
        },
        "FINBOT-0.1-agent-and-financial-authority": {
            "agent": "MECHANIZED",
            "harness": "MECHANIZED",
            "decision_scope": "MECHANIZED",
            "financial_authority": "PRESENCE_ONLY",
        },
        "FINBOT-0.2-financial-exposure-and-dependencies": {
            "assets_and_parties": "PARTIAL",
            "financial_dependencies": "MECHANIZED",
            "real_world_paths": "PARTIAL",
            "exposure_limits": "MECHANIZED",
        },
        "FINBOT-0.3-decisions-effects-and-recovery": {
            "decision_effect_evidence": "PARTIAL",
            "limit_enforcement": "PARTIAL",
            "intervention": "MECHANIZED",
            "reconciliation_and_recovery": "PARTIAL",
        },
    }
    for obligation_id, statuses in expected.items():
        evidence = profiles.declaration_field_evidence(obligation_id)
        assert evidence is not None
        source_or_route_drift = (
            evidence["route_binding_digest"]
                != evidence["required_route_binding_digest"]
            or evidence["source_binding_digest"]
                != evidence["required_source_binding_digest"]
        )
        current = {
            row["field"]: row["status"]
            for row in evidence["field_bindings"]
        }
        assert current == {
            field: (
                "UNKNOWN_SOURCE_OR_ROUTE_DRIFT"
                if status == "MECHANIZED" and source_or_route_drift
                else status
            )
            for field, status in statuses.items()
        }
        assert evidence["status"] == "UNKNOWN"


def test_ledger_field_statuses_preserve_external_accounting_boundaries() -> None:
    expected = {
        "LEDGER-0.1-authoritative-history": {
            "history": "MECHANIZED",
            "state": "MECHANIZED",
            "ordering": "MECHANIZED",
            "authority": "BOUNDARY_EXCLUDED",
        },
        "LEDGER-0.2-accounting-invariants": {
            "units": "MECHANIZED",
            "balance_rules": "MECHANIZED",
            "rounding": "MECHANIZED",
            "sources_and_sinks": "MECHANIZED",
        },
        "LEDGER-0.3-correction-and-recovery": {
            "corrections": "MECHANIZED",
            "replay": "MECHANIZED",
            "reconciliation": "PARTIAL",
            "recovery": "PARTIAL",
        },
    }
    for obligation_id, statuses in expected.items():
        evidence = profiles.declaration_field_evidence(obligation_id)
        assert evidence is not None
        source_or_route_drift = (
            evidence["route_binding_digest"]
                != evidence["required_route_binding_digest"]
            or evidence["source_binding_digest"]
                != evidence["required_source_binding_digest"]
        )
        current = {
            row["field"]: row["status"]
            for row in evidence["field_bindings"]
        }
        assert current == {
            field: (
                "UNKNOWN_SOURCE_OR_ROUTE_DRIFT"
                if status == "MECHANIZED" and source_or_route_drift
                else status
            )
            for field, status in statuses.items()
        }
        assert evidence["status"] == (
            "BOUNDED"
            if (
                not source_or_route_drift
                and set(statuses.values()) == {"MECHANIZED"}
            )
            else "UNKNOWN"
        )
        assert all(row["reason"].strip() for row in evidence["field_bindings"])


def test_ledger_exclusions_name_every_external_overclaim_boundary() -> None:
    exclusions = " ".join(profiles._EXCLUSIONS["LEDGER"]).lower()
    for phrase in (
        "real balances",
        "real settlement",
        "independent operator authority",
        "power-loss durability",
        "external reconciliation",
    ):
        assert phrase in exclusions


@pytest.mark.parametrize(
    ("obligation_id", "field"),
    sorted(profiles._BOUNDARY_STATUS_PINS),
)
def test_consequential_external_boundary_fields_reject_mechanized_overclaim(
    monkeypatch: pytest.MonkeyPatch,
    obligation_id: str,
    field: str,
) -> None:
    binding = profiles._DECLARATION_FIELD_BINDINGS[obligation_id][field]
    monkeypatch.setitem(binding, "status", "MECHANIZED")

    with pytest.raises(
        ValueError,
        match="PACKAGE_CONTRACT_DECLARATION_FIELD_BOUNDARY_OVERCLAIMED",
    ):
        profiles.declaration_field_evidence(obligation_id)


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("kind", "PACKAGE_CONTRACT_MATRIX_KIND_MISSING"),
        ("obligation", "PACKAGE_CONTRACT_MATRIX_OBLIGATION_MISSING"),
        (
            "repository_obligation",
            "PACKAGE_CONTRACT_MATRIX_REPOSITORY_ADMISSION_MISSING",
        ),
        ("route", "PACKAGE_CONTRACT_MATRIX_ROUTE_MISSING"),
        ("mechanism", "PACKAGE_CONTRACT_MATRIX_MECHANISM_MISSING"),
        ("reason", "PACKAGE_CONTRACT_MATRIX_REASON_MISSING"),
        ("applicability", "PACKAGE_CONTRACT_MATRIX_APPLICABILITY_INVALID"),
        (
            "execution_overclaim",
            "PACKAGE_CONTRACT_MATRIX_INSTANCE_EXECUTION_OVERCLAIMED",
        ),
        ("accumulated_role", "PACKAGE_CONTRACT_MATRIX_ACCUMULATED_ROLE_DIFFERS"),
        ("synthetic_only", "PACKAGE_CONTRACT_MATRIX_SYNTHETIC_ONLY_ROUTE"),
    ],
)
def test_contract_matrix_adversarial_omissions_fail_with_exact_focus(
    mutation: str,
    expected_code: str,
) -> None:
    candidate = deepcopy(profiles.contract_coverage_matrix())
    asset = candidate["kinds"]["ASSET"]
    if mutation == "kind":
        candidate["kinds"].pop("ASSET")
    elif mutation == "obligation":
        asset["profile_obligations"].pop(0)
    elif mutation == "repository_obligation":
        candidate["repository_admission_obligations"].pop(0)
    elif mutation == "route":
        asset["routes"].pop(0)
    elif mutation == "mechanism":
        asset["routes"][0]["checking_mechanism"] = ""
    elif mutation == "reason":
        asset["routes"][0]["reason"] = ""
    elif mutation == "applicability":
        asset["routes"][0]["applicability"]["mode"] = "OPTIONAL"
    elif mutation == "execution_overclaim":
        asset["routes"][0]["package_instance_execution_status"] = "PASS"
    elif mutation == "accumulated_role":
        asset["accumulated_roles"].remove("OBJECT")
    else:
        forged = deepcopy(asset["routes"][0])
        forged.update(
            coordinate="ASSET-1.999",
            obligation_id="ASSET-1.999-synthetic-specimen-only",
            catalog_presence="PRESENT_NOT_CONFORMANCE",
        )
        asset["routes"].append(forged)

    audited = profiles.audit_contract_coverage_matrix(candidate)

    assert audited["status"] == "FAIL"
    finding = next(row for row in audited["findings"]
                   if row["code"] == expected_code)
    assert finding["kind"] == (
        None if mutation == "repository_obligation" else "ASSET"
    )
    assert finding["status"] == "FAIL"
    assert finding["reason"].strip()
    assert finding["next_action"] == ["vstd", "polish", "3"]


def _source_pin_occurrences() -> list[tuple[str, str]]:
    """Every source digest pinned anywhere in the profile tables, as (path, digest)."""
    pairs: list[tuple[str, str]] = []
    for name in ("_ADDED_KIND_SEMANTIC_SOURCE_DIGESTS", "_DECLARATION_FIELD_SOURCE_DIGESTS"):
        pairs.extend(getattr(profiles, name).items())
    for mapping in profiles._ADDED_KIND_CHECKER_SOURCE_DIGESTS.values():
        pairs.extend(mapping.items())
    for binding in profiles._SEMANTIC_MAPPING_BINDINGS.values():
        pairs.extend(binding["source_digests"].items())
    return pairs


def test_source_change_receipts_bind_every_pinned_digest() -> None:
    """An aggregate repin without a recorded receipt fails here, not silently."""
    receipts = profiles._SOURCE_CHANGE_RECEIPTS
    used: dict[str, set[str]] = {}
    for path, digest in _source_pin_occurrences():
        used.setdefault(path, set()).add(digest)

    assert set(used) == set(receipts)
    for path, receipt in receipts.items():
        assert receipt["decision"] in {"ACCEPTED", "UNCHANGED", "UNKNOWN", "REJECTED"}, path
        assert used[path] == set(receipt["pinned_sha256"]), path


def test_unchanged_and_accepted_receipts_equal_current_bytes() -> None:
    root = Path(profiles.__file__).resolve().parents[3]
    for path, receipt in profiles._SOURCE_CHANGE_RECEIPTS.items():
        if receipt["decision"] not in {"ACCEPTED", "UNCHANGED"}:
            continue
        current = "sha256:" + sha256((root / path).read_bytes()).hexdigest()
        assert current == receipt["observed_sha256"], path
        assert receipt["pinned_sha256"] == (current,), path


def test_accepted_receipts_name_their_boundaries() -> None:
    for path, receipt in profiles._SOURCE_CHANGE_RECEIPTS.items():
        if receipt["decision"] == "ACCEPTED":
            assert receipt["evidence"].strip(), path
            assert receipt["not_established"], path


@pytest.mark.parametrize(
    ("coordinate", "obligation_id"),
    [
        ("MARKET-2.1", "MARKET-0.2-matching-and-allocation"),
        ("MARKET-3.1", "MARKET-0.3-settlement-and-disruption"),
        ("FINBOT-1.1", "FINBOT-0.1-agent-and-financial-authority"),
    ],
)
def test_route_binding_drift_is_exactly_the_mechanism_digest_field(
    coordinate: str,
    obligation_id: str,
) -> None:
    """Forged old/new variants: only the mechanism_digest projection field differs."""
    from verifier.runtime import added_kind_behavioral_routes

    binding = profiles._SEMANTIC_MAPPING_BINDINGS[obligation_id]
    route = next(
        row for row in added_kind_behavioral_routes.catalog()
        if row["coordinate"] == coordinate
    )
    current = {field: route[field] for field in profiles._ROUTE_BINDING_FIELDS}
    old_variant = {**current, "mechanism_digest": binding["catalog_mechanism_digest"]}

    assert value_digest(old_variant) == binding["route_binding_digest"]
    assert value_digest(current) != binding["route_binding_digest"]
    assert current["mechanism_digest"] != binding["catalog_mechanism_digest"]
    assert all(
        current[field] == old_variant[field]
        for field in profiles._ROUTE_BINDING_FIELDS
        if field != "mechanism_digest"
    )
    evidence = profiles._semantic_mapping_evidence(obligation_id)
    assert evidence is not None
    assert evidence["status"] == "UNKNOWN"


@pytest.mark.parametrize(
    ("coordinate", "obligation_id"),
    [
        ("MARKET-1.1", "MARKET-0.1-orders-and-access"),
        ("ROBOT-1.1", "ROBOT-0.1-agent-to-actuator-binding"),
    ],
)
def test_reviewed_tier_one_route_binds_the_reproducible_current_mechanism(
    coordinate: str,
    obligation_id: str,
) -> None:
    """The accepted current route is exact without claiming legacy equivalence."""
    from verifier.runtime import added_kind_behavioral_routes

    binding = profiles._SEMANTIC_MAPPING_BINDINGS[obligation_id]
    route = next(
        row for row in added_kind_behavioral_routes.catalog()
        if row["coordinate"] == coordinate
    )
    current = {
        field: route[field] for field in profiles._ROUTE_BINDING_FIELDS
    }

    assert value_digest(current) == binding["route_binding_digest"]
    assert current["mechanism_digest"] == binding["catalog_mechanism_digest"]
    evidence = profiles._semantic_mapping_evidence(obligation_id)
    assert evidence is not None
    assert evidence["status"] == (
        "SOURCE_BOUND_EXECUTABLE_MAPPING_NOT_CONFORMANCE"
    )


def test_package_execution_route_catalog_is_pinned_while_transport_changes() -> None:
    """Execution transport may change; the 45 route predicates and ceilings may not, silently."""
    from verifier.runtime import package_execution

    catalog = package_execution.catalog()
    assert len(catalog) == 45
    assert value_digest(catalog) == (
        "sha256:a2c69df733042d148601e8c0c4284a66762aa6dafda0a67cedd798967978f445"
    )


def test_document_scope_builds_the_installed_profile_document_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One command asks for a profile thousands of times; only the first may rebuild it."""
    from verifier.runtime import package_source_contracts

    real = package_source_contracts.catalog
    built = []

    def counting() -> list[dict]:
        built.append(1)
        return real()

    monkeypatch.setattr(package_source_contracts, "catalog", counting)
    with profiles.document_scope():
        first = profiles.profile("ASSET")
        for _ in range(5):
            assert profiles.profile("ASSET") == first
        assert profiles.document()["profiles"]["ASSET"] == first
    assert len(built) == 1

    built.clear()
    profiles.profile("ASSET")
    profiles.profile("ASSET")
    assert len(built) == 2, "outside a scope every call revalidates the installed sources"


def test_document_scope_returns_independent_copies_and_expires(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with profiles.document_scope():
        selected = profiles.profile("ASSET")
        selected["source_routes"]["1"] = "MUTATED"
        document = profiles.document()
        document["profiles"]["ASSET"]["source_routes"]["2"] = "MUTATED"
        assert profiles.profile("ASSET")["source_routes"]["1"] != "MUTATED"
        assert profiles.profile("ASSET")["source_routes"]["2"] != "MUTATED"
        with profiles.document_scope():  # nested scopes share the outer snapshot
            assert profiles.profile("ASSET")["source_routes"]["1"] != "MUTATED"

    from verifier.runtime import package_source_contracts

    real = package_source_contracts.catalog

    def substituted() -> list[dict]:
        rows = deepcopy(real())
        rows[0]["obligation_id"] = "SUBSTITUTED-SOURCE-GATE-OBLIGATION"
        return rows

    monkeypatch.setattr(package_source_contracts, "catalog", substituted)
    with pytest.raises(ValueError, match="PACKAGE_CONTRACT_PROFILE_SOURCE_GATE_MAPPING_DIFFERS"):
        profiles.profile("ASSET")
    with pytest.raises(ValueError, match="PACKAGE_CONTRACT_PROFILE_SOURCE_GATE_MAPPING_DIFFERS"):
        with profiles.document_scope():
            profiles.profile("ASSET")


def test_document_scope_never_caches_a_refused_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from verifier.runtime import package_source_contracts

    real = package_source_contracts.catalog
    calls = []

    def flaky() -> list[dict]:
        calls.append(1)
        rows = deepcopy(real())
        if len(calls) == 1:
            rows[0]["obligation_id"] = "SUBSTITUTED-SOURCE-GATE-OBLIGATION"
        return rows

    monkeypatch.setattr(package_source_contracts, "catalog", flaky)
    with profiles.document_scope():
        with pytest.raises(ValueError):
            profiles.profile("ASSET")
        assert profiles.profile("ASSET") is not None
