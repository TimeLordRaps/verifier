"""Package integration regressions for MARKET, ROBOT, and FINBOT routes.

These tests exercise only catalog assembly, denominator preflight, focused
instance evaluation, and contract-profile aggregation.  They never actuate a
physical endpoint, submit a market order, move money, or run root-level polish.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_package_kind_requirements import prepare
from test_package_polish import declared_package
from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import agency_surface
from verifier.runtime import added_kind_behavioral_routes as behavioral_routes
from verifier.runtime import core_obligation_union as binding
from verifier.runtime import manifest_gate
from verifier.runtime import package_contract_coverage as coverage_checker
from verifier.runtime import package_contract_profiles as contract_profiles
from verifier.runtime import package_polish as package
from verifier.runtime import package_source_contracts as source_contracts
from verifier.runtime.namespace_contracts import namespace_registry
from verifier.runtime.package_kind_requirements import KindRequirements
from verifier.runtime.tier_zero_profile import value_digest


KINDS = ("MARKET", "ROBOT", "FINBOT")
COORDINATES = {
    f"{kind}-{tier}.1"
    for kind in KINDS
    for tier in (1, 2, 3)
}
AGENCY_COORDINATES = {
    "BOT-1.7", "BOT-2.6", "BOT-3.5",
    "ROBOT-1.2", "ROBOT-2.2", "ROBOT-3.2",
    "FINBOT-1.2", "FINBOT-2.2", "FINBOT-3.2",
}
POLICY_COORDINATES = {"POLICY-1.3", "POLICY-2.3", "POLICY-3.3"}
KIND_MECHANISMS = {
    "MARKET": "verifier.domains.contracts.market_checks.recheck_market_checks_certificate",
    "ROBOT": "verifier.domains.contracts.robot_checks.recheck_robot_checks_certificate",
    "FINBOT": "verifier.domains.contracts.finbot_checks.recheck_finbot_checks_certificate",
}


def _source_representation(
    monkeypatch: pytest.MonkeyPatch,
    root: Path,
    kind: str,
) -> tuple[NamespaceObject, SimpleNamespace, source_contracts.SourceContractAssessment]:
    """Build one exact owned-source variant, not a runtime-domain subject."""

    object_id = "fixture-" + kind.lower() + "-source"
    root.mkdir(parents=True, exist_ok=True)
    source_path = root / "fixture.py"
    source_path.write_text(
        "# Source representation only; this file must never execute.\n"
        "raise RuntimeError('source representation executed')\n",
        encoding="utf-8",
    )
    digest = binding.bytes_digest(source_path.read_bytes())
    contract = namespace_registry()[kind]
    declarations = {
        obligation.id: {
            field: obligation.id + ":" + field
            for field in obligation.declaration_fields
        }
        for obligation in contract.obligations
    }
    review = {
        "primary_kind": "OBJECT",
        "owned_paths": ["fixture.py"],
        "classification": {
            kind: {
                "status": "APPLIES",
                "reason": "The exact fixture source represents " + kind + ".",
                "evidence_paths": ["fixture.py"],
            }
        },
        "declarations": declarations,
        "claim_boundary": "Fixture source representation only.",
    }
    monkeypatch.setattr(source_contracts, "_review_catalog", lambda: {object_id: review})
    monkeypatch.setattr(source_contracts, "_INSTALLED_REVIEWS", {object_id: review})
    monkeypatch.setattr(
        source_contracts,
        "_INSTALLED_REVIEW_IDS",
        frozenset({object_id}),
    )
    surfaces = [
        {
            "surface_id": "file:fixture.py",
            "path": "fixture.py",
            "line": 1,
            "form": "file",
            "source_kinds": [],
            "hints": [],
            "unresolved_marker": False,
        },
        {
            "surface_id": "python:fixture.py:<module>",
            "path": "fixture.py",
            "line": 1,
            "form": "Module",
            "source_kinds": [],
            "hints": [],
            "unresolved_marker": False,
        },
    ]
    declaration = {
        "object_id": object_id,
        "kind": "OBJECT",
        "surfaces": [row["surface_id"] for row in surfaces],
        "classification": {
            kind: {
                "status": "APPLIES",
                "reason": "The exact fixture source represents " + kind + ".",
                "evidence": [{"path": "fixture.py", "sha256": digest}],
            }
        },
        "obligations": {
            obligation_id: {
                "reason": "Fixture reason for " + obligation_id,
                "evidence": [{"path": "fixture.py", "sha256": digest}],
                "declaration": deepcopy(declaration_fields),
            }
            for obligation_id, declaration_fields in declarations.items()
        },
        "specializations": [kind],
    }
    item = NamespaceObject.create(
        object_id,
        "OBJECT",
        {"representation_role": kind.lower() + "-source"},
    )
    source_census_digest = value_digest({"fixture.py": digest})
    kinds = SimpleNamespace(
        registry=namespace_registry(),
        declarations={object_id: declaration},
        census={"files": [{"path": "fixture.py", "sha256": digest}]},
        observed={
            "surfaces": surfaces,
            "gaps": [],
            "source_import_bindings": [],
            "export_bindings": [],
        },
        report={"source_census_digest": source_census_digest},
        execution_mechanisms={object_id: frozenset()},
        kinds=lambda selected: {"OBJECT", kind},
        basis=lambda selected, selected_kind: {
            "kind": selected_kind,
            "declared": selected_kind in {"OBJECT", kind},
            "necessity": "NECESSARY",
            "reasons": ["Exact fixture source role."],
            "source_census_digest": source_census_digest,
        },
    )
    return item, kinds, source_contracts.SourceContractAssessment(
        root,
        (item,),
        kinds,
    )


def test_added_kind_routes_partition_exactly_into_disjoint_producers() -> None:
    installed = [
        row
        for row in manifest_gate.obligation_catalog()
        if behavioral_routes.is_route(row)
    ]
    assert installed == behavioral_routes.catalog()
    coordinates = [row["coordinate"] for row in installed]
    assert len(coordinates) == len(set(coordinates)) == 21
    assert len({row["obligation_id"] for row in installed}) == len(installed)

    # Three disjoint producers: the MARKET/ROBOT/FINBOT .1 kind routes, the
    # agency-surface routes, and the POLICY enforcement routes.
    assert len(COORDINATES) == 9
    assert len(AGENCY_COORDINATES) == 9
    assert len(POLICY_COORDINATES) == 3
    assert not (COORDINATES & AGENCY_COORDINATES)
    assert not (COORDINATES & POLICY_COORDINATES)
    assert not (AGENCY_COORDINATES & POLICY_COORDINATES)
    assert set(coordinates) == (
        COORDINATES | AGENCY_COORDINATES | POLICY_COORDINATES
    )
    assert AGENCY_COORDINATES == {
        row["coordinate"] for row in agency_surface.catalog()
    }
    bot_extension_coordinates = {"BOT-1.7", "BOT-2.6", "BOT-3.5"}
    assert bot_extension_coordinates <= set(coordinates)
    assert bot_extension_coordinates <= {
        route
        for routes in contract_profiles.profile("BOT")["behavioral_routes"].values()
        for route in routes
    }
    assert bot_extension_coordinates <= {
        route["coordinate"]
        for route in contract_profiles.contract_coverage_matrix()["kinds"]["BOT"]["routes"]
    }

    for row in installed:
        coordinate = row["coordinate"]
        assert coordinate.split("-")[0] == row["object_kind"]
        assert coordinate.split("-")[1].split(".")[0] == str(row["tier"])
        if coordinate in AGENCY_COORDINATES:
            expected = (
                "verifier-retained-agency-surface-1",
                "verifier.domains.contracts.agency_surface.recheck_agency_surface_certificate",
            )
        elif coordinate in POLICY_COORDINATES:
            expected = (
                "verifier-retained-policy-enforcement-1",
                "verifier.runtime.added_kind_behavioral_routes.recheck_policy_enforcement_certificate",
            )
        else:
            expected = (
                "verifier-retained-added-kind-behavioral-1",
                KIND_MECHANISMS[row["object_kind"]],
            )
        assert (row["adapter"], row["checking_mechanism"]) == expected

    for kind in KINDS:
        profile = contract_profiles.profile(kind)
        assert profile is not None
        for tier in (1, 2, 3):
            # Each tier may carry several added-kind routes (kind plus agency),
            # so the profile is pinned to the exact set, not one coordinate.
            expected_routes = {
                row["coordinate"]
                for row in installed
                if row["object_kind"] == kind and row["tier"] == tier
            }
            route_list = profile["behavioral_routes"][str(tier)]
            assert len(route_list) == len(set(route_list))
            assert set(route_list) == expected_routes
            required = contract_profiles.required_coordinates(kind, tier)
            assert required is not None
            assert len(required) == len(set(required))
            assert set(required) == {
                profile["source_routes"][str(depth)]
                for depth in range(1, tier + 1)
            } | {
                row["coordinate"]
                for row in installed
                if row["object_kind"] == kind and row["tier"] <= tier
            }


def test_effective_robot_and_finbot_roles_enter_preflight_denominator(
    declared_package,
) -> None:
    root, retained, _ = declared_package
    document = prepare(root, retained)
    objects = package.package_manifest.validate_bridge(document)
    kinds = KindRequirements(root, document["namespace"])
    _cells, selected = package._obligation_selection_preflight(
        3,
        objects,
        kinds,
        COORDINATES,
    )
    bot = next(
        row["object_id"]
        for row in document["namespace"]["objects"]
        if row["kind"] == "BOT"
    )
    agent = next(
        row["object_id"]
        for row in document["namespace"]["objects"]
        if row["kind"] == "AGENT"
    )
    added = [row for row in selected if row["coordinate"] in COORDINATES]

    assert {(row["object_id"], row["object_kind"]) for row in added} == {
        (bot, "ROBOT"),
        (bot, "FINBOT"),
        (agent, "ROBOT"),
        (agent, "FINBOT"),
    }
    assert {(row["object_kind"], row["coordinate"]) for row in added} == {
        (kind, f"{kind}-{tier}.1")
        for kind in ("ROBOT", "FINBOT")
        for tier in (1, 2, 3)
    }
    assert len(added) == 12


@pytest.mark.parametrize("kind", KINDS)
def test_source_representations_retain_source_bound_condition_not_met(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
) -> None:
    item, kinds, assessment = _source_representation(
        monkeypatch,
        tmp_path / kind.lower(),
        kind,
    )
    monkeypatch.setattr(
        package.tier_zero_reasons,
        "installed_reason_ledger",
        lambda root: {"objectives": {}},
    )
    coordinates = {f"{kind}-{tier}.1" for tier in (1, 2, 3)}
    commitment: dict = {}
    rows = package._instance_obligations(
        3,
        (item,),
        tmp_path / kind.lower(),
        NamespaceObject.create("fixture-verifier", "VERIFIER", {}),
        {"results": []},
        kinds=kinds,
        source_contracts=assessment,
        coordinates=coordinates,
        selection_commitment=commitment,
    )

    assert {row["coordinate"] for row in rows} == coordinates
    assert commitment["status"] == "COMMITTED"
    assert commitment["conditional_refutation_count"] == 3
    assert all(row["status"] == "PASS" for row in rows)
    assert all(row["checker_status"] == "NOT_REQUIRED" for row in rows)
    assert all(
        row["applicability"]["classification"] == "CONDITION_NOT_MET"
        for row in rows
    )
    assert all(row["blockers"] == [] for row in rows)
    assert all(
        row["package_graph_replay_is_instance_evidence"] is False
        for row in rows
    )
    for row in rows:
        selected = row["selected_package_check"]
        source_route = next(
            route
            for route in source_contracts.catalog()
            if route["object_kind"] == kind and route["tier"] == row["tier"]
        )
        source_result = assessment.evaluate(item, source_route)
        native_route = next(
            route
            for route in behavioral_routes.catalog()
            if route["coordinate"] == row["coordinate"]
        )
        assert selected["evidence_origin"] == (
            "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW"
        )
        assert selected["adaptation_obligation_id"] == source_route["obligation_id"]
        assert selected["adaptation_result_digest"] == value_digest(source_result)
        assert selected["native_coordinate"] == row["coordinate"]
        assert selected["condition"] == native_route["applicability"]["condition"]
        assert selected["applicability_digest"] == native_route[
            "applicability_digest"
        ]
        assert selected["condition_status"] == "NOT_TRIGGERED"
        assert selected["fulfillment_required"] is False
        assert selected["result_digest"] == value_digest(
            {key: value for key, value in selected.items() if key != "result_digest"}
        )


def test_deleted_or_substituted_added_route_cannot_pass_contract_profile(
    declared_package,
) -> None:
    root, retained, _ = declared_package
    document = prepare(root, retained)
    objects = package.package_manifest.validate_bridge(document)
    kinds = KindRequirements(root, document["namespace"])
    verifier = next(item for item in objects if item.kind.value == "VERIFIER")
    assessment = source_contracts.SourceContractAssessment(root, objects, kinds)
    rows = package._instance_obligations(
        3,
        objects,
        root,
        verifier,
        {"results": []},
        kinds=kinds,
        source_contracts=assessment,
    )
    baseline = coverage_checker.assess(
        3,
        objects,
        kinds,
        rows,
        verifier_id=verifier.object_id,
    )
    assert baseline["denominator_status"] == "PASS"
    target = next(
        row
        for row in rows
        if row["object_kind"] == "ROBOT" and row["coordinate"] == "ROBOT-1.1"
    )

    deleted = [row for row in rows if row is not target]
    substituted = deepcopy(rows)
    changed = next(
        row
        for row in substituted
        if row["object_id"] == target["object_id"]
        and row["coordinate"] == target["coordinate"]
    )
    changed["proposition_digest"] = "sha256:" + "0" * 64

    for altered, expected_code in (
        (deleted, "PACKAGE_CONTRACT_INSTANCE_MISSING"),
        (substituted, "PACKAGE_CONTRACT_INSTANCE_BINDING_DIFFERS"),
    ):
        assessed = coverage_checker.assess(
            3,
            objects,
            kinds,
            altered,
            verifier_id=verifier.object_id,
        )
        assert assessed["denominator_status"] == "FAIL"
        assert assessed["status"] == "FAIL"
        assert any(
            finding["code"] == expected_code
            and finding["object_id"] == target["object_id"]
            and finding["coordinate"] == target["coordinate"]
            for finding in assessed["findings"]
        )
        contract = next(
            row
            for row in assessed["contracts"]
            if row["object_id"] == target["object_id"]
            and row["kind"] == "ROBOT"
        )
        assert contract["finite_check_status"] == "FAIL"
        assert contract["profile_status"] != "PASS"
        assert contract["status"] == "FAIL"
