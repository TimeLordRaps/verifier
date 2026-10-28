# Terminology: identifier (ID).
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from verifier.core.namespace import NamespaceObject
from verifier.runtime import namespace_consequences
from verifier.runtime import package_source_contracts as contracts
from verifier.runtime import (
    added_kind_behavioral_routes,
    manifest_gate,
    package_execution,
    package_polish,
)
from verifier.runtime.namespace_contracts import namespace_registry
from verifier.runtime.tier_zero_profile import value_digest


def _fixture(monkeypatch: pytest.MonkeyPatch, *, added: bool = False,
             added_kind: str | None = None,
             primary_kind: str = "OBJECT"):
    object_id = "fixture-source-object"
    digest = "sha256:" + "1" * 64
    declarations = {}
    classification = {}
    specializations = []
    selected_added_kind = added_kind or ("LEDGER" if added else None)
    if selected_added_kind is not None:
        contract = namespace_registry()[selected_added_kind]
        declarations = {
            obligation.id: {name: obligation.id + ":" + name
                            for name in obligation.declaration_fields}
            for obligation in contract.obligations
        }
        classification = {selected_added_kind: {
            "status": "APPLIES",
            "reason": f"Exact fixture {selected_added_kind} role.",
            "evidence_paths": ["fixture.py"],
        }}
        specializations = [selected_added_kind]
    review = {
        "primary_kind": primary_kind, "owned_paths": ["fixture.py"],
        "classification": classification, "declarations": declarations,
        "claim_boundary": "Fixture source review only.",
    }
    monkeypatch.setattr(contracts, "_review_catalog", lambda: {object_id: review})
    monkeypatch.setattr(contracts, "_INSTALLED_REVIEWS", {object_id: review})
    monkeypatch.setattr(contracts, "_INSTALLED_REVIEW_IDS", frozenset({object_id}))
    surfaces = [
        {"surface_id": "file:fixture.py", "path": "fixture.py", "line": 1,
         "form": "file", "source_kinds": [], "hints": [], "unresolved_marker": False},
        {"surface_id": "python:fixture.py:<module>", "path": "fixture.py", "line": 1,
         "form": "Module", "source_kinds": [], "hints": [], "unresolved_marker": False},
    ]
    obligations = {
        obligation_id: {
            "reason": "Fixture reason for " + obligation_id,
            "evidence": [{"path": "fixture.py", "sha256": digest}],
            "declaration": deepcopy(declaration),
        }
        for obligation_id, declaration in declarations.items()
    }
    selected_classification = {
        kind: {"status": row["status"], "reason": row["reason"],
               "evidence": [{"path": "fixture.py", "sha256": digest}]}
        for kind, row in classification.items()
    }
    declaration = {
        "object_id": object_id, "kind": primary_kind,
        "surfaces": [row["surface_id"] for row in surfaces],
        "classification": selected_classification, "obligations": obligations,
        "specializations": specializations,
    }
    kinds = SimpleNamespace(
        registry=namespace_registry(),
        declarations={object_id: declaration},
        census={"files": [{"path": "fixture.py", "sha256": digest}]},
        observed={"surfaces": surfaces, "gaps": [], "source_import_bindings": [],
                  "export_bindings": []},
        report={"source_census_digest": "sha256:" + "2" * 64},
        kinds=lambda selected: {"OBJECT", primary_kind, *specializations},
        basis=lambda selected, kind: {
            "kind": kind, "declared": kind == "OBJECT" or kind in specializations,
            "necessity": "NECESSARY", "reasons": ["Fixture source role."],
            "source_census_digest": "sha256:" + "2" * 64,
        },
    )
    item = NamespaceObject.create(
        object_id, primary_kind, {"representation_role": "fixture"}
    )
    return item, kinds, declaration


def test_catalog_has_one_reasoned_source_route_for_every_installed_kind_and_tier() -> None:
    rows = contracts.catalog()
    assert len(rows) == 38 * 3
    assert len({row["coordinate"] for row in rows}) == len(rows)
    assert all(row["reason"] and row["exact_claim"] for row in rows)
    assert {row["tier"] for row in rows} == {1, 2, 3}
    for row in rows:
        covered = row["covered_admission_obligations"]
        assert covered
        identifiers = [entry["obligation_id"] for entry in covered]
        assert len(identifiers) == len(set(identifiers))
        assert all(set(entry) == {
            "obligation_id", "reason", "claim_boundary"
        } for entry in covered)
        assert all(entry["reason"].strip() for entry in covered)
        assert all(entry["claim_boundary"].strip() for entry in covered)
        identity = {
            "semantic_version": row["semantic_version"],
            "coordinate": row["coordinate"],
            "object_kind": row["object_kind"],
            "tier": row["tier"],
            "covered_admission_obligations": covered,
            "exact_claim": row["exact_claim"],
            "applicability": row["applicability"],
            "applicability_digest": row["applicability_digest"],
        }
        assert row["proposition_digest"] == value_digest(identity)


def test_legacy_source_admission_is_adapter_owned_and_not_tier_zero_credit() -> None:
    registry = namespace_registry()
    legacy = {kind for kind, contract in registry.items() if not contract.obligations}
    assert len(legacy) == 26
    for kind in legacy:
        route = next(row for row in contracts.catalog()
                     if row["object_kind"] == kind and row["tier"] == 1)
        identifier = f"{kind}-SOURCE-0.1-installed-review-binding"
        assert [entry["obligation_id"] for entry in
                route["covered_admission_obligations"]] == [identifier]
        obligation = route["covered_admission_obligations"][0]
        assert kind in obligation["reason"]
        assert "VSTD-T0 credit" in obligation["claim_boundary"]
        assert not identifier.startswith("VSTD-T0.")


def test_added_kind_source_admission_retains_installed_ids_and_reasons() -> None:
    for kind, contract in namespace_registry().items():
        if not contract.obligations:
            continue
        route = next(row for row in contracts.catalog()
                     if row["object_kind"] == kind and row["tier"] == 1)
        assert [row["obligation_id"] for row in
                route["covered_admission_obligations"]] == [
            obligation.id for obligation in contract.obligations
        ]
        assert {
            entry["obligation_id"]: entry["reason"]
            for entry in route["covered_admission_obligations"]
        } == {
            obligation.id: obligation.reason for obligation in contract.obligations
        }


def test_source_contract_replays_facets_dynamics_statics_and_native_nontrigger(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, declaration = _fixture(monkeypatch)
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    for tier in (1, 2, 3):
        route = next(row for row in contracts.catalog()
                     if row["object_kind"] == "OBJECT" and row["tier"] == tier)
        assert contracts.applies_to(item, declaration, route, kinds)
        result = assessment.evaluate(item, route)
        assert result["status"] == "PASS"
        assert [entry["obligation_id"] for entry in
                result["covered_admission_obligations"]] == [
                    "OBJECT-SOURCE-0.1-installed-review-binding"
                ]
        assert result["covered_admission_obligations"] == route[
            "covered_admission_obligations"
        ]
    native = next(
        row for row in manifest_gate.obligation_catalog()
        if row["coordinate"] == "OBJECT-1.2"
    )
    refutation = assessment.refute_native_runtime_variant(item, native)
    assert refutation["status"] == "PASS"
    assert refutation["condition_status"] == "NOT_TRIGGERED"
    assert refutation["fulfillment_required"] is False


def test_base_object_source_contract_is_ubiquitous_for_non_object_primary_kind(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, declaration = _fixture(monkeypatch, primary_kind="DATA")
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    for tier in (1, 2, 3):
        object_route = next(row for row in contracts.catalog()
                            if row["object_kind"] == "OBJECT" and row["tier"] == tier)
        data_route = next(row for row in contracts.catalog()
                          if row["object_kind"] == "DATA" and row["tier"] == tier)

        assert contracts.applies_to(item, declaration, object_route, kinds)
        assert contracts.applies_to(item, declaration, data_route, kinds)
        assert assessment.evaluate(item, object_route)["status"] == "PASS"
        assert assessment.evaluate(item, data_route)["status"] == "PASS"


def test_evidence_bound_legacy_cross_root_role_accumulates_source_routes(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, declaration = _fixture(monkeypatch, primary_kind="DATA")
    digest = kinds.census["files"][0]["sha256"]
    declaration["classification"]["VERIFIER"] = {
        "status": "APPLIES",
        "reason": "The exact owned source evaluates a bounded proposition.",
        "evidence": [{"path": "fixture.py", "sha256": digest}],
    }
    kinds.kinds = lambda selected: {"OBJECT", "DATA", "VERIFIER"}
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    for tier in (1, 2, 3):
        route = next(row for row in contracts.catalog()
                     if row["object_kind"] == "VERIFIER" and row["tier"] == tier)
        assert contracts.applies_to(item, declaration, route, kinds)
        assert assessment.evaluate(item, route)["status"] == "PASS"

    typed_runtime = next(
        row for row in manifest_gate.obligation_catalog()
        if row["coordinate"] == "VERIFIER-1.1"
    )
    refutation = assessment.refute_native_runtime_variant(
        item, typed_runtime
    )
    assert refutation is not None
    assert refutation["status"] == "PASS"
    assert refutation["condition_status"] == "NOT_TRIGGERED"
    assert refutation["fulfillment_required"] is False

    generic_identity = {
        **typed_runtime,
        "object_kind": "OBJECT",
        "coordinate": "OBJECT-1.1",
        "scope": "generic_canonical_representation_and_address",
    }
    assert assessment.refute_native_runtime_variant(
        item, generic_identity
    ) is None

    declaration["classification"]["VERIFIER"]["evidence"][0]["sha256"] = (
        "sha256:" + "9" * 64
    )
    changed = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    route = next(row for row in contracts.catalog()
                 if row["object_kind"] == "VERIFIER" and row["tier"] == 1)
    assert changed.evaluate(item, route)["status"] == "FAIL"


def test_exact_reviewed_refutation_closes_conditional_hint_without_erasing_denominator(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """A source hint stays selected while its native subject condition is refuted.

    Tier 0 deliberately treats a clean ``DOES_NOT_APPLY`` as documented rather
    than pretending static discovery proved the semantic kind absent.  Package
    polish must therefore keep the hinted obligation in its denominator, but it
    may use the same exact current-source decision to prove that the conditional
    retained-runtime subject is not the selected source representation.
    """

    item, kinds, declaration = _fixture(
        monkeypatch, primary_kind="ARCH",
    )
    reason = "The reviewed architecture source is not a retained DATA subject."
    review = contracts._INSTALLED_REVIEWS[item.object_id]
    review["classification"]["DATA"] = {
        "status": "DOES_NOT_APPLY",
        "reason": reason,
        "evidence_paths": ["fixture.py"],
    }
    declaration["classification"]["DATA"] = {
        "status": "DOES_NOT_APPLY",
        "reason": namespace_consequences.compiled_classification_reason(
            "DOES_NOT_APPLY", reason,
        ),
        "evidence": [{
            "path": "fixture.py",
            "sha256": kinds.census["files"][0]["sha256"],
        }],
    }
    kinds.kinds = lambda selected: {"OBJECT", "ARCH", "DATA"}
    kinds.objects = {
        item.object_id: {
            "classification": [{
                "kind": "DATA",
                "declared": False,
                "source_declared": False,
                "hinted": True,
                "decision": "DOES_NOT_APPLY",
                "support_status": "PASS",
                "non_applicability": "DOCUMENTED",
                "refutation_status": "DOCUMENTED",
                "refutation_code": "DOCUMENTED_BOUNDED_ABSENCE",
                "refutation_receipt_digest": "sha256:" + "4" * 64,
                "semantic_classification_status": "NOT_ESTABLISHED",
            }],
        },
    }
    kinds.basis = lambda selected, kind: {
        "kind": kind,
        "declared": kind in {"OBJECT", "ARCH"},
        "necessity": (
            "CONDITIONAL_UNRESOLVED" if kind == "DATA" else "NECESSARY"
        ),
        "reasons": ["Static source discovery retained a DATA hint."],
        "source_census_digest": kinds.report["source_census_digest"],
    }
    route = next(
        row for row in manifest_gate.obligation_catalog()
        if row["coordinate"] == "DATA-1.1"
    )
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.refute_native_runtime_variant(item, route)

    assert "DATA" in kinds.kinds(item.object_id)
    assert kinds.basis(item.object_id, "DATA")["necessity"] == (
        "CONDITIONAL_UNRESOLVED"
    )
    assert result is not None
    assert result["status"] == "PASS"
    assert result["condition_status"] == "NOT_TRIGGERED"
    assert result["fulfillment_required"] is False
    assert result["adaptation_obligation_id"] == (
        "ARCH-1.90-source-representation-facets"
    )
    assert result["classification_decision_digest"].startswith("sha256:")
    assert result["native_coordinate"] == "DATA-1.1"


def test_reason_only_retention_assesses_route_without_inventing_typed_subject(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """Authored retention is assessment authority, not a native record cast."""

    item, kinds, declaration = _fixture(
        monkeypatch, primary_kind="ARCH",
    )
    declaration["classification"]["ACTOR"] = {
        "status": "UNRESOLVED",
        "reason": "The exact source-role decision remains open.",
        "evidence": [],
    }
    kinds.kinds = lambda selected: {"OBJECT", "ARCH", "ACTOR"}
    kinds.objects = {
        item.object_id: {
            "classification": [{
                "kind": "ACTOR",
                "declared": False,
                "source_declared": False,
                "hinted": False,
                "decision": "UNRESOLVED",
                "support_status": "UNKNOWN",
                "detail_profile": "DOCUMENTED_APPLIES_RETENTION",
                "reason_decision": "APPLIES",
                "reason_status": "DOCUMENTED",
                "reason_id": "fixture-actor-retention",
                "semantic_classification_status": "NOT_ESTABLISHED",
            }],
        },
    }
    retained_reasons = [
        "reasons.vstd: APPLIES; adoption/source truth remain NOT_ESTABLISHED."
    ]
    kinds.basis = lambda selected, kind: {
        "kind": kind,
        "declared": kind in {"OBJECT", "ARCH"},
        "necessity": "NECESSARY",
        "reasons": retained_reasons,
        "source_census_digest": kinds.report["source_census_digest"],
    }
    route = next(
        row for row in manifest_gate.obligation_catalog()
        if row["coordinate"] == "ACTOR-1.1"
    )
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.refute_native_runtime_variant(item, route)

    assert result is not None
    assert result["status"] == "PASS"
    assert result["condition_status"] == "NOT_TRIGGERED"
    assert result["adaptation_obligation_id"] == (
        "ARCH-1.90-source-representation-facets"
    )
    assert result["applicability_retention_digest"].startswith("sha256:")
    assert "without adopting that source role" in result["reason"]

    retained_reasons.append(
        "Declared consequence graph requires ACTOR; simulation or generic labels "
        "cannot erase an external path."
    )
    assert assessment.refute_native_runtime_variant(item, route) is None


def test_compiled_nonstructural_role_retains_demand_but_not_runtime_subject(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """Whole-graph obligation retention is not a retained FINBOT record."""

    item, kinds, declaration = _fixture(
        monkeypatch, primary_kind="HARDWARE",
    )
    review = contracts._INSTALLED_REVIEWS[item.object_id]
    review["classification"]["FINBOT"] = {
        "status": "UNRESOLVED",
        "reason": "The isolated source review does not decide FINBOT.",
        "evidence_paths": [],
    }
    declaration["classification"]["FINBOT"] = {
        "status": "APPLIES",
        "reason": namespace_consequences.compiled_role_reason(
            item.object_id, "FINBOT",
        ),
        "evidence": [{
            "path": "fixture.py",
            "sha256": kinds.census["files"][0]["sha256"],
        }],
    }
    declaration["specializations"] = ["FINBOT"]
    kinds.kinds = lambda selected: {"OBJECT", "HARDWARE", "FINBOT"}
    kinds.objects = {
        item.object_id: {
            "classification": [{
                "kind": "FINBOT",
                "declared": True,
                "source_declared": False,
                "hinted": False,
                "decision": "APPLIES",
                "support_status": "PASS",
                "non_applicability": "NOT_ESTABLISHED",
                "semantic_classification_status": "NOT_ESTABLISHED",
            }],
        },
    }
    kinds.basis = lambda selected, kind: {
        "kind": kind,
        "declared": kind in {"OBJECT", "HARDWARE", "FINBOT"},
        "necessity": "NECESSARY",
        "reasons": ["The compiled graph retains the FINBOT denominator."],
        "source_census_digest": kinds.report["source_census_digest"],
    }
    route = next(
        row for row in manifest_gate.obligation_catalog()
        if row["coordinate"] == "FINBOT-1.1"
    )
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.refute_native_runtime_variant(item, route)

    assert result is not None
    assert result["status"] == "PASS"
    assert result["condition_status"] == "NOT_TRIGGERED"
    assert result["adaptation_obligation_id"] == (
        "HARDWARE-1.90-source-representation-facets"
    )
    assert result["applicability_retention_digest"].startswith("sha256:")
    assert "without structural role evidence" in result["reason"]


def test_added_kind_requires_exact_reviewed_obligation_declarations(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, declaration = _fixture(monkeypatch, added=True)
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    route = next(row for row in contracts.catalog()
                 if row["object_kind"] == "LEDGER" and row["tier"] == 1)
    result = assessment.evaluate(item, route)
    assert result["status"] == "PASS"
    assert [row["obligation_id"] for row in
            result["covered_admission_obligations"]] == [
        row.id for row in namespace_registry()["LEDGER"].obligations
    ]
    assert result["covered_admission_obligations"] == route[
        "covered_admission_obligations"
    ]

    declaration["obligations"]["LEDGER-0.1-authoritative-history"][
        "declaration"]["history"] = "substituted"
    changed = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    failed = changed.evaluate(item, route)
    assert failed["status"] == "FAIL"
    assert "LEDGER-0.1-authoritative-history" in failed["reason"]


def test_added_kind_accepts_exact_compact_v6_review_reason_projection(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """Transport compaction cannot refute the full installed rationale it binds."""

    item, kinds, declaration = _fixture(monkeypatch, added=True)
    full_reason = "Exact fixture LEDGER role. " + "bounded detail " * 120
    contracts._INSTALLED_REVIEWS[item.object_id]["classification"]["LEDGER"][
        "reason"
    ] = full_reason
    declaration["classification"]["LEDGER"]["reason"] = (
        namespace_consequences.compiled_classification_reason(
            "APPLIES", full_reason
        )
    )
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    for tier in (1, 3):
        route = next(
            row
            for row in contracts.catalog()
            if row["object_kind"] == "LEDGER" and row["tier"] == tier
        )
        assert assessment.evaluate(item, route)["status"] == "PASS"


@pytest.mark.parametrize("mutation", ["malformed", "duplicate_id"])
def test_source_admission_ledger_runtime_rejects_malformed_or_duplicate_ids(
        monkeypatch: pytest.MonkeyPatch, tmp_path, mutation: str) -> None:
    item, kinds, _declaration = _fixture(monkeypatch)
    route = next(deepcopy(row) for row in contracts.catalog()
                 if row["object_kind"] == "OBJECT" and row["tier"] == 1)
    if mutation == "malformed":
        del route["covered_admission_obligations"][0]["reason"]
    else:
        duplicate = deepcopy(route["covered_admission_obligations"][0])
        duplicate["reason"] = "A second reason must not conceal a duplicate ID."
        route["covered_admission_obligations"].append(duplicate)
    monkeypatch.setitem(contracts._CATALOG, ("OBJECT", 1), route)
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    with pytest.raises(ValueError, match="PACKAGE_SOURCE_ADMISSION_LEDGER"):
        assessment.evaluate(item, route)


def test_extra_complete_admission_row_is_refused_by_catalog_runtime_equality(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, _declaration = _fixture(monkeypatch)
    route = next(deepcopy(row) for row in contracts.catalog()
                 if row["object_kind"] == "OBJECT" and row["tier"] == 1)
    route["covered_admission_obligations"].append({
        "obligation_id": "OBJECT-SOURCE-0.2-uninstalled-extra",
        "reason": "A structurally valid extra row is not installed authority.",
        "claim_boundary": "Test-only uninstalled proposition.",
    })
    monkeypatch.setitem(contracts._CATALOG, ("OBJECT", 1), route)
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.evaluate(item, route)

    assert result["status"] == "FAIL"
    assert "source-route admission denominator differs" in result["reason"]


def test_dynamic_surface_omission_is_refuted(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, _declaration = _fixture(monkeypatch)
    kinds.declarations[item.object_id]["surfaces"].pop()
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    route = next(row for row in contracts.catalog()
                 if row["object_kind"] == "OBJECT" and row["tier"] == 2)
    result = assessment.evaluate(item, route)
    assert result["status"] == "FAIL"
    assert "source-interface denominator differs" in result["reason"]


def test_negative_controls_execute_live_denominator_predicates_and_return_typed_evidence(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, _declaration = _fixture(monkeypatch)
    owned = contracts._owned_path_denominator_matches
    surfaces = contracts._declared_surface_denominator_matches
    calls = {"owned": 0, "surfaces": 0}

    def checked_owned(*args, **kwargs):
        calls["owned"] += 1
        return owned(*args, **kwargs)

    def checked_surfaces(*args, **kwargs):
        calls["surfaces"] += 1
        return surfaces(*args, **kwargs)

    monkeypatch.setattr(contracts, "_owned_path_denominator_matches", checked_owned)
    monkeypatch.setattr(contracts, "_declared_surface_denominator_matches", checked_surfaces)
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    route = next(row for row in contracts.catalog()
                 if row["object_kind"] == "OBJECT" and row["tier"] == 3)

    result = assessment.evaluate(item, route)

    assert result["status"] == "PASS"
    controls = result["observations"]["negative_controls"]
    assert calls["owned"] >= 7 and calls["surfaces"] >= 7
    assert set(controls) == {"missing_owned_source_refused", "omitted_surface_refused"}
    for name, evidence in controls.items():
        assert evidence["schema"] == "verifier-source-denominator-negative-control-1"
        assert evidence["control"] == name
        assert evidence["status"] == "PASS"
        assert evidence["baseline"] == {"accepted": True, "status": "PASS"}
        assert {probe["mutation"] for probe in evidence["probes"]} == {
            "OMITTED", "EMPTY", "MALFORMED", "DUPLICATED",
            "DIGEST_PRESERVING_SUBSTITUTION",
        }
        assert all(probe["accepted"] is False and probe["status"] == "PASS"
                   for probe in evidence["probes"])
        assert evidence["denominator_digest"].startswith("sha256:")


@pytest.mark.parametrize("selected", [
    [],
    None,
    ["file:fixture.py", "file:fixture.py"],
    ["file:substituted.py"],
])
def test_owned_path_denominator_rejects_empty_malformed_duplicate_or_substitution(
        selected) -> None:
    digest = "sha256:" + "1" * 64
    files = {"fixture.py": digest, "substituted.py": digest}
    assert not contracts._owned_path_denominator_matches(
        ["fixture.py"], selected, files,
    )


@pytest.mark.parametrize("selected", [
    [],
    None,
    ["file:fixture.py", "file:fixture.py"],
    ["python:fixture.py:substituted"],
])
def test_declared_surface_denominator_rejects_empty_malformed_duplicate_or_substitution(
        selected) -> None:
    discovered = {
        "file:fixture.py": {"surface_id": "file:fixture.py", "path": "fixture.py"},
    }
    assert not contracts._declared_surface_denominator_matches(
        selected, discovered, {"fixture.py"},
    )


def test_digest_preserving_path_metadata_substitution_is_still_refused() -> None:
    digest = "sha256:" + "1" * 64
    files = {"fixture.py": digest, "renamed.py": digest}
    assert files["fixture.py"] == files["renamed.py"]
    assert not contracts._owned_path_denominator_matches(
        ["fixture.py"], ["file:renamed.py"], files,
    )


def test_object_label_does_not_exempt_a_denominator_substitution(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, declaration = _fixture(monkeypatch)
    assert item.kind.value == declaration["kind"] == "OBJECT"
    declaration["surfaces"][0] = "file:substituted.py"
    kinds.census["files"].append({
        "path": "substituted.py", "sha256": kinds.census["files"][0]["sha256"],
    })
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    route = next(row for row in contracts.catalog()
                 if row["object_kind"] == "OBJECT" and row["tier"] == 3)

    result = assessment.evaluate(item, route)

    assert result["status"] == "FAIL"
    assert "reviewed owned-file denominator differs" in result["reason"]
    controls = result["observations"]["negative_controls"]
    assert controls["missing_owned_source_refused"]["status"] == "FAIL"


@pytest.mark.parametrize(("predicate", "control"), [
    ("_owned_path_denominator_matches", "missing_owned_source_refused"),
    ("_declared_surface_denominator_matches", "omitted_surface_refused"),
])
def test_negative_control_fails_when_its_production_predicate_accepts_every_mutant(
        monkeypatch: pytest.MonkeyPatch, tmp_path, predicate: str, control: str) -> None:
    item, kinds, _declaration = _fixture(monkeypatch)
    monkeypatch.setattr(contracts, predicate, lambda *args, **kwargs: True)
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    route = next(row for row in contracts.catalog()
                 if row["object_kind"] == "OBJECT" and row["tier"] == 3)

    result = assessment.evaluate(item, route)

    assert result["status"] == "FAIL"
    evidence = result["observations"]["negative_controls"][control]
    assert evidence["status"] == "FAIL"
    assert all(probe["accepted"] is True and probe["status"] == "FAIL"
               for probe in evidence["probes"])
    assert "source-contract negative control unavailable" in result["reason"]


def test_coverage_requires_every_cumulative_source_route() -> None:
    clauses = [{"obligation_id": row["obligation_id"], "status": "PASS"}
               for row in contracts.catalog()
               if row["object_kind"] == "POLICY" and row["tier"] <= 2]
    assert contracts.coverage_satisfies("POLICY", 2, clauses)
    clauses[-1]["status"] = "UNKNOWN"
    assert not contracts.coverage_satisfies("POLICY", 2, clauses)


def test_runtime_variant_nontrigger_binds_installed_conditional_declaration(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """A checker existing does not turn source code into its runtime record."""
    item, kinds, _declaration = _fixture(monkeypatch)
    route = next(
        deepcopy(route) for route in manifest_gate.obligation_catalog()
        if route["coordinate"] == "OBJECT-1.2"
    )
    monkeypatch.setattr(
        package_polish.core_tier_progression, "installed_core_route_inventory",
        lambda: {"family_cells": [{
            "object_kind": "OBJECT", "tier": 1,
            "registered_route_memberships": [route],
        }]},
    )
    monkeypatch.setattr(
        package_polish.tier_zero_reasons, "installed_reason_ledger",
        lambda root: {"objectives": {"OBJECT-1.2": {
            "reason": "The retained typed-facet record is conditional on an actual runtime-domain subject.",
            "repository_realization": {
                "explanation": "The source representation proves whether this retained runtime variant is selected.",
                "claim_boundary": "Source adaptation does not manufacture a runtime-domain record.",
            },
        }}},
    )
    source = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    verifier = NamespaceObject.create("verifier", "VERIFIER", {})
    typed_facets = {
        field: route[field]
        for field in (
            "coordinate",
            "semantic_version",
            "proposition_digest",
            "checking_mechanism",
            "certificate_schema_version",
        )
    }
    typed_facets["status"] = "PASS"

    rows = package_polish._instance_obligations(
        1,
        (item,),
        tmp_path,
        verifier,
        {"results": [{"object_id": item.object_id,
                      "typed_facets": typed_facets}]},
        kinds=kinds, source_contracts=source,
    )

    native = next(row for row in rows if row["coordinate"] == "OBJECT-1.2")
    assert native["status"] == "PASS"
    assert native["checker_status"] == "NOT_REQUIRED"
    assert native["applicability"]["classification"] == "CONDITION_NOT_MET"
    assert native["selected_package_check"]["native_coordinate"] == "OBJECT-1.2"
    assert native["selected_package_check"]["condition"] == route[
        "applicability"
    ]["condition"]
    assert native["selected_package_check"]["applicability_digest"] == route[
        "applicability_digest"
    ]
    assert native["package_graph_replay_is_instance_evidence"] is False
    assert all(row["status"] == "PASS" for row in rows)


def _production_core_route(kind: str, tier: int, coordinate: str) -> dict:
    """Return the route shape consumed by package preflight, not its facade."""

    inventory = package_polish.core_tier_progression.installed_core_route_inventory()
    declarations = (
        package_polish.core_tier_progression.installed_core_route_declarations()
    )
    cell = next(
        row for row in inventory["family_cells"]
        if row["object_kind"] == kind and row["tier"] == tier
    )
    membership = next(
        row for row in cell["registered_route_memberships"]
        if row["coordinate"] == coordinate
    )
    route = {**membership, **declarations[kind, tier, coordinate]}
    assert "object_kind" not in route
    assert "tier" not in route
    return route


def test_all_tier_three_production_core_memberships_reach_exact_refutation_lookup(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """Exercise the 113 routes in the shape package preflight actually uses."""

    item, kinds, _declaration = _fixture(monkeypatch)
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    monkeypatch.setattr(contracts, "applies_to", lambda *_: True)
    monkeypatch.setattr(
        assessment,
        "evaluate",
        lambda _item, _route: {"status": "PASS", "result": "source-bound"},
    )
    inventory = package_polish.core_tier_progression.installed_core_route_inventory()
    declarations = (
        package_polish.core_tier_progression.installed_core_route_declarations()
    )
    reached = []
    required = []
    for cell in inventory["family_cells"]:
        if cell["tier"] > 3:
            continue
        for membership in cell["registered_route_memberships"]:
            key = cell["object_kind"], cell["tier"], membership["coordinate"]
            route = {**membership, **declarations[key]}
            assert "object_kind" not in route and "tier" not in route
            result = assessment.refute_native_runtime_variant(
                item,
                route,
                object_kind=cell["object_kind"],
                tier=cell["tier"],
            )
            if route["applicability"]["mode"] == "NECESSARY":
                required.append(key)
                assert result is None
            else:
                assert result is not None
                assert result["native_coordinate"] == membership["coordinate"]
                reached.append(key)

    assert len(reached) == 112
    assert required == [("OBJECT", 1, "OBJECT-1.1")]
    assert len(reached) + len(required) == 113


@pytest.mark.parametrize(
    "mutation",
    ["count_preserving_swap", "wrong_kind", "wrong_tier", "forged_key"],
)
def test_production_core_refutation_rejects_route_or_cell_forgery(
        monkeypatch: pytest.MonkeyPatch, tmp_path, mutation: str) -> None:
    item, kinds, _declaration = _fixture(monkeypatch, primary_kind="DATA")
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    route = _production_core_route("DATA", 1, "DATA-1.2")
    selected_kind = "DATA"
    selected_tier = 1
    if mutation == "count_preserving_swap":
        replacement = _production_core_route("DATA", 1, "DATA-1.4")
        route["proposition_digest"] = replacement["proposition_digest"]
    elif mutation == "wrong_kind":
        selected_kind = "MODEL"
    elif mutation == "wrong_tier":
        selected_tier = 2
    else:
        route["uninstalled_authority"] = "forged"

    assert assessment.refute_native_runtime_variant(
        item,
        route,
        object_kind=selected_kind,
        tier=selected_tier,
    ) is None


def test_production_and_public_route_shapes_refute_with_identical_digest(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """The readable facade cannot change the production route proposition."""

    item, kinds, _declaration = _fixture(
        monkeypatch, primary_kind="DATA"
    )
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    monkeypatch.setattr(contracts, "applies_to", lambda *_: True)
    monkeypatch.setattr(
        assessment,
        "evaluate",
        lambda _item, _route: {"status": "PASS", "result": "source-bound"},
    )
    production = _production_core_route("DATA", 1, "DATA-1.2")
    public = next(
        route for route in manifest_gate.obligation_catalog()
        if route["object_kind"] == "DATA"
        and route["tier"] == 1
        and route["coordinate"] == "DATA-1.2"
    )

    production_result = assessment.refute_native_runtime_variant(
        item, production, object_kind="DATA", tier=1,
    )
    public_result = assessment.refute_native_runtime_variant(item, public)

    assert production_result is not None
    assert public_result is not None
    assert production_result == public_result
    assert production_result["result_digest"] == public_result["result_digest"]


def test_core_runtime_route_views_initialize_atomically(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """A facade exception cannot strand a partially initialized route cache."""

    item, kinds, _declaration = _fixture(monkeypatch)
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    core = package_polish.core_tier_progression
    inventory = core.installed_core_route_inventory()
    declarations = core.installed_core_route_declarations()
    public_catalog = manifest_gate.obligation_catalog()
    monkeypatch.setattr(
        core, "installed_core_route_inventory", lambda: deepcopy(inventory),
    )
    monkeypatch.setattr(
        core, "installed_core_route_declarations", lambda: deepcopy(declarations),
    )

    def unavailable_facade():
        raise RuntimeError("synthetic facade interruption")

    monkeypatch.setattr(
        manifest_gate, "obligation_catalog", unavailable_facade,
    )
    with pytest.raises(RuntimeError, match="synthetic facade interruption"):
        assessment._installed_core_runtime_routes()

    assert assessment._core_runtime_route_cells is None
    assert assessment._core_runtime_route_declarations is None
    assert assessment._core_runtime_public_routes is None

    monkeypatch.setattr(
        manifest_gate, "obligation_catalog", lambda: deepcopy(public_catalog),
    )
    cells, selected_declarations = assessment._installed_core_runtime_routes()
    assert cells
    assert selected_declarations
    assert assessment._core_runtime_public_routes


def test_necessary_runtime_route_cannot_be_refuted_by_source_variant(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, _declaration = _fixture(monkeypatch)
    route = next(
        deepcopy(route) for route in manifest_gate.obligation_catalog()
        if route["coordinate"] == "OBJECT-1.2"
    )
    declaration = contracts.applicability_declaration(
        mode="NECESSARY",
        condition="The selected package object requires this exact native proposition.",
        reason="This test makes the native proposition unconditionally necessary.",
    )
    route.update(
        applicability=declaration,
        applicability_digest=contracts.applicability_digest(declaration),
    )
    source = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    assert source.refute_native_runtime_variant(item, route) is None


def test_native_runtime_refutation_eligibility_matches_route_partition() -> None:
    source_route = contracts.catalog()[0]
    installed = manifest_gate.obligation_catalog()
    generic = next(
        row for row in installed
        if row["scope"] == "generic_canonical_representation_and_address"
    )
    conditional = next(
        row for row in installed
        if row["coordinate"] == "OBJECT-1.2"
    )
    necessary = deepcopy(conditional)
    declaration = contracts.applicability_declaration(
        mode="NECESSARY",
        condition="This exact native proposition is always required.",
        reason="The eligibility test needs an installed-shape necessary route.",
    )
    necessary.update(
        applicability=declaration,
        applicability_digest=contracts.applicability_digest(declaration),
    )
    malformed = deepcopy(conditional)
    del malformed["applicability"]

    assert not contracts.can_refute_native_runtime_variant(source_route)
    assert not contracts.can_refute_native_runtime_variant(generic)
    assert not contracts.can_refute_native_runtime_variant(necessary)
    assert contracts.can_refute_native_runtime_variant(conditional)
    with pytest.raises(ValueError):
        contracts.can_refute_native_runtime_variant(malformed)


def test_source_assessment_indexes_installed_core_routes_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path,
) -> None:
    item, kinds, _declaration = _fixture(monkeypatch)
    first_route = next(
        row for row in manifest_gate.obligation_catalog()
        if row["coordinate"] == "OBJECT-1.2"
    )
    second_route = next(
        row for row in manifest_gate.obligation_catalog()
        if row["coordinate"] == "OBJECT-2.1"
    )
    core = package_polish.core_tier_progression
    inventory = core.installed_core_route_inventory
    declarations = core.installed_core_route_declarations
    calls = {"inventory": 0, "declarations": 0}

    def counted_inventory():
        calls["inventory"] += 1
        return inventory()

    def counted_declarations():
        calls["declarations"] += 1
        return declarations()

    monkeypatch.setattr(core, "installed_core_route_inventory", counted_inventory)
    monkeypatch.setattr(
        core, "installed_core_route_declarations", counted_declarations,
    )
    source = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    first = source.refute_native_runtime_variant(item, first_route)
    first_counts = dict(calls)
    second = source.refute_native_runtime_variant(item, second_route)

    assert first is not None and second is not None
    assert second["native_coordinate"] == second_route["coordinate"]
    # One production-shape index and one readable-facade index are captured
    # for the immutable assessment.  Subsequent route checks reuse both.
    assert first_counts == {"inventory": 4, "declarations": 2}
    assert calls == first_counts

    # Installed process state is cached only for one immutable source
    # assessment.  A new source snapshot must rebuild its own validated index
    # instead of inheriting the earlier assessment's installed-route view.
    fresh_source = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    fresh = fresh_source.refute_native_runtime_variant(item, first_route)

    assert fresh is not None
    assert calls == {"inventory": 8, "declarations": 4}


def test_nonowned_execution_refutation_is_explicitly_route_scoped(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, _declaration = _fixture(monkeypatch, added=True)
    route = next(row for row in package_execution.catalog()
                 if row["coordinate"] == "LEDGER-1.1")
    source = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = source.refute_native_runtime_variant(item, route)

    assert result is not None
    assert result["condition"] == route["applicability"]["condition"]
    assert result["applicability_digest"] == route["applicability_digest"]
    assert result["condition_status"] == "NOT_TRIGGERED"
    assert "refutes only the named implementation-specific route" in result["reason"]
    assert "does not discharge the applicable obligation family" in result["reason"]


def test_nonowned_execution_refutation_uses_primary_source_for_open_specialization(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """A real role does not select every installed implementation of that role."""

    item, kinds, declaration = _fixture(
        monkeypatch, primary_kind="VERIFIER",
    )
    review = contracts._INSTALLED_REVIEWS[item.object_id]
    review["classification"]["MEASUREMENT"] = {
        "status": "UNRESOLVED",
        "reason": "The isolated review leaves MEASUREMENT open.",
        "evidence_paths": [],
    }
    declaration["classification"]["MEASUREMENT"] = _open_cell()
    declaration["specializations"] = ["MEASUREMENT"]
    kinds.kinds = lambda selected: {"OBJECT", "VERIFIER", "MEASUREMENT"}
    kinds.basis = lambda selected, kind: {
        "kind": kind,
        "declared": kind in {"OBJECT", "VERIFIER", "MEASUREMENT"},
        "necessity": "NECESSARY",
        "reasons": ["The source owns a distinct digital measurement role."],
        "source_census_digest": kinds.report["source_census_digest"],
    }
    route = next(
        row for row in package_execution.catalog()
        if row["coordinate"] == "MEASUREMENT-1.1"
    )
    source = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = source.refute_native_runtime_variant(item, route)

    assert result is not None
    assert result["condition_status"] == "NOT_TRIGGERED"
    assert result["adaptation_obligation_id"] == (
        "VERIFIER-1.90-source-representation-facets"
    )
    assert "sim_resource_fresh.py" in result["reason"]


def test_retained_added_kind_variant_uses_its_installed_conditional_partition(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, _declaration = _fixture(
        monkeypatch, added_kind="MARKET"
    )
    route = next(
        row for row in manifest_gate.obligation_catalog()
        if row["coordinate"] == "MARKET-1.1"
        and row.get("adapter")
        == "verifier-retained-added-kind-behavioral-1"
    )
    source = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = source.refute_native_runtime_variant(item, route)

    assert result is not None
    assert result["condition"] == route["applicability"]["condition"]
    assert result["applicability_digest"] == route["applicability_digest"]
    assert result["condition_status"] == "NOT_TRIGGERED"


@pytest.mark.parametrize(
    ("kind", "coordinate"),
    [
        ("BOT", "BOT-1.7"),
        ("POLICY", "POLICY-1.3"),
    ],
)
def test_retained_subadapter_variant_uses_its_installed_conditional_partition(
        monkeypatch: pytest.MonkeyPatch, tmp_path, kind: str,
        coordinate: str) -> None:
    """Agency and POLICY adapters retain the same exact route authority.

    The aggregate added-kind catalog owns three adapter families.  A source
    variant may refute any exact installed conditional row, not only rows that
    happen to carry the aggregate module's default adapter identifier.
    """

    item, kinds, _declaration = _fixture(
        monkeypatch, added_kind=kind,
    )
    route = next(
        row for row in added_kind_behavioral_routes.catalog()
        if row["coordinate"] == coordinate
    )
    source = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = source.refute_native_runtime_variant(item, route)

    assert result is not None
    assert result["condition"] == route["applicability"]["condition"]
    assert result["applicability_digest"] == route["applicability_digest"]
    assert result["condition_status"] == "NOT_TRIGGERED"


_OWNED_GAP = {
    "path": "fixture.py",
    "code": "NAMESPACE_DYNAMIC_SURFACES_UNRESOLVED",
    "reason": "Dynamic construction may expose interfaces outside the static "
              "definition/export census.",
}


def _tier_two_object_route() -> dict:
    return next(row for row in contracts.catalog()
                if row["object_kind"] == "OBJECT" and row["tier"] == 2)


def test_owned_discovery_gap_alone_leaves_the_route_unknown_not_refuted(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """An unresolved discovery gap is missing evidence, never a refutation.

    The census cannot enumerate what dynamic construction might expose, so the
    source-representation claim is unestablished. A FAIL would also stop every
    higher package gate, hiding real verdicts behind an unanswered question.
    """
    item, kinds, _declaration = _fixture(monkeypatch)
    kinds.observed["gaps"] = [deepcopy(_OWNED_GAP)]
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.evaluate(item, _tier_two_object_route())

    assert result["status"] == "UNKNOWN"
    assert result["applicability_established"] is False
    assert "owned source has unresolved discovery gaps" in result["reason"]
    assert result["observations"]["owned_gap_count"] == 1


def test_owned_discovery_gap_never_masks_a_real_denominator_refutation(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, _declaration = _fixture(monkeypatch)
    kinds.observed["gaps"] = [deepcopy(_OWNED_GAP)]
    kinds.declarations[item.object_id]["surfaces"].pop()
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.evaluate(item, _tier_two_object_route())

    assert result["status"] == "FAIL"
    assert "source-interface denominator differs" in result["reason"]
    assert "owned source has unresolved discovery gaps" in result["reason"]


def test_a_discovery_gap_in_unowned_source_does_not_change_the_verdict(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, _declaration = _fixture(monkeypatch)
    kinds.observed["gaps"] = [{**_OWNED_GAP, "path": "elsewhere.py"}]
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.evaluate(item, _tier_two_object_route())

    assert result["status"] == "PASS"
    assert result["observations"]["owned_gap_count"] == 0


def _tier_three_object_route() -> dict:
    return next(row for row in contracts.catalog()
                if row["object_kind"] == "OBJECT" and row["tier"] == 3)


def _with_audited_refutation(monkeypatch: pytest.MonkeyPatch, kinds, kind: str = "ASSET"):
    """Install an audited DOES_NOT_APPLY answer for ``kind`` into the fixture review."""
    object_id = next(iter(kinds.declarations))
    review = contracts._INSTALLED_REVIEWS[object_id]
    review["classification"][kind] = {
        "status": "DOES_NOT_APPLY",
        "reason": "Audited refutation over the reviewed source.",
        "evidence_paths": ["fixture.py"],
    }
    return kinds.declarations[object_id]


def _open_cell() -> dict:
    return {"status": "UNRESOLVED", "reason": "Migration retains this question.", "evidence": []}


def test_manifest_cell_left_open_beside_an_audited_answer_is_unknown_not_refuted(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """A stale label whose claim was already withdrawn leaves the answer unadopted.

    The manifest says nothing yet (UNRESOLVED, no evidence) while the installed review
    answers with evidence. Nothing contradicts the review, so the route is unestablished:
    FAIL would stop every higher package gate over a question only a developer can close.
    """
    item, kinds, _ = _fixture(monkeypatch)
    declaration = _with_audited_refutation(monkeypatch, kinds)
    declaration["classification"]["ASSET"] = _open_cell()
    declaration["specializations"] = ["ASSET"]
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.evaluate(item, _tier_three_object_route())

    assert result["status"] == "UNKNOWN"
    assert result["applicability_established"] is False
    assert "installed review answer is not adopted by the manifest: ASSET" in result["reason"]
    assert "complete installed classification review differs" not in result["reason"]


def test_manifest_cell_that_contradicts_the_audited_answer_is_still_refuted(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, _ = _fixture(monkeypatch)
    declaration = _with_audited_refutation(monkeypatch, kinds)
    declaration["classification"]["ASSET"] = {
        "status": "APPLIES",
        "reason": "A standing claim the review refutes.",
        "evidence": [{"path": "fixture.py", "sha256": "sha256:" + "1" * 64}],
    }
    declaration["specializations"] = ["ASSET"]
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.evaluate(item, _tier_three_object_route())

    assert result["status"] == "FAIL"
    assert "complete installed classification review differs: ASSET" in result["reason"]
    assert "reviewed specialization set differs" in result["reason"]


def test_compiler_owned_consequence_role_is_outside_local_review_statics(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """The graph compiler and one-object review retain separate authority."""

    item, kinds, declaration = _fixture(monkeypatch)
    review = contracts._INSTALLED_REVIEWS[item.object_id]
    review["classification"]["FINBOT"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "The isolated fixture source has no financial endpoint.",
        "evidence_paths": ["fixture.py"],
    }
    declaration["classification"]["FINBOT"] = {
        "status": "APPLIES",
        "reason": namespace_consequences.compiled_role_reason(
            item.object_id, "FINBOT"
        ),
        "evidence": [{"path": "fixture.py", "sha256": "sha256:" + "1" * 64}],
    }
    declaration["specializations"].append("FINBOT")
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.evaluate(item, _tier_three_object_route())

    assert result["status"] == "PASS"
    assert "complete installed classification review differs" not in result["reason"]
    assert "reviewed specialization set differs" not in result["reason"]
    assert result["observations"]["compiled_consequence_roles"] == ["FINBOT"]


def test_compiler_role_lookalike_does_not_bypass_local_review_statics(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, declaration = _fixture(monkeypatch)
    review = contracts._INSTALLED_REVIEWS[item.object_id]
    review["classification"]["FINBOT"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "The isolated fixture source has no financial endpoint.",
        "evidence_paths": ["fixture.py"],
    }
    declaration["classification"]["FINBOT"] = {
        "status": "APPLIES",
        "reason": namespace_consequences.compiled_role_reason(
            "some-other-object", "FINBOT"
        ),
        "evidence": [{"path": "fixture.py", "sha256": "sha256:" + "1" * 64}],
    }
    declaration["specializations"].append("FINBOT")
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.evaluate(item, _tier_three_object_route())

    assert result["status"] == "FAIL"
    assert "complete installed classification review differs: FINBOT" in result["reason"]
    assert "reviewed specialization set differs" in result["reason"]


def test_documented_obligation_retention_is_outside_local_review_statics(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """The sole reasons ledger may retain demand without claiming a source role."""

    item, kinds, declaration = _fixture(monkeypatch)
    review = contracts._INSTALLED_REVIEWS[item.object_id]
    review["classification"]["ASSET"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "The isolated fixture source does not establish an asset role.",
        "evidence_paths": ["fixture.py"],
    }
    monkeypatch.setattr(
        contracts,
        "_documented_obligation_retention_keys",
        lambda root, declarations: frozenset({(item.object_id, "ASSET")}),
    )
    declaration["classification"]["ASSET"] = _open_cell()
    declaration["specializations"].append("ASSET")
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.evaluate(item, _tier_three_object_route())

    assert result["status"] == "PASS"
    assert "complete installed classification review differs" not in result["reason"]
    assert "reviewed specialization set differs" not in result["reason"]
    assert result["observations"]["documented_obligation_retention_roles"] == [
        "ASSET"
    ]


def test_obligation_retention_lookalike_does_not_bypass_local_review_statics(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, declaration = _fixture(monkeypatch)
    review = contracts._INSTALLED_REVIEWS[item.object_id]
    review["classification"]["ASSET"] = {
        "status": "DOES_NOT_APPLY",
        "reason": "The isolated fixture source does not establish an asset role.",
        "evidence_paths": ["fixture.py"],
    }
    declaration["classification"]["ASSET"] = {
        "status": "APPLIES",
        "reason": "Text claiming this is an exact reasons.vstd obligation retention.",
        "evidence": [{"path": "fixture.py", "sha256": "sha256:" + "1" * 64}],
    }
    declaration["specializations"].append("ASSET")
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.evaluate(item, _tier_three_object_route())

    assert result["status"] == "FAIL"
    assert "complete installed classification review differs: ASSET" in result["reason"]
    assert "reviewed specialization set differs" in result["reason"]


def test_an_open_stale_label_never_masks_a_missing_reviewed_label(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, _ = _fixture(monkeypatch)
    declaration = _with_audited_refutation(monkeypatch, kinds)
    review = contracts._INSTALLED_REVIEWS[item.object_id]
    review["classification"]["POLICY"] = {
        "status": "APPLIES",
        "reason": "Audited role.",
        "evidence_paths": ["fixture.py"],
    }
    declaration["classification"]["ASSET"] = _open_cell()
    declaration["classification"]["POLICY"] = {
        "status": "APPLIES",
        "reason": "Audited role.",
        "evidence": [{"path": "fixture.py", "sha256": "sha256:" + "1" * 64}],
    }
    declaration["specializations"] = ["ASSET"]
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.evaluate(item, _tier_three_object_route())

    assert result["status"] == "FAIL"
    assert "reviewed specialization set differs" in result["reason"]


def test_an_open_cell_beside_an_open_review_answer_adds_no_unadopted_finding(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, _ = _fixture(monkeypatch)
    object_id = item.object_id
    contracts._INSTALLED_REVIEWS[object_id]["classification"]["ASSET"] = {
        "status": "UNRESOLVED",
        "reason": "Migration retains this question.",
        "evidence_paths": [],
    }
    kinds.declarations[object_id]["classification"]["ASSET"] = _open_cell()
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.evaluate(item, _tier_three_object_route())

    assert result["status"] == "PASS"


def test_open_cell_beside_an_open_review_answer_with_new_wording_is_unknown_not_refuted(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """Two unanswered questions that only word the question differently never contradict.

    The manifest keeps its migration wording while the installed review states the
    question more precisely. Neither side makes a claim, so the new wording is simply
    not adopted yet: UNKNOWN, not the FAIL that would block every higher package gate.
    """
    item, kinds, _ = _fixture(monkeypatch)
    object_id = item.object_id
    contracts._INSTALLED_REVIEWS[object_id]["classification"]["ASSET"] = {
        "status": "UNRESOLVED",
        "reason": "Asset applicability is not established. Applicability is UNRESOLVED, not refuted.",
        "evidence_paths": [],
    }
    kinds.declarations[object_id]["classification"]["ASSET"] = _open_cell()
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.evaluate(item, _tier_three_object_route())

    assert result["status"] == "UNKNOWN"
    assert "installed review answer is not adopted by the manifest: ASSET" in result["reason"]
    assert "complete installed classification review differs" not in result["reason"]


def test_open_cell_that_claims_evidence_beside_an_open_review_answer_is_still_refuted(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    item, kinds, _ = _fixture(monkeypatch)
    object_id = item.object_id
    contracts._INSTALLED_REVIEWS[object_id]["classification"]["ASSET"] = {
        "status": "UNRESOLVED", "reason": "Asset applicability is not established.",
        "evidence_paths": [],
    }
    kinds.declarations[object_id]["classification"]["ASSET"] = {
        "status": "UNRESOLVED", "reason": _open_cell()["reason"],
        "evidence": [{"path": "fixture.py", "sha256": "sha256:" + "1" * 64}],
    }
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)

    result = assessment.evaluate(item, _tier_three_object_route())

    assert result["status"] == "FAIL"
    assert "complete installed classification review differs: ASSET" in result["reason"]


class _ScanCountingDict(dict):
    """Counts whole-denominator scans of the discovered-surface mapping."""

    scans = 0

    def items(self):
        type(self).scans += 1
        return super().items()

    def values(self):
        type(self).scans += 1
        return super().values()

    def __iter__(self):
        type(self).scans += 1
        return super().__iter__()


def test_source_route_evaluation_scans_the_discovered_denominator_once_per_assessment(
        monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """Every route of every object reuses one validated per-path surface index.

    The discovered mapping holds every surface of the repository; scanning it for each
    predicate and each negative-control probe made tier-3 evaluation dominate a
    whole-repository polish. The index is built when the snapshot is, and a route
    evaluation afterwards must not walk the mapping again.
    """
    item, kinds, _ = _fixture(monkeypatch)
    assessment = contracts.SourceContractAssessment(tmp_path, (item,), kinds)
    assessment.discovered = _ScanCountingDict(assessment.discovered)
    _ScanCountingDict.scans = 0

    result = assessment.evaluate(item, _tier_three_object_route())

    assert result["status"] == "PASS"
    assert _ScanCountingDict.scans == 0


def test_surface_index_selects_exactly_what_the_full_scan_selects() -> None:
    discovered = {
        "file:a.py": {"surface_id": "file:a.py", "path": "a.py"},
        "python:a.py:f": {"surface_id": "python:a.py:f", "path": "a.py"},
        "file:b.py": {"surface_id": "file:b.py", "path": "b.py"},
        "file:c.py": {"surface_id": "file:c.py", "path": "c.py"},
    }
    index = contracts._surface_index(discovered)
    for paths in ({"a.py"}, {"a.py", "b.py"}, {"c.py", "missing.py"}, {"missing.py"}):
        assert contracts._expected_declared_surfaces(
            discovered, paths, index=index
        ) == contracts._expected_declared_surfaces(discovered, paths)
    assert contracts._expected_declared_surfaces(discovered, {"a.py"}, index=index) == {
        "file:a.py", "python:a.py:f",
    }
    assert contracts._expected_declared_surfaces(discovered, {"missing.py"}, index=index) is None


@pytest.mark.parametrize("broken", [
    {"file:a.py": {"surface_id": "file:other.py", "path": "a.py"}},
    {"file:a.py": {"surface_id": "file:a.py", "path": ""}},
    {"file:a.py": {"surface_id": "file:a.py"}},
    {"": {"surface_id": "", "path": "a.py"}},
    {"file:a.py": ["not", "a", "row"]},
])
def test_surface_index_refuses_a_malformed_denominator_like_the_full_scan(broken) -> None:
    assert contracts._surface_index(broken) is None
    assert contracts._expected_declared_surfaces(broken, {"a.py"}) is None
    assert contracts._surface_index([]) is None
