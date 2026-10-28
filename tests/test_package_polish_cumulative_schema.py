"""Schema regressions for cumulative package-polish Tier 3 reports.

Terminology: identifier (ID).

Tier 3 is meaningful only when one result preserves the Tier 0 admission
record, the Tier 1 and Tier 2 prerequisites, and the Tier 3 execution/result.
These tests load the package-data schemas through the same importlib resource
surface available to installed consumers.
"""

from __future__ import annotations

from copy import deepcopy
from importlib.resources import files
import json
from types import SimpleNamespace

import jsonschema
import pytest

from verifier.core.namespace import NamespaceObject
from verifier.runtime import core_obligation_union as binding
from verifier.runtime import added_kind_behavioral_routes
from verifier.runtime import manifest_gate
from verifier.runtime import package_polish
from verifier.runtime import package_polish_schema_validation
from verifier.runtime import package_source_contracts
from verifier.runtime.namespace_contracts import (
    kind_denominators,
    namespace_registry,
    validate_kind_denominators,
)


DIGEST = "sha256:" + "a" * 64


def test_kind_denominators_separate_native_wire_grid_from_installed_namespace() -> None:
    record = kind_denominators()

    assert record == {
        "schema_version": "verifier-kind-denominators-1",
        "object_kind_count": 26,
        "object_kind_denominator_scope": "RETAINED_NATIVE_WIRE",
        "installed_namespace_kind_count": 38,
    }
    assert len(tuple(package_polish.namespace.ObjectKind)) * 9 == 234
    assert len(namespace_registry()) * 9 == 342
    assert package_polish.core_tier_progression.installed_core_route_inventory()[
        "registered_route_membership_count"
    ] == 408


@pytest.mark.parametrize(
    ("field", "value", "diagnostic"),
    (
        (
            "schema_version", "verifier-kind-denominators-0",
            "PACKAGE_KIND_DENOMINATOR_SCHEMA_INVALID",
        ),
        ("object_kind_count", 38, "PACKAGE_OBJECT_KIND_COUNT_INVALID"),
        ("object_kind_count", True, "PACKAGE_OBJECT_KIND_COUNT_INVALID"),
        (
            "object_kind_denominator_scope", "INSTALLED_NAMESPACE",
            "PACKAGE_OBJECT_KIND_DENOMINATOR_SCOPE_INVALID",
        ),
        (
            "installed_namespace_kind_count", 26,
            "PACKAGE_INSTALLED_NAMESPACE_KIND_COUNT_INVALID",
        ),
        (
            "installed_namespace_kind_count", 37,
            "PACKAGE_INSTALLED_NAMESPACE_KIND_COUNT_INVALID",
        ),
        (
            "installed_namespace_kind_count", 39,
            "PACKAGE_INSTALLED_NAMESPACE_KIND_COUNT_INVALID",
        ),
        (
            "installed_namespace_kind_count", True,
            "PACKAGE_INSTALLED_NAMESPACE_KIND_COUNT_INVALID",
        ),
    ),
)
def test_kind_denominators_reject_ambiguous_or_non_integer_counts(
    field: str, value: object, diagnostic: str,
) -> None:
    record = kind_denominators()
    record[field] = value

    with pytest.raises(ValueError, match=diagnostic):
        validate_kind_denominators(record)


def _reseal(report: dict) -> dict:
    report.pop("report_digest", None)
    report["report_digest"] = binding.value_digest(report)
    return report


def _validator(filename: str) -> jsonschema.Draft202012Validator:
    schema = json.loads(
        files("verifier").joinpath("schemas", filename).read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def _native_diagnostics() -> dict:
    names = {
        0: "ADMISSION",
        1: "FACETS",
        2: "DYNAMICS",
        3: "STATICS",
    }
    return {
        "schema_version": "verifier-native-diagnostic-reference-1",
        "status": "PASS",
        "report_digest": DIGEST,
        "complete_tier_evidence_replay": {
            "status": "PASS",
            "evidence_digest": DIGEST,
            "receipt_digest": DIGEST,
            "transport": "DIGEST_BOUND_REFERENCE",
        },
        "prerequisites": {
            "0": {
                "status": "PASS",
                "report_digest": DIGEST,
                "manifest_digest": DIGEST,
                "obligation_count": 9,
                "obligation_status_counts": {"PASS": 9, "FAIL": 0, "UNKNOWN": 0},
                "obligations": [
                    {
                        "coordinate": f"VSTD-T0.{index}",
                        "status": "PASS",
                        "assessment_reason": "Admission obligation passed.",
                    }
                    for index in range(1, 10)
                ],
            },
            "1": {
                "schema_version": "verifier-self-polish-tier-assessment-7",
                "tier": 1,
                "status": "PASS",
                "report_digest": DIGEST,
                "source_coordinate_digest": DIGEST,
                "post_replay_full_source_recapture": "PASS",
            },
            "2": {
                "schema_version": "verifier-self-polish-tier-assessment-7",
                "tier": 2,
                "status": "PASS",
                "report_digest": DIGEST,
                "source_coordinate_digest": DIGEST,
                "post_replay_full_source_recapture": "PASS",
            },
        },
        "tier_execution": {
            str(tier): {
                "schema_version": "verifier-self-polish-tier-execution-1",
                "tier": tier,
                "tier_name": names[tier],
                "execution_status": "EXECUTED",
                "status": "PASS",
                "reason": f"Tier {tier} assessment executed.",
                "evidence_digest": DIGEST,
                "blocking_prerequisite": None,
                "execution_record_digest": DIGEST,
            }
            for tier in range(4)
        },
    }


def _tier_results() -> list[dict]:
    return [
        {
            "tier": tier,
            "instance_count": 1,
            "status_counts": {"PASS": 1},
            "status": "PASS",
            "checker_status_counts": {},
            "prerequisite_tiers": list(range(tier)),
        }
        for tier in range(1, 4)
    ]


def _recompute_cumulative_tier_results(report: dict) -> None:
    """Bind each package tier summary to its complete prerequisite prefix."""

    rows = report["obligation_instances"]
    results = []
    for depth in range(1, report["requested_tier"] + 1):
        selected = [row for row in rows if row["tier"] <= depth]
        status_counts = {
            status: sum(row["status"] == status for row in selected)
            for status in sorted({row["status"] for row in selected})
        }
        checker_counts = {
            status: sum(row["checker_status"] == status for row in selected)
            for status in sorted({row["checker_status"] for row in selected})
        }
        status = (
            "FAIL" if status_counts.get("FAIL", 0)
            else "UNKNOWN" if status_counts.get("UNKNOWN", 0)
            else "PASS"
        )
        results.append({
            "tier": depth,
            "instance_count": len(selected),
            "status_counts": status_counts,
            "status": status,
            "checker_status_counts": checker_counts,
            "prerequisite_tiers": list(range(depth)),
        })
    report["tier_results"] = results


def _rebind_pass_coordinates(report: dict) -> None:
    """Make every retained PASS coordinate name the same assessment snapshot."""

    source_digest = binding.value_digest(report["source_coordinate"])
    report["source_coordinate_digest"] = source_digest
    manifest_digest = report["manifest"]["digest"]
    report["package_graph"]["manifest_digest"] = manifest_digest
    execution = report["verifier_execution"]
    execution["manifest_digest"] = manifest_digest
    execution["subject_collection_digest"] = report["package_graph"][
        "collection_digest"
    ]
    native = report["native_diagnostics"]
    execution["native_diagnostic_report_digest"] = native["report_digest"]
    native["prerequisites"]["0"]["manifest_digest"] = manifest_digest
    for depth in ("1", "2"):
        prerequisite = native["prerequisites"].get(depth)
        if prerequisite is not None:
            prerequisite["source_coordinate_digest"] = source_digest
    facet_replay = report.get("package_facet_replay")
    if facet_replay is not None:
        facet_replay["source_coordinate_digest"] = source_digest
        facet_replay["collection_digest"] = report["package_graph"][
            "collection_digest"
        ]
    manifest_refresh = report.get("manifest_refresh")
    if manifest_refresh is not None:
        manifest_refresh["assessed_manifest_digest"] = manifest_digest
        manifest_refresh["assessed_source_coordinate_digest"] = source_digest


def _obligation_instance(tier: int) -> dict:
    return {
        "object_id": f"object-{tier}",
        "object_digest": DIGEST,
        "coordinate": f"OBJECT-{tier}.1",
        "tier": tier,
        "proposition_digest": DIGEST,
        "instance_digest": DIGEST,
        "object_kind": "OBJECT",
        "verifier_id": "verifier-core-self",
        "checking_mechanism": "tests.synthetic.pass_check",
        "scope": "selected package source",
        "reason": "The selected package obligation requires fresh evidence.",
        "repository_realization": {
            "explanation": "Fresh replay binds the selected package source.",
        },
        "applicability": {
            "status": "PASS",
            "classification": "NECESSARY",
            "assessment_required": True,
            "reason": "This obligation is necessary for this object.",
        },
        "selected_package_check": {
            "schema_version": "verifier-package-check-reference-1",
            "status": "PASS",
            "full_check_digest": DIGEST,
            "full_check_bytes": 1,
            "transport": "DIGEST_BOUND_REFERENCE",
            "claim_boundary": "The complete fresh check is digest-bound.",
        },
        "checker_status": "PASS",
        "status": "PASS",
        "blockers": [],
        "native_specimen_is_instance_evidence": False,
        "package_graph_replay_is_instance_evidence": True,
        "declared_kind": "OBJECT",
        "specializations": [],
    }


def _facet_branch(coordinate: str) -> dict:
    return {
        "coordinate": coordinate,
        "semantic_version": "1.0.0",
        "proposition_digest": DIGEST,
        "checking_mechanism": "tests.synthetic.facet_recheck",
        "certificate_schema_version": "synthetic-facet-certificate-1",
        "status": "PASS",
        "case_statuses": {
            "POSITIVE": "PASS",
            "NEGATIVE": "FAIL",
            "UNKNOWN": "UNKNOWN",
        },
        "request_digest": DIGEST,
        "certificate_digests": {
            "POSITIVE": DIGEST,
            "NEGATIVE": DIGEST,
            "UNKNOWN": DIGEST,
        },
        "authority": "NOT_ESTABLISHED",
    }


def _conditional_not_required_check(
    adaptation_result_digest: str = DIGEST,
    *,
    coordinate: str = "OBJECT-1.2",
    object_id: str = "object-1",
    object_digest: str = DIGEST,
    collection_digest: str = DIGEST,
) -> dict:
    route = next(
        route for route in manifest_gate.obligation_catalog()
        if route["coordinate"] == coordinate
    )
    adaptation_obligation_id = "OBJECT-1.90-source-representation-facets"
    reason = (
        "The selected package object is the exact reviewed source representation, "
        "not the retained runtime-domain record required by this native route. "
        "Its necessary adaptation passed at " + adaptation_obligation_id + "."
    )
    body = {
        "status": "PASS",
        "evidence_origin": "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW",
        "object_id": object_id,
        "object_digest": object_digest,
        "collection_digest": collection_digest,
        "reason": reason,
        "applicability_established": True,
        "applicability_classification": "CONDITION_NOT_MET",
        "fulfillment_required": False,
        "native_coordinate": coordinate,
        "conditional_coordinate": coordinate,
        "adaptation_obligation_id": adaptation_obligation_id,
        "adaptation_result_digest": adaptation_result_digest,
        "condition": route["applicability"]["condition"],
        "applicability_digest": route["applicability_digest"],
        "condition_status": "NOT_TRIGGERED",
    }
    return {**body, "result_digest": binding.value_digest(body)}


def _source_contract_selected_check(
    *,
    object_id: str = "object-1",
    object_digest: str = DIGEST,
    collection_digest: str = DIGEST,
) -> dict:
    identifier = "OBJECT-SOURCE-0.1-installed-review-binding"
    body = {
        "status": "PASS",
        "evidence_origin": "INSTALLED_SOURCE_REVIEW_AND_FRESH_DISCOVERY",
        "object_id": object_id,
        "object_digest": object_digest,
        "collection_digest": collection_digest,
        "reason": "The installed source review and discovery passed.",
        "applicability_established": True,
        "applicability_reason": "The exact source variant is selected.",
        "adapter": "verifier-package-source-contracts-1",
        "coordinate": "OBJECT-1.90",
        "covered_admission_obligations": [
            {
                "obligation_id": identifier,
                "reason": (
                    "An OBJECT source-representation result requires the exact "
                    "installed review and current owned-source denominator."
                ),
                "claim_boundary": (
                    "This is source-adapter admission only, not VSTD-T0 credit."
                ),
            }
        ],
        "review_digest": DIGEST,
        "observations": {"owned_path_count": 1},
        "claim_boundary": "Source representation only.",
    }
    return {**body, "result_digest": binding.value_digest(body)}


def _added_kind_instance_selected_check() -> dict:
    route = added_kind_behavioral_routes.catalog()[0]
    body = {
        "schema_version": "verifier-package-added-kind-instance-1",
        "adapter_id": "verifier-retained-added-kind-behavioral-1",
        "status": "PASS",
        "object_id": "market-fixture",
        "object_digest": DIGEST,
        "collection_digest": DIGEST,
        "coordinate": route["coordinate"],
        "obligation_id": route["obligation_id"],
        "semantic_version": route["semantic_version"],
        "proposition_digest": route["proposition_digest"],
        "checking_mechanism": route["checking_mechanism"],
        "evidence_origin": "MANIFEST_SELECTED_ADDED_KIND_INSTANCE",
        "selection_digest": DIGEST,
        "selection": {
            "object_id": "market-fixture",
            "coordinate": route["coordinate"],
        },
        "replay": {"computational_status": "PASS"},
        "reason": route["reason"],
        "applicability_established": True,
        "applicability_reason": route["applicability"]["reason"],
    }
    return {**body, "result_digest": binding.value_digest(body)}


def _pass_report(requested_tier: int = 3) -> dict:
    report = _normal_report()
    report.update(
        requested_tier=requested_tier,
        status="PASS",
        blockers=[],
        findings=[],
        source_coordinate={
            "source_head": "1" * 40,
            "source_tree": "2" * 40,
            "source_worktree_status_digest": DIGEST,
            "source_manifest_digest": DIGEST,
        },
        verifier_execution={
            "object_id": "verifier-core-self",
            "object_digest": DIGEST,
            "subject_id": "package",
            "subject_collection_digest": DIGEST,
            "manifest_digest": DIGEST,
            "assignment": (
                "objects.vstd:surface_rules:installed_route+"
                "installed_mechanism"
            ),
            "checking_mechanism": (
                "verifier.runtime.package_polish.assess_package_polish"
            ),
            "mechanism_digest": DIGEST,
            "requested_tier": requested_tier,
            "self_application": True,
            "self_application_authority": "NOT_ESTABLISHED",
            "native_diagnostic_report_digest": DIGEST,
            "package_facet_replay_digest": DIGEST,
            "obligation_denominator_commitment": {
                "schema_version": (
                    "verifier-package-obligation-denominator-commitment-1"
                ),
                "status": "COMMITTED",
                "selected_instance_count": requested_tier,
                "selected_instance_index_digest": DIGEST,
                "conditional_refutation_count": 0,
                "conditional_refutations": [],
                "conditional_refutations_digest": DIGEST,
                "claim_boundary": (
                    "The selected package-obligation denominator is retained."
                ),
                "commitment_digest": DIGEST,
            },
        },
        package_facet_replay={
            "schema_version": "verifier-package-native-facets-replay-1",
            "status": "PASS",
            "source_coordinate_digest": DIGEST,
            "collection_digest": DIGEST,
            "collection_bytes_digest": DIGEST,
            "generic_mechanism_digest": DIGEST,
            "typed_mechanism_digest": DIGEST,
            "object_count": 1,
            "objective_count": 2,
            "case_count": 6,
            "positive_case_count": 2,
            "negative_case_count": 2,
            "unknown_case_count": 2,
            "pass_count": 2,
            "fail_count": 0,
            "unknown_count": 0,
            "policy_anchor_class": (
                "SELF_SELECTED_SOURCE_BINDING_NOT_AUTHORITY"
            ),
            "results": [
                {
                    "object_id": "object-1",
                    "object_kind": "OBJECT",
                    "status": "PASS",
                    "generic_object_facets": _facet_branch("OBJECT-1.1"),
                    "typed_facets": _facet_branch("OBJECT-1.2"),
                    "resource_status": "AVAILABLE",
                }
            ],
            "claim_boundary": "Fresh facet discrimination only.",
            "replay_digest": DIGEST,
        },
        obligation_instances=[
            _obligation_instance(tier)
            for tier in range(1, requested_tier + 1)
        ],
        tier_results=[
            {
                **row,
                "checker_status_counts": {"PASS": 1},
            }
            for row in _tier_results()[:requested_tier]
        ],
        kind_requirements={
            "status": "PASS",
            "objects": [],
            "source_census_digest": DIGEST,
            "consequence_graph": {},
            "claim_boundary": "Current source-kind classifications only.",
            "contract_coverage": {
                "status": "PASS",
                "denominator_status": "PASS",
                "finite_check_status": "PASS",
                "normative_coverage": "PASS",
                "expected_instance_count": 1,
                "observed_instance_count": 1,
                "findings": [],
                "contracts": [{
                    "status": "PASS",
                    "profile_status": "PASS",
                    "finite_check_status": "PASS",
                    "residual_requirements": [],
                    "clauses": [{"status": "PASS", "closure_status": "PASS"}],
                }],
            },
        },
        refinement_coverage=[],
        execution_observations=[
            {
                "schema_version": "verifier-package-parent-exchange-1",
                "origin": "PARENT_SUBPROCESS_OBSERVATION",
                "outcome": "ACCEPTED",
                "streams_complete": True,
                "returncode": 0,
                "exception_type": None,
                "observation_digest": DIGEST,
            }
        ],
        post_replay_source_recapture="PASS",
        post_replay_manifest_recapture="PASS",
        whole_package_conformance="PASS",
        polished=True,
    )
    report["manifest"]["validation"] = {
        "schema_version": "verifier-tier-zero-manifest-validation-1",
        "status": "PASS",
        "graph_digest": DIGEST,
    }
    if requested_tier == 1:
        del report["native_diagnostics"]["prerequisites"]["2"]
    if requested_tier in (1, 2):
        report["native_diagnostics"]["tier_execution"] = {
            str(depth): report["native_diagnostics"]["tier_execution"][str(depth)]
            for depth in range(requested_tier + 1)
        }
    _rebind_pass_coordinates(report)
    _recompute_cumulative_tier_results(report)
    return _reseal(report)


def _projected_pass_report(*, conditional: bool = False) -> dict:
    report = _pass_report(2)
    rows = report["obligation_instances"]
    if conditional:
        source_check = _source_contract_selected_check()
        source_route = next(
            route for route in package_source_contracts.catalog()
            if route["object_kind"] == "OBJECT" and route["tier"] == 1
        )
        native_route = next(
            route for route in manifest_gate.obligation_catalog()
            if route["coordinate"] == "OBJECT-1.2"
        )
        conditional_row = rows[0]
        conditional_row.update(
            coordinate=native_route["coordinate"],
            proposition_digest=native_route["proposition_digest"],
            checking_mechanism=native_route["checking_mechanism"],
            scope=native_route["scope"],
            checker_status="NOT_REQUIRED",
            package_graph_replay_is_instance_evidence=False,
        )
        conditional_row["applicability"] = {
            "status": "PASS",
            "classification": "CONDITION_NOT_MET",
            "assessment_required": True,
        }
        conditional_row["selected_package_check"] = (
            _conditional_not_required_check(binding.value_digest(source_check))
        )
        conditional_row["applicability"]["reason"] = conditional_row[
            "selected_package_check"
        ]["reason"]
        source_row = deepcopy(conditional_row)
        source_row.update(
            coordinate=source_route["coordinate"],
            proposition_digest=source_route["proposition_digest"],
            checking_mechanism=source_route["checking_mechanism"],
            scope=source_route["scope"],
            reason=source_route["reason"],
            checker_status="PASS",
            selected_package_check=source_check,
            package_graph_replay_is_instance_evidence=False,
            applicability={
                "status": "PASS",
                "classification": "NECESSARY",
                "assessment_required": True,
                "reason": source_check["applicability_reason"],
            },
        )
        rows.append(source_row)
        _rebind_pass_coordinates(report)
    for row in rows:
        identity = {
            key: row[key] for key in (
                "object_id", "object_digest", "coordinate", "tier",
                "proposition_digest",
            )
        }
        row["instance_digest"] = binding.value_digest(identity)
    selected_index = [
        {
            "object_id": row["object_id"],
            "object_kind": row["object_kind"],
            "coordinate": row["coordinate"],
            "tier": row["tier"],
            "instance_digest": row["instance_digest"],
        }
        for row in rows
    ]
    selected_index.sort(key=lambda item: (
        item["tier"], item["object_id"], item["coordinate"],
        item["object_kind"], item["instance_digest"],
    ))
    conditional_refutations = package_polish._conditional_refutation_index(rows)
    commitment_body = {
        "schema_version": (
            "verifier-package-obligation-denominator-commitment-1"
        ),
        "status": "COMMITTED",
        "selected_instance_count": len(rows),
        "selected_instance_index_digest": binding.value_digest(selected_index),
        "conditional_refutation_count": len(conditional_refutations),
        "conditional_refutations": conditional_refutations,
        "conditional_refutations_digest": binding.value_digest(
            conditional_refutations
        ),
        "claim_boundary": (
            "The selected package-obligation denominator is retained."
        ),
    }
    report["verifier_execution"][
        "obligation_denominator_commitment"
    ] = {
        **commitment_body,
        "commitment_digest": binding.value_digest(commitment_body),
    }
    _recompute_cumulative_tier_results(report)
    assert package_polish._attach_successful_instance_projection(
        report, force=True
    )
    return _reseal(report)


def _table_projected_pass_report(*, conditional: bool = False) -> dict:
    report = _projected_pass_report(conditional=conditional)
    assert package_polish._upgrade_successful_instance_projection_v3(report)
    return _reseal(report)


def _table_projected_nonpass_report() -> tuple[dict, dict]:
    report = _pass_report(2)
    nonpass = report["obligation_instances"][1]
    nonpass.update(
        status="FAIL",
        checker_status="FAIL",
        blockers=["Synthetic expanded non-PASS evidence."],
    )
    report.update(
        status="FAIL",
        blockers=["Synthetic expanded non-PASS evidence."],
        whole_package_conformance="NOT_ESTABLISHED",
        polished=False,
    )
    report["tier_results"][1].update(
        status="FAIL",
    )
    _recompute_cumulative_tier_results(report)
    for row in report["obligation_instances"]:
        row["instance_digest"] = binding.value_digest({
            key: row[key] for key in (
                "object_id", "object_digest", "coordinate", "tier",
                "proposition_digest",
            )
        })
    retained_nonpass = deepcopy(nonpass)
    _rebind_denominator_commitment(report)
    _reseal(report)
    assert package_polish._attach_successful_instance_projection(
        report, force=True
    )
    assert package_polish._upgrade_successful_instance_projection_v3(report)
    return _reseal(report), retained_nonpass


def _reconstructed_projected_row(report: dict, row: dict) -> dict:
    realization = row["repository_realization"]
    semantic_definition_digest = realization[
        "semantic_definition_digest"
    ]
    semantic_definition = next(
        item
        for item in report["pass_instance_definitions"]
        if item["definition_digest"] == semantic_definition_digest
    )
    reconstructed = deepcopy(row)
    reconstructed["reason"] = semantic_definition["reason"]
    reconstructed["repository_realization"] = semantic_definition[
        "repository_realization"
    ]
    reconstructed["applicability"] = semantic_definition["applicability"]
    kind_digest = realization.get("kind_requirement_definition_digest")
    if kind_digest is not None:
        kind_definition = next(
            item
            for item in report["pass_instance_definitions"]
            if item["definition_digest"] == kind_digest
        )
        reconstructed["kind_requirement"] = kind_definition[
            "kind_requirement"
        ]
    else:
        reconstructed.pop("kind_requirement", None)
    return reconstructed


def _rebind_projected_source_commitments(report: dict) -> None:
    reconstructed_rows = []
    for row in report["obligation_instances"]:
        if row["status"] == "PASS" and row["blockers"] == []:
            reconstructed = _reconstructed_projected_row(report, row)
            row["repository_realization"]["complete_instance_digest"] = (
                binding.value_digest(reconstructed)
            )
            reconstructed_rows.append(reconstructed)
        else:
            reconstructed_rows.append(row)
    report["obligation_instance_projection"]["source_instances_digest"] = (
        binding.value_digest(reconstructed_rows)
    )


def _rebind_denominator_commitment(report: dict) -> None:
    rows = report["obligation_instances"]
    selected_index = [
        {
            "object_id": row["object_id"],
            "object_kind": row["object_kind"],
            "coordinate": row["coordinate"],
            "tier": row["tier"],
            "instance_digest": row["instance_digest"],
        }
        for row in rows
    ]
    selected_index.sort(key=lambda item: (
        item["tier"], item["object_id"], item["coordinate"],
        item["object_kind"], item["instance_digest"],
    ))
    conditional_refutations = package_polish._conditional_refutation_index(
        rows
    )
    commitment = report["verifier_execution"][
        "obligation_denominator_commitment"
    ]
    commitment.update(
        selected_instance_count=len(rows),
        selected_instance_index_digest=binding.value_digest(selected_index),
        conditional_refutation_count=len(conditional_refutations),
        conditional_refutations_digest=binding.value_digest(
            conditional_refutations
        ),
    )
    if commitment.get("schema_version") == (
        "verifier-package-obligation-denominator-commitment-2"
    ):
        commitment["conditional_refutations_transport"] = (
            "RECONSTRUCT_FROM_PROJECTED_ROWS"
        )
        commitment.pop("conditional_refutations", None)
    else:
        commitment["conditional_refutations"] = conditional_refutations
    commitment_body = {
        key: value for key, value in commitment.items()
        if key != "commitment_digest"
    }
    commitment["commitment_digest"] = binding.value_digest(commitment_body)


def _normal_report() -> dict:
    objects = [
        {
            "object_id": (
                "package" if index == 0
                else "verifier-core-self" if index == 1
                else f"object-{index}"
            ),
            "kind": (
                "GRAPH" if index == 0
                else "VERIFIER" if index == 1
                else "OBJECT"
            ),
            "payload": {},
            "operands": {},
        }
        for index in range(26)
    ]
    return _reseal({
        "schema_version": "verifier-manifest-package-polish-2",
        "claim_scope": "MANIFEST_PACKAGE_GRAPH",
        "kind_denominators": kind_denominators(),
        "requested_tier": 3,
        "status": "UNKNOWN",
        "blockers": ["PACKAGE_INSTANCE_EVIDENCE_INCOMPLETE"],
        "findings": [],
        "next_target": None,
        "manifest": {
            "path": "objects.vstd",
            "status": "SELECTED",
            "digest": DIGEST,
        },
        "manifest_refresh": {
            "schema_version": "verifier-package-polish-refresh-binding-1",
            "status": "PASS",
            "disposition": "NOT_REQUESTED",
            "receipt_reference": None,
            "assessed_manifest_digest": DIGEST,
            "assessed_source_census_digest": None,
            "assessed_source_coordinate_digest": DIGEST,
            "failure_code": None,
            "claim_boundary": (
                "No refresh receipt was supplied; this binds the assessed "
                "manifest and source coordinate without claiming refresh "
                "execution."
            ),
        },
        "source_coordinate": None,
        "source_coordinate_digest": DIGEST,
        "mechanism_digest": DIGEST,
        "package_graph": {
            "status": "PASS",
            "root_id": "package",
            "root_kind": "GRAPH",
            "manifest_digest": DIGEST,
            "collection_digest": DIGEST,
            "object_count": 26,
            "objects": objects,
            "declaration_count": 26,
            "declaration_digest": DIGEST,
            "claim_boundary": "Current package declarations only.",
        },
        "verifier_execution": None,
        "native_diagnostics": _native_diagnostics(),
        "package_facet_replay": None,
        "obligation_instances": [],
        "tier_results": _tier_results(),
        "post_replay_source_recapture": "PASS",
        "post_replay_manifest_recapture": "PASS",
        "whole_package_conformance": "NOT_ESTABLISHED",
        "polished": False,
        "release_authorized": False,
        "deployment_authorized": False,
        "claim_boundary": "Package-polish assessment only.",
        "report_digest": DIGEST,
    })


def _capacity_report() -> dict:
    return _reseal({
        "schema_version": "verifier-manifest-package-polish-capacity-2",
        "source_report_schema": "verifier-manifest-package-polish-2",
        "claim_scope": "MANIFEST_PACKAGE_GRAPH",
        "kind_denominators": kind_denominators(),
        "requested_tier": 3,
        "status": "UNKNOWN",
        "blockers": ["PACKAGE_REPORT_CAPACITY_EXHAUSTED"],
        "manifest": {
            "path": "objects.vstd",
            "status": "SELECTED",
            "digest": DIGEST,
        },
        "package_graph": None,
        "obligation_instances": [],
        "tier_results": _tier_results(),
        "source_coordinate_digest": DIGEST,
        "mechanism_digest": DIGEST,
        "package_graph_reference": {
            "status": "PASS",
            "root_id": "package",
            "root_kind": "GRAPH",
            "manifest_digest": DIGEST,
            "collection_digest": DIGEST,
            "object_count": 26,
            "objects": [
                {
                    "object_id": f"object-{index}",
                    "kind": "OBJECT",
                    "object_digest": DIGEST,
                    "specializations": [],
                }
                for index in range(26)
            ],
        },
        "native_diagnostics": _native_diagnostics(),
        "source_instance_count": 1,
        "denominator_status": "COMPLETE",
        "obligation_index": {
            "schema_version": "verifier-package-obligation-index-1",
            "instance_count": 1,
            "status_counts": {"UNKNOWN": 1},
            "entries": [
                {
                    "object_id": "subject",
                    "object_kind": "OBJECT",
                    "coordinate": "OBJECT-1.1",
                    "obligation_id": "OBJECT-1.1-subject-evidence",
                    "tier": 1,
                    "status": "UNKNOWN",
                    "checker_status": "NOT_RUN",
                    "instance_digest": DIGEST,
                    "blockers": ["PACKAGE_INSTANCE_EVIDENCE_MISSING"],
                    "reason": "Package-instance evidence is missing.",
                    "actions": [],
                    "rerun_argv": [
                        "vstd",
                        "gate",
                        "--object",
                        "subject",
                        "--obligation",
                        "OBJECT-1.1-subject-evidence",
                    ],
                }
            ],
            "index_digest": DIGEST,
        },
        "finding_count": 0,
        "findings": [],
        "next_target": None,
        "omitted_finding_count": 0,
        "source_report_encoding_status": "AVAILABLE",
        "source_report_digest": DIGEST,
        "source_report_bytes": 1,
        "omitted_sections": ["obligation_instances.evidence_bodies"],
        "whole_package_conformance": "NOT_ESTABLISHED",
        "polished": False,
        "release_authorized": False,
        "deployment_authorized": False,
        "claim_boundary": "Bounded fail-closed capacity receipt only.",
        "report_digest": DIGEST,
    })


def _publication_rejection_report() -> dict:
    return {
        "schema_version": (
            "verifier-manifest-package-polish-publication-rejected-1"
        ),
        "status": "UNKNOWN",
        "blockers": ["PACKAGE_POLISH_REPORT_SCHEMA_INVALID"],
        "source_report_schema": "verifier-manifest-package-polish-2",
        "selected_schema_digest": DIGEST,
        "validator_mechanism_digest": DIGEST,
        "source_report_status": "PASS",
        "requested_tier": 1,
        "source_report_encoding_status": "AVAILABLE",
        "source_report_digest": DIGEST,
        "source_report_bytes": 1,
        "validation_error_count": 1,
        "validation_errors": ["/: synthetic publication rejection"],
        "validation_errors_at_limit": False,
        "whole_package_conformance": "NOT_ESTABLISHED",
        "polished": False,
        "release_authorized": False,
        "deployment_authorized": False,
        "claim_boundary": "Bounded fail-closed publication rejection only.",
        "report_digest": DIGEST,
    }


@pytest.mark.parametrize(
    "filename",
    [
        "verifier-manifest-package-polish-2.schema.json",
        "verifier-manifest-package-polish-capacity-2.schema.json",
        (
            "verifier-manifest-package-polish-"
            "publication-rejected-1.schema.json"
        ),
    ],
)
def test_published_cumulative_schemas_are_draft_2020_12_valid(
    filename: str,
) -> None:
    _validator(filename)


@pytest.mark.parametrize(
    ("encoding_status", "digest", "byte_count"),
    [
        ("AVAILABLE", DIGEST, 1),
        ("UNAVAILABLE", None, None),
    ],
)
def test_publication_rejection_source_encoding_states_are_coherent(
    encoding_status: str,
    digest: str | None,
    byte_count: int | None,
) -> None:
    validator = _validator(
        "verifier-manifest-package-polish-publication-rejected-1.schema.json"
    )
    receipt = _publication_rejection_report()
    receipt["source_report_encoding_status"] = encoding_status
    receipt["source_report_digest"] = digest
    receipt["source_report_bytes"] = byte_count
    if encoding_status == "UNAVAILABLE":
        receipt["blockers"] = [
            "PACKAGE_POLISH_REPORT_ENCODING_UNAVAILABLE"
        ]

    validator.validate(receipt)


@pytest.mark.parametrize(
    ("encoding_status", "digest", "byte_count"),
    [
        ("AVAILABLE", None, 1),
        ("AVAILABLE", DIGEST, None),
        ("UNAVAILABLE", DIGEST, None),
        ("UNAVAILABLE", None, 0),
    ],
)
def test_publication_rejection_rejects_false_source_encoding_claims(
    encoding_status: str,
    digest: str | None,
    byte_count: int | None,
) -> None:
    validator = _validator(
        "verifier-manifest-package-polish-publication-rejected-1.schema.json"
    )
    receipt = _publication_rejection_report()
    receipt["source_report_encoding_status"] = encoding_status
    receipt["source_report_digest"] = digest
    receipt["source_report_bytes"] = byte_count

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(receipt)


@pytest.mark.parametrize(
    ("encoding_status", "blocker"),
    [
        ("AVAILABLE", "PACKAGE_POLISH_REPORT_ENCODING_UNAVAILABLE"),
        ("UNAVAILABLE", "PACKAGE_POLISH_REPORT_SCHEMA_INVALID"),
        ("UNAVAILABLE", "PACKAGE_POLISH_REPORT_SCHEMA_UNSUPPORTED"),
    ],
)
def test_publication_rejection_couples_encoding_state_to_blocker(
    encoding_status: str,
    blocker: str,
) -> None:
    validator = _validator(
        "verifier-manifest-package-polish-publication-rejected-1.schema.json"
    )
    receipt = _publication_rejection_report()
    receipt["source_report_encoding_status"] = encoding_status
    receipt["blockers"] = [blocker]
    if encoding_status == "UNAVAILABLE":
        receipt["source_report_digest"] = None
        receipt["source_report_bytes"] = None

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(receipt)


def test_dependency_free_publication_validator_matches_draft_2020_12(
    tmp_path,
) -> None:
    """The runtime gate agrees with jsonschema on every admitted report kind."""
    reports = [
        package_polish.assess_package_polish(3, tmp_path, cancelled=True),
        _normal_report(),
        _capacity_report(),
    ]
    filenames = {
        schema_version: filename
        for schema_version, filename in (
            (
                "verifier-manifest-package-polish-1",
                "verifier-manifest-package-polish-1.schema.json",
            ),
            (
                "verifier-manifest-package-polish-2",
                "verifier-manifest-package-polish-2.schema.json",
            ),
            (
                "verifier-manifest-package-polish-capacity-2",
                "verifier-manifest-package-polish-capacity-2.schema.json",
            ),
        )
    }

    for report in reports:
        reference = _validator(filenames[report["schema_version"]])
        reference.validate(report)
        accepted = (
            package_polish_schema_validation.validate_package_polish_report(
                report
            )
        )
        assert accepted.schema_supported is True
        assert accepted.valid is True
        assert accepted.errors == ()

        rejected_report = deepcopy(report)
        rejected_report["undeclared_publication_authority"] = True
        assert list(reference.iter_errors(rejected_report))
        rejected = (
            package_polish_schema_validation.validate_package_polish_report(
                rejected_report
            )
        )
        assert rejected.schema_supported is True
        assert rejected.valid is False
        assert any("additionalProperties" in error for error in rejected.errors)


@pytest.mark.parametrize("builder", (_normal_report, _capacity_report))
def test_current_reports_require_exact_separate_kind_denominators(builder) -> None:
    report = builder()
    report.pop("kind_denominators")
    _reseal(report)

    rejected = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert rejected.valid is False
    assert any(
        error == "/: required: missing property 'kind_denominators'"
        for error in rejected.errors
    ), rejected.errors


@pytest.mark.parametrize("builder", (_normal_report, _capacity_report))
@pytest.mark.parametrize(
    ("field", "value", "path"),
    (
        (
            "object_kind_count", 38,
            "/kind_denominators/object_kind_count",
        ),
        (
            "object_kind_count", True,
            "/kind_denominators/object_kind_count",
        ),
        (
            "object_kind_denominator_scope", "INSTALLED_NAMESPACE",
            "/kind_denominators/object_kind_denominator_scope",
        ),
        (
            "installed_namespace_kind_count", 26,
            "/kind_denominators/installed_namespace_kind_count",
        ),
        (
            "installed_namespace_kind_count", 37,
            "/kind_denominators/installed_namespace_kind_count",
        ),
        (
            "installed_namespace_kind_count", 39,
            "/kind_denominators/installed_namespace_kind_count",
        ),
        (
            "installed_namespace_kind_count", True,
            "/kind_denominators/installed_namespace_kind_count",
        ),
    ),
)
def test_current_reports_reject_native_namespace_denominator_substitution(
    builder, field: str, value: object, path: str,
) -> None:
    report = builder()
    report["kind_denominators"][field] = value
    _reseal(report)

    rejected = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert rejected.valid is False
    assert any(error.startswith(path + ":") for error in rejected.errors), (
        rejected.errors
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "empty_definitions",
        "wrong_projection_schema",
        "negative_pass_count",
        "wrong_definition_count",
        "wrong_definitions_digest",
        "wrong_definition_digest",
        "missing_definition_reference",
    ],
)
def test_projected_pass_report_rejects_fabricated_projection_commitments(
    mutation: str,
) -> None:
    report = _projected_pass_report()
    assert package_polish_schema_validation.validate_package_polish_report(
        report
    ).valid

    if mutation == "empty_definitions":
        report["pass_instance_definitions"] = []
    elif mutation == "wrong_projection_schema":
        report["obligation_instance_projection"]["schema_version"] = "anything"
    elif mutation == "negative_pass_count":
        report["obligation_instance_projection"]["pass_reference_count"] = -1
    elif mutation == "wrong_definition_count":
        report["obligation_instance_projection"]["definition_count"] += 1
    elif mutation == "wrong_definitions_digest":
        report["obligation_instance_projection"]["definitions_digest"] = DIGEST
    elif mutation == "wrong_definition_digest":
        report["pass_instance_definitions"][0]["definition_digest"] = DIGEST
    elif mutation == "missing_definition_reference":
        report["obligation_instances"][0]["repository_realization"][
            "semantic_definition_digest"
        ] = DIGEST
    _reseal(report)

    rejected = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert rejected.valid is False
    assert rejected.errors


def test_pass_projection_factors_semantic_kind_cross_product() -> None:
    semantic_count = 8
    kind_count = 8
    rows = []
    for semantic_index in range(semantic_count):
        semantic_evidence = (
            f"semantic-{semantic_index}-source-evidence " * 128
        )
        for kind_index in range(kind_count):
            tier = 1 + ((semantic_index * kind_count + kind_index) % 2)
            row = _obligation_instance(tier)
            row.update(
                object_id=f"object-{semantic_index}-{kind_index}",
                coordinate=(
                    f"OBJECT-{tier}.{semantic_index * kind_count + kind_index + 1}"
                ),
                reason=(
                    f"Semantic family {semantic_index} requires this evidence. "
                    + semantic_evidence
                ),
                repository_realization={
                    "explanation": semantic_evidence,
                    "mechanism_bindings": [semantic_evidence] * 4,
                },
                applicability={
                    "status": "PASS",
                    "classification": "NECESSARY",
                    "assessment_required": True,
                    "reason": semantic_evidence,
                },
                kind_requirement={
                    "kind": f"SYNTHETIC_KIND_{kind_index}",
                    "declared": True,
                    "necessity": "NECESSARY",
                    "reasons": [
                        f"Kind family {kind_index} is declared for this row."
                    ],
                    "source_census_digest": DIGEST,
                },
            )
            identity = {
                key: row[key] for key in (
                    "object_id", "object_digest", "coordinate", "tier",
                    "proposition_digest",
                )
            }
            row["instance_digest"] = binding.value_digest(identity)
            rows.append(row)

    report = _pass_report(2)
    report["obligation_instances"] = rows
    _recompute_cumulative_tier_results(report)
    _rebind_denominator_commitment(report)
    _reseal(report)
    unprojected_bytes = len(binding.canonical_bytes(report))

    assert package_polish._attach_successful_instance_projection(
        report, force=True
    )
    _reseal(report)
    projected_bytes = len(binding.canonical_bytes(report))
    definitions = report["pass_instance_definitions"]

    assert report["obligation_instance_projection"]["schema_version"] == (
        "verifier-pass-instance-projection-2"
    )
    assert len(definitions) == semantic_count + kind_count
    assert sum(
        definition["definition_kind"] == "SEMANTIC"
        for definition in definitions
    ) == semantic_count
    assert sum(
        definition["definition_kind"] == "KIND_REQUIREMENT"
        for definition in definitions
    ) == kind_count
    assert len(definitions) < semantic_count * kind_count
    assert projected_bytes * 2 < unprojected_bytes
    assert package_polish_schema_validation.validate_package_polish_report(
        report
    ).valid


@pytest.mark.parametrize("conditional", [False, True])
def test_pass_table_projection_v3_is_exactly_reconstructable(
    conditional: bool,
) -> None:
    report = _table_projected_pass_report(conditional=conditional)
    projection = report["obligation_instance_projection"]

    assert projection["schema_version"] == "verifier-pass-instance-projection-3"
    assert projection["transport"] == "DIGEST_BOUND_PASS_TABLE_REFERENCES"
    assert report["obligation_instances"] == []
    assert projection["pass_reference_count"] == len(projection["pass_entries"])
    assert projection["expanded_nonpass_count"] == 0
    assert projection["expanded_nonpass_source_indexes"] == []
    assert not list(_validator(
        "verifier-manifest-package-polish-2.schema.json"
    ).iter_errors(report))

    validated = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert validated.valid is True, validated.errors


def test_pass_table_projection_v3_keeps_every_nonpass_row_expanded() -> None:
    report, retained_nonpass = _table_projected_nonpass_report()
    projection = report["obligation_instance_projection"]

    assert report["obligation_instances"] == [retained_nonpass]
    assert projection["expanded_nonpass_source_indexes"] == [1]
    assert projection["expanded_nonpass_count"] == 1
    assert projection["source_instance_count"] == 2
    assert package_polish_schema_validation.validate_package_polish_report(
        report
    ).valid


@pytest.mark.parametrize(
    "mutation",
    [
        "object_value_with_resealed_table",
        "unused_object_with_resealed_table",
        "pass_digest_with_resealed_entries",
        "reordered_pass_entries_with_resealed_entries",
        "duplicate_source_index_with_resealed_entries",
        "source_instances_digest",
    ],
)
def test_pass_table_projection_v3_rejects_resealed_tampering(
    mutation: str,
) -> None:
    report = _table_projected_pass_report(conditional=True)
    projection = report["obligation_instance_projection"]
    other_digest = "sha256:" + "b" * 64

    if mutation == "object_value_with_resealed_table":
        projection["object_table"][0][0] += "-forged"
        projection["object_table_digest"] = binding.value_digest(
            projection["object_table"]
        )
    elif mutation == "unused_object_with_resealed_table":
        unused = deepcopy(projection["object_table"][0])
        unused[0] += "-unused"
        projection["object_table"].append(unused)
        projection["object_table_digest"] = binding.value_digest(
            projection["object_table"]
        )
    elif mutation == "pass_digest_with_resealed_entries":
        projection["pass_entries"][0][10] = other_digest
        projection["pass_entries_digest"] = binding.value_digest(
            projection["pass_entries"]
        )
    elif mutation == "reordered_pass_entries_with_resealed_entries":
        projection["pass_entries"][0], projection["pass_entries"][1] = (
            projection["pass_entries"][1],
            projection["pass_entries"][0],
        )
        projection["pass_entries_digest"] = binding.value_digest(
            projection["pass_entries"]
        )
    elif mutation == "duplicate_source_index_with_resealed_entries":
        projection["pass_entries"][1][0] = projection["pass_entries"][0][0]
        projection["pass_entries_digest"] = binding.value_digest(
            projection["pass_entries"]
        )
    elif mutation == "source_instances_digest":
        projection["source_instances_digest"] = other_digest
    _reseal(report)

    rejected = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert rejected.valid is False
    assert any(
        "projectionCommitment" in error for error in rejected.errors
    ), rejected.errors


def test_pass_table_projection_v3_rejects_resealed_nonpass_mutation() -> None:
    report, _ = _table_projected_nonpass_report()
    report["obligation_instances"][0]["reason"] = (
        "Mutated after the full row was evaluated."
    )
    _reseal(report)

    rejected = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert rejected.valid is False
    assert any(
        "source_instances_digest" in error for error in rejected.errors
    ), rejected.errors


@pytest.mark.parametrize(
    "mutation",
    [
        "identity_marker_omitted",
        "identity_marker_forged_field",
        "identity_marker_template_collision",
        "result_marker_omitted",
        "conditional_result_recompute_forged",
    ],
)
def test_pass_table_projection_v3_rejects_resealed_check_projection_forgery(
    mutation: str,
) -> None:
    """Projection metadata cannot omit, forge, or override row identity."""

    report = _table_projected_pass_report(conditional=True)
    projection = report["obligation_instance_projection"]
    old_definitions = list(projection["check_definitions"])
    entry_definitions = [
        old_definitions[entry[9]] for entry in projection["pass_entries"]
    ]
    conditional = next(
        definition for definition in old_definitions
        if definition["checker_status"] == "NOT_REQUIRED"
    )
    template = conditional["template"]
    if mutation == "identity_marker_omitted":
        template.pop("projection_identity_fields")
    elif mutation == "identity_marker_forged_field":
        template["projection_identity_fields"].append("forged_object_key")
    elif mutation == "identity_marker_template_collision":
        template["object_id"] = "forged-subject"
    elif mutation == "result_marker_omitted":
        template.pop("projection_recompute_result_digest")
    else:
        template["projection_recompute_result_digest"] = True

    for definition in old_definitions:
        definition["definition_digest"] = binding.value_digest({
            "checker_status": definition["checker_status"],
            "template": definition["template"],
        })
    projection["check_definitions"] = sorted(
        old_definitions, key=lambda definition: definition["definition_digest"]
    )
    definition_indexes = {
        id(definition): index
        for index, definition in enumerate(projection["check_definitions"])
    }
    for entry, definition in zip(
        projection["pass_entries"], entry_definitions
    ):
        entry[9] = definition_indexes[id(definition)]
    projection["check_definitions_digest"] = binding.value_digest(
        projection["check_definitions"]
    )
    projection["pass_entries_digest"] = binding.value_digest(
        projection["pass_entries"]
    )
    _reseal(report)

    rejected = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert rejected.valid is False
    assert any(
        "projectionCommitment" in error for error in rejected.errors
    ), rejected.errors


def test_pass_table_projection_v3_schema_rejects_inline_pass_row() -> None:
    v2_report = _projected_pass_report()
    inline_pass = deepcopy(v2_report["obligation_instances"][0])
    assert package_polish._upgrade_successful_instance_projection_v3(v2_report)
    v2_report["obligation_instances"].append(inline_pass)
    _reseal(v2_report)

    rejected = package_polish_schema_validation.validate_package_polish_report(
        v2_report
    )

    assert rejected.valid is False
    assert any(
        "/obligation_instances" in error and "not" in error
        for error in rejected.errors
    ), rejected.errors


def test_projected_denominator_commitment_reconstructs_conditional_ledger() -> None:
    report = _projected_pass_report(conditional=True)
    commitment = report["verifier_execution"][
        "obligation_denominator_commitment"
    ]
    reconstructed = package_polish._conditional_refutation_index(
        report["obligation_instances"]
    )

    assert commitment["schema_version"] == (
        "verifier-package-obligation-denominator-commitment-2"
    )
    assert commitment["conditional_refutations_transport"] == (
        "RECONSTRUCT_FROM_PROJECTED_ROWS"
    )
    assert "conditional_refutations" not in commitment
    assert commitment["conditional_refutation_count"] == len(reconstructed)
    assert commitment["conditional_refutations_digest"] == binding.value_digest(
        reconstructed
    )
    assert "result_digest" in report["obligation_instances"][0][
        "selected_package_check"
    ]
    assert package_polish_schema_validation.validate_package_polish_report(
        report
    ).valid


def test_unprojected_report_rejects_reconstructable_denominator_commitment() -> None:
    report = _pass_report(2)
    commitment = report["verifier_execution"][
        "obligation_denominator_commitment"
    ]
    commitment["schema_version"] = (
        "verifier-package-obligation-denominator-commitment-2"
    )
    commitment["conditional_refutations_transport"] = (
        "RECONSTRUCT_FROM_PROJECTED_ROWS"
    )
    commitment.pop("conditional_refutations")
    commitment["commitment_digest"] = binding.value_digest({
        key: value for key, value in commitment.items()
        if key != "commitment_digest"
    })
    _reseal(report)

    rejected = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert rejected.valid is False
    assert any(
        "obligation_denominator_commitment" in error
        for error in rejected.errors
    )


def test_projected_report_rejects_redundant_inline_conditional_ledger() -> None:
    report = _projected_pass_report(conditional=True)
    commitment = report["verifier_execution"][
        "obligation_denominator_commitment"
    ]
    commitment["conditional_refutations"] = (
        package_polish._conditional_refutation_index(
            report["obligation_instances"]
        )
    )
    commitment["commitment_digest"] = binding.value_digest({
        key: value for key, value in commitment.items()
        if key != "commitment_digest"
    })
    _reseal(report)

    rejected = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert rejected.valid is False
    assert any(
        "conditional_refutations" in error for error in rejected.errors
    )


def test_projected_pass_report_rejects_forged_source_instances_digest() -> None:
    report = _projected_pass_report()
    report["obligation_instance_projection"]["source_instances_digest"] = DIGEST
    _reseal(report)

    rejected = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert rejected.valid is False
    assert any(
        "source_instances_digest" in error
        and "reconstructable normalized source rows" in error
        for error in rejected.errors
    )


def test_projected_pass_report_rejects_forged_complete_instance_digest() -> None:
    report = _projected_pass_report()
    report["obligation_instances"][0]["repository_realization"][
        "complete_instance_digest"
    ] = DIGEST
    _reseal(report)

    rejected = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert rejected.valid is False
    assert any(
        "complete_instance_digest" in error
        and "reconstructable normalized source row" in error
        for error in rejected.errors
    )


def test_projected_pass_report_rejects_unused_digest_valid_definition() -> None:
    report = _projected_pass_report()
    unused_definition = deepcopy(next(
        definition
        for definition in report["pass_instance_definitions"]
        if definition["definition_kind"] == "SEMANTIC"
    ))
    unused_definition["reason"] = "Unused digest-valid semantic definition."
    definition_body = {
        key: value for key, value in unused_definition.items()
        if key != "definition_digest"
    }
    unused_definition["definition_digest"] = binding.value_digest(
        definition_body
    )
    report["pass_instance_definitions"].append(unused_definition)
    projection = report["obligation_instance_projection"]
    projection["definition_count"] = len(report["pass_instance_definitions"])
    projection["definitions_digest"] = binding.value_digest(
        report["pass_instance_definitions"]
    )
    _reseal(report)

    rejected = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert rejected.valid is False
    assert any(
        "definitions must be used" in error for error in rejected.errors
    )


def test_projected_pass_report_rejects_fully_recommitted_duplicate_row() -> None:
    report = _projected_pass_report()
    duplicate = deepcopy(report["obligation_instances"][0])
    duplicate["selected_package_check"]["claim_boundary"] = (
        "Distinct transport bytes do not make a duplicate denominator valid."
    )
    report["obligation_instances"].append(duplicate)

    projection = report["obligation_instance_projection"]
    projection.update(
        source_instance_count=3,
        pass_reference_count=3,
        expanded_nonpass_count=0,
    )
    _rebind_projected_source_commitments(report)
    _rebind_denominator_commitment(report)
    _recompute_cumulative_tier_results(report)
    _reseal(report)

    rejected = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert rejected.valid is False
    assert any(
        "coordinate duplicates an earlier row" in error
        for error in rejected.errors
    )


def test_projected_conditional_rejects_fabricated_synchronized_check_reference(
) -> None:
    report = _projected_pass_report(conditional=True)
    row = report["obligation_instances"][0]
    row["selected_package_check"] = {
        "schema_version": "verifier-package-check-reference-1",
        "status": "PASS",
        "full_check_digest": DIGEST,
        "full_check_bytes": 1,
        "transport": "DIGEST_BOUND_REFERENCE",
        "claim_boundary": "Fabricated conditional reference.",
        "reason": "The fabricated reference claims the condition did not trigger.",
    }
    _rebind_projected_source_commitments(report)
    with pytest.raises(
        ValueError,
        match="PACKAGE_CONDITIONAL_REFUTATION_ROUTE_BINDING_INVALID",
    ):
        _rebind_denominator_commitment(report)


def test_projection_rejects_resealed_wrong_applicability_digest() -> None:
    report = _projected_pass_report(conditional=True)
    row = next(
        item for item in report["obligation_instances"]
        if item["checker_status"] == "NOT_REQUIRED"
    )
    check = row["selected_package_check"]
    check["applicability_digest"] = DIGEST
    check["result_digest"] = binding.value_digest({
        key: value for key, value in check.items()
        if key != "result_digest"
    })

    with pytest.raises(
        ValueError,
        match="PACKAGE_CONDITIONAL_REFUTATION_ROUTE_BINDING_INVALID",
    ):
        package_polish._conditional_refutation_index(
            report["obligation_instances"]
        )


def test_projection_rejects_resealed_condition_with_stale_applicability_digest(
) -> None:
    report = _projected_pass_report(conditional=True)
    row = next(
        item for item in report["obligation_instances"]
        if item["checker_status"] == "NOT_REQUIRED"
    )
    check = row["selected_package_check"]
    check["condition"] = "A substituted condition outside the installed route."
    check["result_digest"] = binding.value_digest({
        key: value for key, value in check.items()
        if key != "result_digest"
    })

    with pytest.raises(
        ValueError,
        match="PACKAGE_CONDITIONAL_REFUTATION_ROUTE_BINDING_INVALID",
    ):
        package_polish._conditional_refutation_index(
            report["obligation_instances"]
        )


def test_projected_conditional_rejects_fully_recommitted_authority_forgery(
) -> None:
    report = _projected_pass_report(conditional=True)
    assert package_polish_schema_validation.validate_package_polish_report(
        report
    ).valid
    row = next(
        item for item in report["obligation_instances"]
        if item["checker_status"] == "NOT_REQUIRED"
    )
    check = row["selected_package_check"]
    check["reason"] = (
        "A report-local attacker substituted a different conditional reason."
    )
    check["adaptation_result_digest"] = DIGEST
    check["result_digest"] = binding.value_digest({
        key: value for key, value in check.items()
        if key != "result_digest"
    })
    _rebind_projected_source_commitments(report)
    _rebind_denominator_commitment(report)
    _reseal(report)

    rejected = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert rejected.valid is False
    assert any(
        "conditional source binding differs" in error
        for error in rejected.errors
    )


def test_conditional_binding_accepts_declared_kind_source_companion() -> None:
    """A hinted native kind may bind the source object's real declared kind."""

    route = next(
        row for row in manifest_gate.obligation_catalog()
        if row["coordinate"] == "DATA-1.1"
    )
    source_route = next(
        row for row in package_source_contracts.catalog()
        if row["coordinate"] == "ARCH-1.90"
    )
    check = _conditional_not_required_check(coordinate="DATA-1.1")
    check["adaptation_obligation_id"] = source_route["obligation_id"]
    check["classification_decision_digest"] = DIGEST
    check["result_digest"] = binding.value_digest({
        key: value for key, value in check.items()
        if key != "result_digest"
    })
    source_coordinate = {"fixture": "current-source"}
    report = {
        "source_coordinate": source_coordinate,
        "source_coordinate_digest": binding.value_digest(source_coordinate),
        "post_replay_source_recapture": "PASS",
        "post_replay_manifest_recapture": "PASS",
        "manifest": {"digest": DIGEST},
        "verifier_execution": {"manifest_digest": DIGEST},
        "package_graph": {"manifest_digest": DIGEST},
    }
    row = {
        "object_id": "object-1",
        "object_digest": DIGEST,
        "object_kind": "DATA",
        "coordinate": route["coordinate"],
        "tier": 1,
        "proposition_digest": route["proposition_digest"],
        "checking_mechanism": route["checking_mechanism"],
        "scope": route["scope"],
    }
    companion = {
        "object_id": "object-1",
        "object_digest": DIGEST,
        "object_kind": "ARCH",
        "coordinate": source_route["coordinate"],
        "tier": 1,
        "status": "PASS",
        "checker_status": "PASS",
        "blockers": [],
        "checking_mechanism": source_route["checking_mechanism"],
        "scope": source_route["scope"],
        "selected_package_check": {
            "schema_version": "verifier-package-check-reference-1",
            "status": "PASS",
            "transport": "DIGEST_BOUND_REFERENCE",
            "evidence_origin": "INSTALLED_SOURCE_REVIEW_AND_FRESH_DISCOVERY",
            "full_check_digest": check["adaptation_result_digest"],
        },
    }
    semantic_definition = {
        "applicability": {
            "status": "PASS",
            "classification": "CONDITION_NOT_MET",
            "assessment_required": True,
            "reason": check["reason"],
        },
    }

    assert package_polish_schema_validation._conditional_source_binding_matches(
        report,
        row,
        check,
        semantic_definition,
        {("object-1", "ARCH-1.90"): [companion]},
    )


def test_publication_validator_rejects_recommitted_applicability_forgery(
) -> None:
    report = _projected_pass_report(conditional=True)
    row = next(
        item for item in report["obligation_instances"]
        if item["checker_status"] == "NOT_REQUIRED"
    )
    original_ledger = package_polish._conditional_refutation_index(
        report["obligation_instances"]
    )
    check = row["selected_package_check"]
    check["applicability_digest"] = DIGEST
    check["result_digest"] = binding.value_digest({
        key: value for key, value in check.items()
        if key != "result_digest"
    })
    forged_ledger = deepcopy(original_ledger)
    forged_ledger[0]["evidence_digest"] = binding.value_digest(check)
    commitment = report["verifier_execution"][
        "obligation_denominator_commitment"
    ]
    commitment["conditional_refutations_digest"] = binding.value_digest(
        forged_ledger
    )
    commitment["commitment_digest"] = binding.value_digest({
        key: value for key, value in commitment.items()
        if key != "commitment_digest"
    })
    _rebind_projected_source_commitments(report)
    _reseal(report)

    rejected = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert rejected.valid is False
    assert any(
        "conditional source binding differs" in error
        for error in rejected.errors
    )


def test_projected_conditional_commitment_must_equal_retained_check_binding() -> None:
    report = _projected_pass_report(conditional=True)
    assert package_polish_schema_validation.validate_package_polish_report(
        report
    ).valid
    commitment = report["verifier_execution"][
        "obligation_denominator_commitment"
    ]
    fabricated = package_polish._conditional_refutation_index(
        report["obligation_instances"]
    )
    fabricated[0]["reason"] = "Fabricated reason."
    fabricated[0]["evidence_digest"] = DIGEST
    commitment["conditional_refutations_digest"] = binding.value_digest(
        fabricated
    )
    commitment_body = {
        key: value for key, value in commitment.items()
        if key != "commitment_digest"
    }
    commitment["commitment_digest"] = binding.value_digest(commitment_body)
    _reseal(report)

    rejected = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert rejected.valid is False
    assert any(
        "conditional ledger differs" in error for error in rejected.errors
    )


def test_publication_validator_replays_final_report_digest() -> None:
    report = _normal_report()
    report["report_digest"] = DIGEST

    rejected = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert rejected.valid is False
    assert rejected.errors == (
        "/report_digest: commitment: digest does not seal the published report body",
    )


def test_dependency_free_publication_validator_rejects_unknown_schema() -> None:
    rejected = package_polish_schema_validation.validate_package_polish_report(
        {"schema_version": "verifier-manifest-package-polish-future"}
    )

    assert rejected.schema_supported is False
    assert rejected.valid is False
    assert rejected.errors == (
        "/: schema_version: unsupported or missing package-polish schema",
    )


def test_dependency_free_validator_accepts_integral_json_number_as_integer() -> None:
    report = _normal_report()
    report["package_graph"]["object_count"] = 26.0
    _reseal(report)
    reference = _validator("verifier-manifest-package-polish-2.schema.json")

    reference.validate(report)
    result = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert result.valid is True
    assert result.errors == ()


def test_dependency_free_validator_handles_large_unique_array_linearly(
    tmp_path,
) -> None:
    report = package_polish.assess_package_polish(
        3, tmp_path, cancelled=True
    )
    report["blockers"] = [f"UNIQUE_BLOCKER_{index}" for index in range(8_000)]
    _reseal(report)

    result = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert result.valid is True
    assert result.errors == ()


def test_dependency_free_validator_supports_and_enforces_max_length() -> None:
    schema = {"type": "string", "maxLength": 3}

    assert package_polish_schema_validation._check_schema_document(schema) == ()
    accepted = package_polish_schema_validation._Issues()
    package_polish_schema_validation._validate(
        "abc", schema, schema, "/", accepted, 0,
        package_polish_schema_validation._WorkBudget(),
    )
    assert accepted.values == []

    rejected = package_polish_schema_validation._Issues()
    package_polish_schema_validation._validate(
        "abcd", schema, schema, "/", rejected, 0,
        package_polish_schema_validation._WorkBudget(),
    )
    assert rejected.values == [
        "/: maxLength: length 4 exceeds maximum 3",
    ]


@pytest.mark.parametrize(
    "keyword, instance_type, accepted, rejected",
    [
        ("maxItems", "array", [], [None, None]),
        ("maxLength", "string", "", "ab"),
        ("minItems", "array", [None], []),
        ("minLength", "string", "a", ""),
        ("minProperties", "object", {"key": None}, {}),
    ],
)
def test_dependency_free_validator_accepts_integral_number_size_keywords(
    keyword: str,
    instance_type: str,
    accepted,
    rejected,
) -> None:
    schema = {"type": instance_type, keyword: 1.0}

    jsonschema.Draft202012Validator.check_schema(schema)
    assert package_polish_schema_validation._check_schema_document(schema) == ()

    reference = jsonschema.Draft202012Validator(schema)
    reference.validate(accepted)
    with pytest.raises(jsonschema.ValidationError):
        reference.validate(rejected)

    accepted_issues = package_polish_schema_validation._Issues()
    package_polish_schema_validation._validate(
        accepted, schema, schema, "/", accepted_issues, 0,
        package_polish_schema_validation._WorkBudget(),
    )
    assert accepted_issues.values == []

    rejected_issues = package_polish_schema_validation._Issues()
    package_polish_schema_validation._validate(
        rejected, schema, schema, "/", rejected_issues, 0,
        package_polish_schema_validation._WorkBudget(),
    )
    assert any(f": {keyword}:" in issue for issue in rejected_issues.values)


@pytest.mark.parametrize(
    "malformed",
    [True, -1, -1.0, 1.5, float("nan"), float("inf"), float("-inf"), "1"],
)
def test_dependency_free_validator_rejects_non_integer_size_keywords(
    malformed,
) -> None:
    schema = {"type": "string", "maxLength": malformed}

    with pytest.raises(jsonschema.SchemaError):
        jsonschema.Draft202012Validator.check_schema(schema)
    issues = package_polish_schema_validation._check_schema_document(schema)

    assert issues == (
        "/: maxLength: keyword value must be a non-negative integer",
    )


@pytest.mark.parametrize(
    "keyword, malformed",
    [
        ("$schema", 7),
        ("$id", 7),
        ("title", 7),
        ("$defs", []),
        ("$ref", 7),
        ("additionalProperties", []),
        ("allOf", {}),
        ("anyOf", {}),
        ("oneOf", {}),
        ("prefixItems", {}),
        ("contains", []),
        ("else", []),
        ("if", []),
        ("items", []),
        ("not", []),
        ("then", []),
        ("const", {1, 2}),
        ("enum", {}),
        ("maxItems", "1"),
        ("maxLength", "1"),
        ("minItems", "1"),
        ("minLength", "1"),
        ("minProperties", "1"),
        ("maximum", "1"),
        ("minimum", "1"),
        ("pattern", 7),
        ("properties", []),
        ("required", 7),
        ("type", 7),
        ("uniqueItems", 1),
    ],
)
def test_dependency_free_validator_preflights_every_keyword_shape(
    keyword: str,
    malformed,
) -> None:
    schema = {
        "type": "object",
        "properties": {
            "schema_version": {"const": "synthetic-schema"},
        },
        keyword: malformed,
    }

    issues = package_polish_schema_validation._check_schema_document(schema)

    assert issues
    assert any(f": {keyword}:" in issue for issue in issues)


def test_dependency_free_validator_converts_internal_exception_to_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        package_polish_schema_validation,
        "_validate",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            TypeError("synthetic validator failure")
        ),
    )

    result = package_polish_schema_validation.validate_package_polish_report(
        _normal_report()
    )

    assert result.valid is False
    assert result.errors == (
        "/: validatorException: dependency-free validation raised TypeError",
    )


def test_dependency_free_validator_enforces_total_work_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        package_polish_schema_validation, "MAX_VALIDATION_WORK", 10
    )

    result = package_polish_schema_validation.validate_package_polish_report(
        _normal_report()
    )

    assert result.valid is False
    assert result.errors == (
        "/: workBudget: validation exceeded 10 bounded work units",
    )


def test_dependency_free_validator_does_not_double_charge_container_children(
) -> None:
    """A visited capacity row consumes one unit per schema-node visit.

    The validator already descends into and charges every declared child.  A
    second up-front charge for the parent container's length made a valid
    under-32-MiB Tier 2 capacity receipt exhaust the eight-million-unit budget
    solely because each 12-field obligation entry was counted twice.
    """

    field_names = [f"field_{index}" for index in range(12)]
    instance = [
        {name: "value" for name in field_names}
        for _ in range(100)
    ]
    schema = {
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": False,
            "required": field_names,
            "properties": {
                name: {"type": "string"} for name in field_names
            },
        },
    }
    issues = package_polish_schema_validation._Issues()
    budget = package_polish_schema_validation._WorkBudget(limit=1_400)

    package_polish_schema_validation._validate(
        instance, schema, schema, "/", issues, 0, budget,
    )

    assert issues.values == []
    assert budget.used == 1_301


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_prerequisite_2",
        "missing_execution_2",
        "missing_execution_status_2",
        "wrong_execution_tier_2",
        "missing_tier_result_2",
        "empty_prerequisite_2",
    ],
)
def test_tier3_normal_report_requires_every_cumulative_ledger(
    mutation: str,
) -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _normal_report()
    validator.validate(report)

    invalid = deepcopy(report)
    if mutation == "missing_prerequisite_2":
        del invalid["native_diagnostics"]["prerequisites"]["2"]
    elif mutation == "missing_execution_2":
        del invalid["native_diagnostics"]["tier_execution"]["2"]
    elif mutation == "missing_execution_status_2":
        del invalid["native_diagnostics"]["tier_execution"]["2"][
            "execution_status"
        ]
    elif mutation == "wrong_execution_tier_2":
        invalid["native_diagnostics"]["tier_execution"]["2"]["tier"] = 1
    elif mutation == "missing_tier_result_2":
        invalid["tier_results"][1]["tier"] = 1
    else:
        invalid["native_diagnostics"]["prerequisites"]["2"] = {}

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(invalid)


def test_normal_cumulative_requirement_starts_after_graph_admission() -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _normal_report()
    report["package_graph"] = None
    report["native_diagnostics"] = None
    report["tier_results"] = []

    validator.validate(report)


def test_normal_schema_rejects_vacuous_whole_package_pass() -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _normal_report()
    report.update(
        status="PASS",
        blockers=[],
        findings=[],
        whole_package_conformance="PASS",
        polished=True,
    )
    report["tier_results"] = [
        {**result, "status": "PASS"} for result in report["tier_results"]
    ]

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


@pytest.mark.parametrize("requested_tier", [1, 2, 3])
def test_normal_pass_accepts_exact_requested_tier_shape(
    requested_tier: int,
) -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")

    validator.validate(_pass_report(requested_tier))


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_graph_kind",
        "missing_verifier_kind",
        "blank_object_id",
        "blank_kind",
        "payload_not_object",
        "operands_not_object",
    ],
)
def test_package_graph_requires_shaped_graph_and_verifier_objects(
    mutation: str,
) -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _normal_report()
    objects = report["package_graph"]["objects"]
    validator.validate(report)

    if mutation == "missing_graph_kind":
        objects[0]["kind"] = "OBJECT"
    elif mutation == "missing_verifier_kind":
        objects[1]["kind"] = "OBJECT"
    elif mutation == "blank_object_id":
        objects[2]["object_id"] = ""
    elif mutation == "blank_kind":
        objects[2]["kind"] = ""
    elif mutation == "payload_not_object":
        objects[2]["payload"] = []
    else:
        objects[2]["operands"] = []

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


def test_package_graph_schema_does_not_claim_runtime_membership_or_uniqueness() -> None:
    """Root membership and unique object IDs remain executable invariants."""

    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _normal_report()
    report["package_graph"]["root_id"] = "not-a-retained-object"
    report["package_graph"]["objects"][2]["object_id"] = (
        report["package_graph"]["objects"][3]["object_id"]
    )

    validator.validate(report)


@pytest.mark.parametrize(
    "mutation",
    [
        "empty_source_coordinate",
        "incomplete_source_coordinate",
        "extra_source_coordinate_field",
        "arbitrary_verifier_execution",
        "execution_requested_tier_disagrees",
        "execution_missing_native_binding",
        "execution_missing_denominator_commitment",
        "empty_facet_results",
        "facet_discrimination_is_not_pass",
        "facet_positive_count_is_zero",
        "only_tier_one_obligation",
        "missing_tier_two_obligation",
        "fabricated_tier_identity",
        "fabricated_prerequisite_tiers",
        "fabricated_zero_instance_summary",
        "fabricated_nonpass_status_counts",
        "fabricated_nonpass_checker_counts",
        "native_pass_with_nonpass_execution",
    ],
)
def test_normal_pass_rejects_structurally_unbound_or_incomplete_evidence(
    mutation: str,
) -> None:
    """Reject former PASS bypasses without claiming cross-field arithmetic.

    Draft 2020-12 can require the complete typed receipts and cumulative tier
    identities, but cannot recompute digests or prove arbitrary count equality.
    Runtime validation remains responsible for those semantic equalities.
    """

    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(3)
    validator.validate(report)

    invalid = deepcopy(report)
    if mutation == "empty_source_coordinate":
        invalid["source_coordinate"] = {}
    elif mutation == "incomplete_source_coordinate":
        del invalid["source_coordinate"]["source_manifest_digest"]
    elif mutation == "extra_source_coordinate_field":
        invalid["source_coordinate"]["unbound"] = "value"
    elif mutation == "arbitrary_verifier_execution":
        invalid["verifier_execution"] = {"requested_tier": 3}
    elif mutation == "execution_requested_tier_disagrees":
        invalid["verifier_execution"]["requested_tier"] = 2
    elif mutation == "execution_missing_native_binding":
        del invalid["verifier_execution"]["native_diagnostic_report_digest"]
    elif mutation == "execution_missing_denominator_commitment":
        del invalid["verifier_execution"][
            "obligation_denominator_commitment"
        ]
    elif mutation == "empty_facet_results":
        invalid["package_facet_replay"]["results"] = []
    elif mutation == "facet_discrimination_is_not_pass":
        branch = invalid["package_facet_replay"]["results"][0][
            "generic_object_facets"
        ]
        branch["case_statuses"]["NEGATIVE"] = "PASS"
    elif mutation == "facet_positive_count_is_zero":
        invalid["package_facet_replay"]["positive_case_count"] = 0
    elif mutation == "only_tier_one_obligation":
        invalid["obligation_instances"] = [
            invalid["obligation_instances"][0]
        ]
    elif mutation == "missing_tier_two_obligation":
        invalid["obligation_instances"] = [
            row for row in invalid["obligation_instances"]
            if row["tier"] != 2
        ]
    elif mutation == "fabricated_tier_identity":
        invalid["tier_results"][1]["tier"] = 1
    elif mutation == "fabricated_prerequisite_tiers":
        invalid["tier_results"][2]["prerequisite_tiers"] = [0]
    elif mutation == "fabricated_zero_instance_summary":
        invalid["tier_results"][2]["instance_count"] = 0
    elif mutation == "fabricated_nonpass_status_counts":
        invalid["tier_results"][1]["status_counts"] = {
            "PASS": 1,
            "UNKNOWN": 1,
        }
    elif mutation == "fabricated_nonpass_checker_counts":
        invalid["tier_results"][1]["checker_status_counts"] = {
            "PASS": 1,
            "NOT_RUN": 1,
        }
    else:
        invalid["native_diagnostics"]["tier_execution"]["2"][
            "status"
        ] = "UNKNOWN"

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(invalid)


def test_nonpass_report_validates_any_retained_denominator_commitment() -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(1)
    report.update(
        status="UNKNOWN",
        blockers=["SYNTHETIC_POST_DENOMINATOR_BLOCKER"],
        whole_package_conformance="NOT_ESTABLISHED",
        polished=False,
    )
    validator.validate(report)

    report["verifier_execution"]["obligation_denominator_commitment"][
        "status"
    ] = "PRECOMMITTED"
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


@pytest.mark.parametrize(
    ("requested_tier", "mutation"),
    [
        (1, "missing_zero"),
        (1, "missing_one"),
        (1, "unexpected_two"),
        (1, "nonpass_one"),
        (2, "missing_zero"),
        (2, "missing_one"),
        (2, "missing_two"),
        (2, "nonpass_two"),
    ],
)
def test_tier_one_and_two_pass_require_exact_passing_native_prerequisites(
    requested_tier: int,
    mutation: str,
) -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(requested_tier)
    validator.validate(report)

    prerequisites = report["native_diagnostics"]["prerequisites"]
    if mutation == "missing_zero":
        del prerequisites["0"]
    elif mutation == "missing_one":
        del prerequisites["1"]
    elif mutation == "missing_two":
        del prerequisites["2"]
    elif mutation == "unexpected_two":
        prerequisites["2"] = {
            "status": "PASS",
            "report_digest": DIGEST,
            "source_coordinate_digest": DIGEST,
            "post_replay_full_source_recapture": "PASS",
        }
    elif mutation == "nonpass_one":
        prerequisites["1"]["status"] = "UNKNOWN"
    else:
        prerequisites["2"]["status"] = "FAIL"

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


@pytest.mark.parametrize(
    ("tier", "field", "value"),
    [
        (1, "source_coordinate_digest", None),
        (2, "source_coordinate_digest", None),
        (1, "post_replay_full_source_recapture", None),
        (2, "post_replay_full_source_recapture", None),
        (1, "post_replay_full_source_recapture", "FAIL"),
        (2, "post_replay_full_source_recapture", "UNKNOWN"),
    ],
)
def test_tier_three_pass_requires_source_bound_recaptured_prerequisites(
    tier: int,
    field: str,
    value: str | None,
) -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(3)
    prerequisite = report["native_diagnostics"]["prerequisites"][str(tier)]
    if value is None:
        del prerequisite[field]
    else:
        prerequisite[field] = value

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_validation",
        "validation_not_pass",
        "missing_graph_digest",
        "invalid_graph_digest",
        "wrong_validation_schema",
    ],
)
def test_normal_pass_requires_manifest_validation_binding(mutation: str) -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(3)
    if mutation == "missing_validation":
        del report["manifest"]["validation"]
    elif mutation == "validation_not_pass":
        report["manifest"]["validation"]["status"] = "FAIL"
    elif mutation == "missing_graph_digest":
        del report["manifest"]["validation"]["graph_digest"]
    elif mutation == "wrong_validation_schema":
        report["manifest"]["validation"]["schema_version"] = (
            "verifier-package-manifest-validation-1"
        )
    else:
        report["manifest"]["validation"]["graph_digest"] = "not-a-digest"

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_kind_requirements",
        "missing_refinement_coverage",
        "missing_execution_observations",
        "kind_requirements_not_pass",
        "contract_coverage_not_pass",
        "contract_denominator_not_pass",
        "nonempty_refinement_coverage",
        "observation_wrong_schema",
        "observation_bad_digest",
        "observation_not_accepted",
        "observation_streams_incomplete",
        "observation_nonzero_returncode",
        "observation_exception",
    ],
)
def test_normal_pass_requires_closed_kind_refinement_and_execution_surfaces(
    mutation: str,
) -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(3)
    if mutation == "missing_kind_requirements":
        del report["kind_requirements"]
    elif mutation == "missing_refinement_coverage":
        del report["refinement_coverage"]
    elif mutation == "missing_execution_observations":
        del report["execution_observations"]
    elif mutation == "kind_requirements_not_pass":
        report["kind_requirements"]["status"] = "UNKNOWN"
    elif mutation == "contract_coverage_not_pass":
        report["kind_requirements"]["contract_coverage"]["status"] = (
            "UNKNOWN"
        )
    elif mutation == "contract_denominator_not_pass":
        report["kind_requirements"]["contract_coverage"][
            "denominator_status"
        ] = "FAIL"
    elif mutation == "nonempty_refinement_coverage":
        report["refinement_coverage"] = [{"status": "UNKNOWN"}]
    else:
        observation = report["execution_observations"][0]
        if mutation == "observation_wrong_schema":
            observation["schema_version"] = "verifier-package-parent-exchange-0"
        elif mutation == "observation_bad_digest":
            observation["observation_digest"] = "not-a-digest"
        elif mutation == "observation_not_accepted":
            observation["outcome"] = "LAUNCH_ERROR"
        elif mutation == "observation_streams_incomplete":
            observation["streams_complete"] = False
        elif mutation == "observation_nonzero_returncode":
            observation["returncode"] = 1
        else:
            observation["exception_type"] = "RuntimeError"

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


def test_normal_pass_accepts_no_execution_observations_when_none_were_run() -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(3)
    report["execution_observations"] = []

    validator.validate(report)


@pytest.mark.parametrize(
    "mutation",
    [
        "applicability_unknown",
        "applicability_condition_not_met_for_executed_check",
        "nonempty_blockers",
        "selected_check_missing",
        "selected_check_nonpass",
        "checker_fail",
        "checker_not_run",
        "conditional_applicability_digest_missing",
        "conditional_classification_wrong",
        "conditional_fulfillment_required",
        "conditional_triggered",
    ],
)
def test_normal_pass_rejects_unsubstantiated_obligation_rows(
    mutation: str,
) -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(3)
    row = report["obligation_instances"][0]
    if mutation == "applicability_unknown":
        row["applicability"]["status"] = "UNKNOWN"
    elif mutation == "applicability_condition_not_met_for_executed_check":
        row["applicability"]["classification"] = "CONDITION_NOT_MET"
    elif mutation == "nonempty_blockers":
        row["blockers"] = ["SYNTHETIC_UNCLOSED_EVIDENCE"]
    elif mutation == "selected_check_missing":
        row["selected_package_check"] = None
    elif mutation == "selected_check_nonpass":
        row["selected_package_check"]["status"] = "UNKNOWN"
    elif mutation == "checker_fail":
        row["checker_status"] = "FAIL"
    elif mutation == "checker_not_run":
        row["checker_status"] = "NOT_RUN"
    else:
        row["checker_status"] = "NOT_REQUIRED"
        row["applicability"]["classification"] = "CONDITION_NOT_MET"
        row["selected_package_check"] = _conditional_not_required_check()
        row["package_graph_replay_is_instance_evidence"] = False
        if mutation == "conditional_applicability_digest_missing":
            del row["selected_package_check"]["applicability_digest"]
        elif mutation == "conditional_classification_wrong":
            row["applicability"]["classification"] = "NECESSARY"
        elif mutation == "conditional_fulfillment_required":
            row["selected_package_check"]["fulfillment_required"] = True
        else:
            row["selected_package_check"]["condition_status"] = "TRIGGERED"

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


def test_normal_pass_accepts_evidenced_conditional_not_required_row() -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(3)
    row = report["obligation_instances"][0]
    row["checker_status"] = "NOT_REQUIRED"
    row["applicability"]["classification"] = "CONDITION_NOT_MET"
    row["selected_package_check"] = _conditional_not_required_check()
    row["package_graph_replay_is_instance_evidence"] = False
    report["tier_results"][0]["checker_status_counts"] = {
        "NOT_REQUIRED": 1,
    }

    validator.validate(report)


@pytest.mark.parametrize(
    "mutation",
    [
        "bare_status",
        "partial_reference",
        "necessary_false_fulfillment",
        "necessary_not_triggered_condition",
    ],
)
def test_normal_pass_requires_fully_shaped_nonconditional_selected_check(
    mutation: str,
) -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(3)
    row = report["obligation_instances"][0]
    if mutation == "bare_status":
        row["selected_package_check"] = {"status": "PASS"}
    elif mutation == "partial_reference":
        del row["selected_package_check"]["full_check_digest"]
    elif mutation == "necessary_false_fulfillment":
        row["selected_package_check"]["fulfillment_required"] = False
    else:
        row["selected_package_check"]["condition_status"] = "NOT_TRIGGERED"

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


@pytest.mark.parametrize(
    "selected_check",
    [
        _facet_branch("OBJECT-1.1"),
        {
            "status": "PASS",
            "evidence_origin": "MANIFEST_SELECTED_INSTANCE",
            "object_id": "object-1",
            "object_digest": DIGEST,
            "collection_digest": DIGEST,
            "coordinate": "OBJECT-1.1",
            "semantic_version": "1.0.0",
            "proposition_digest": DIGEST,
            "checking_mechanism": "tests.synthetic.pass_check",
            "selection_digest": DIGEST,
            "selection": {"coordinate": "OBJECT-1.1"},
            "replay": {"computational_status": "PASS"},
            "reason": "The exact selected instance replay passed.",
            "applicability_established": True,
        },
        _source_contract_selected_check(),
    ],
)
def test_normal_pass_accepts_actual_fully_shaped_selected_check_variants(
    selected_check: dict,
) -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(3)
    report["obligation_instances"][0]["selected_package_check"] = deepcopy(
        selected_check
    )

    validator.validate(report)


def test_added_kind_instance_selected_check_accepts_exact_subject_and_route() -> None:
    schema = json.loads(
        files("verifier").joinpath(
            "schemas", "verifier-manifest-package-polish-2.schema.json"
        ).read_text(encoding="utf-8")
    )
    validator = jsonschema.Draft202012Validator({
        "$ref": "#/$defs/addedKindInstanceSelectedCheck",
        "$defs": schema["$defs"],
    })

    validator.validate(_added_kind_instance_selected_check())


@pytest.mark.parametrize(
    ("mutation", "replacement"),
    [
        ("object_id", None),
        ("object_digest", None),
        ("collection_digest", None),
        ("adapter_id", "unregistered-added-kind-adapter"),
        ("evidence_origin", "SOURCE_BOUND_FRESH_EXECUTION"),
    ],
)
def test_added_kind_instance_selected_check_rejects_unbound_identity_or_origin(
    mutation: str,
    replacement: str | None,
) -> None:
    schema = json.loads(
        files("verifier").joinpath(
            "schemas", "verifier-manifest-package-polish-2.schema.json"
        ).read_text(encoding="utf-8")
    )
    validator = jsonschema.Draft202012Validator({
        "$ref": "#/$defs/addedKindInstanceSelectedCheck",
        "$defs": schema["$defs"],
    })
    selected_check = _added_kind_instance_selected_check()
    if replacement is None:
        del selected_check[mutation]
    else:
        selected_check[mutation] = replacement

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(selected_check)


def test_actual_source_contract_producer_result_validates_normal_schema(
    monkeypatch: pytest.MonkeyPatch, tmp_path,
) -> None:
    object_id = "schema-source-object"
    source_digest = "sha256:" + "b" * 64
    review = {
        "primary_kind": "OBJECT",
        "owned_paths": ["fixture.py"],
        "classification": {},
        "declarations": {},
        "claim_boundary": "Fixture source review only.",
    }
    monkeypatch.setattr(
        package_source_contracts,
        "_review_catalog",
        lambda: {object_id: review},
    )
    declaration = {
        "object_id": object_id,
        "kind": "OBJECT",
        "surfaces": ["file:fixture.py"],
        "classification": {},
        "obligations": {},
        "specializations": [],
    }
    kinds = SimpleNamespace(
        registry=namespace_registry(),
        declarations={object_id: declaration},
        census={"files": [{"path": "fixture.py", "sha256": source_digest}]},
        observed={
            "surfaces": [{
                "surface_id": "file:fixture.py",
                "path": "fixture.py",
                "line": 1,
                "form": "file",
                "source_kinds": [],
                "hints": [],
                "unresolved_marker": False,
            }],
            "gaps": [],
            "source_import_bindings": [],
            "export_bindings": [],
        },
        report={"source_census_digest": "sha256:" + "c" * 64},
    )
    item = NamespaceObject.create(
        object_id, "OBJECT", {"representation_role": "fixture"}
    )
    assessment = package_source_contracts.SourceContractAssessment(
        tmp_path, (item,), kinds
    )
    route = next(
        row for row in package_source_contracts.catalog()
        if row["object_kind"] == "OBJECT" and row["tier"] == 1
    )
    produced = assessment.evaluate(item, route)
    assert produced["status"] == "PASS"
    assert produced["covered_admission_obligations"] == (
        route["covered_admission_obligations"]
    )

    report = _pass_report(3)
    report["obligation_instances"][0]["selected_package_check"] = produced
    _validator("verifier-manifest-package-polish-2.schema.json").validate(report)


@pytest.mark.parametrize(
    "mutation",
    [
        "fresh_empty_selection",
        "fresh_empty_replay",
        "source_empty_covered_obligations",
        "source_duplicate_covered_obligations",
        "source_empty_observations",
        "source_missing_reason",
        "source_blank_reason",
        "source_mismatched_reason_shape",
        "source_blank_reason_boundary",
        "source_old_parallel_reason_map",
        "source_legacy_string_ids",
        "source_extra_ledger_field",
    ],
)
def test_selected_check_producer_shapes_require_nonempty_evidence(
    mutation: str,
) -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(3)
    if mutation.startswith("fresh_"):
        selected_check = {
            "status": "PASS",
            "evidence_origin": "SOURCE_BOUND_FRESH_EXECUTION",
            "selection_digest": DIGEST,
            "selection": {"mechanism": "python"},
            "replay": {"observations": ["PASS"]},
            "reason": "The fresh owned execution passed.",
            "applicability_established": True,
        }
        selected_check[
            "selection" if mutation == "fresh_empty_selection" else "replay"
        ] = {}
    else:
        selected_check = _source_contract_selected_check()
        ledger = selected_check["covered_admission_obligations"]
        identifier = ledger[0]["obligation_id"]
        if mutation == "source_empty_covered_obligations":
            selected_check["covered_admission_obligations"] = []
        elif mutation == "source_duplicate_covered_obligations":
            ledger.append(deepcopy(ledger[0]))
        elif mutation == "source_empty_observations":
            selected_check["observations"] = {}
        elif mutation == "source_missing_reason":
            del ledger[0]["reason"]
        elif mutation == "source_blank_reason":
            ledger[0]["reason"] = ""
        elif mutation == "source_mismatched_reason_shape":
            ledger[0]["reason"] = {"unexpected": "mapping"}
        elif mutation == "source_blank_reason_boundary":
            ledger[0]["claim_boundary"] = ""
        elif mutation == "source_old_parallel_reason_map":
            selected_check["covered_admission_obligation_reasons"] = {
                identifier: {
                    "reason": ledger[0]["reason"],
                    "claim_boundary": ledger[0]["claim_boundary"],
                }
            }
        elif mutation == "source_legacy_string_ids":
            selected_check["covered_admission_obligations"] = [identifier]
        else:
            ledger[0]["unmatched_reason_key"] = "not part of the atomic ledger"
    report["obligation_instances"][0]["selected_package_check"] = (
        selected_check
    )

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


def test_conditional_not_required_rejects_package_graph_evidence_claim() -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(3)
    row = report["obligation_instances"][0]
    row["checker_status"] = "NOT_REQUIRED"
    row["applicability"]["classification"] = "CONDITION_NOT_MET"
    row["selected_package_check"] = _conditional_not_required_check()
    row["package_graph_replay_is_instance_evidence"] = True

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


@pytest.mark.parametrize("requested_tier", [1, 2])
@pytest.mark.parametrize(
    "mutation",
    ["missing_ledger", "missing_record", "extra_record", "unsealed_record"],
)
def test_tier_one_and_two_pass_require_exact_native_execution_prefix(
    requested_tier: int,
    mutation: str,
) -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(requested_tier)
    if mutation == "missing_ledger":
        del report["native_diagnostics"]["tier_execution"]
    elif mutation == "missing_record":
        del report["native_diagnostics"]["tier_execution"][
            str(requested_tier)
        ]
    elif mutation == "extra_record":
        extra = requested_tier + 1
        report["native_diagnostics"]["tier_execution"][str(extra)] = (
            deepcopy(_native_diagnostics()["tier_execution"][str(extra)])
        )
    else:
        del report["native_diagnostics"]["tier_execution"]["0"][
            "execution_record_digest"
        ]

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


@pytest.mark.parametrize("requested_tier", [1, 2])
def test_lower_schema_retains_exact_dependency_blocked_native_prefix(
    requested_tier: int,
) -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(requested_tier)
    report.update(
        status="FAIL",
        blockers=["SYNTHETIC_ADMISSION_FAILURE"],
        whole_package_conformance="NOT_ESTABLISHED",
        polished=False,
    )
    native = report["native_diagnostics"]
    native["status"] = "FAIL"
    zero = native["prerequisites"]["0"]
    zero["status"] = "FAIL"
    zero["obligation_status_counts"] = {
        "PASS": 8, "FAIL": 1, "UNKNOWN": 0,
    }
    zero["obligations"][0]["status"] = "FAIL"
    native["tier_execution"]["0"]["status"] = "FAIL"
    blocking = {
        "tier": 0,
        "tier_name": "ADMISSION",
        "required_status": "PASS",
        "observed_status": "FAIL",
        "report_digest": zero["report_digest"],
        "blockers": ["SYNTHETIC_ADMISSION_FAILURE"],
    }
    for depth in range(1, requested_tier + 1):
        native["tier_execution"][str(depth)].update(
            execution_status="NOT_RUN",
            status="UNKNOWN",
            evidence_digest=None,
            blocking_prerequisite=blocking,
        )
        del native["prerequisites"][str(depth)]

    validator.validate(report)

    native["prerequisites"]["1"] = deepcopy(
        _native_diagnostics()["prerequisites"]["1"]
    )
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


def test_tier_three_rejects_extra_native_execution_key() -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(3)
    report["native_diagnostics"]["tier_execution"]["4"] = deepcopy(
        report["native_diagnostics"]["tier_execution"]["3"]
    )

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


@pytest.mark.parametrize("requested_tier", [1, 2, 3])
@pytest.mark.parametrize("mutation", ["wrong_schema", "wrong_tier"])
def test_source_bound_prerequisites_require_exact_schema_and_tier_identity(
    requested_tier: int,
    mutation: str,
) -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(requested_tier)
    tier = 1 if requested_tier == 1 else 2
    prerequisite = report["native_diagnostics"]["prerequisites"][str(tier)]
    if mutation == "wrong_schema":
        prerequisite["schema_version"] = "verifier-self-polish-tier-assessment-6"
    else:
        prerequisite["tier"] = 2 if tier == 1 else 1

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


@pytest.mark.parametrize(
    ("requested_tier", "unexpected_tier"),
    [(1, 2), (1, 3), (2, 3)],
)
def test_normal_pass_forbids_obligations_above_requested_tier(
    requested_tier: int,
    unexpected_tier: int,
) -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _pass_report(requested_tier)
    report["obligation_instances"].append(
        _obligation_instance(unexpected_tier)
    )

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


@pytest.mark.parametrize("requested_tier", [1, 2, 3])
def test_runtime_closes_post_graph_exception_cumulative_accounting(
    requested_tier: int,
) -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _normal_report()
    report["requested_tier"] = requested_tier
    report["status"] = "FAIL"
    report["blockers"] = ["SYNTHETIC_PACKAGE_FACET_EXCEPTION"]
    report["native_diagnostics"] = None
    report["tier_results"] = []

    package_polish._close_incomplete_cumulative_accounting(
        report, tier=requested_tier, stage="PACKAGE_FACET_REPLAY",
    )

    validator.validate(report)
    assert [row["tier"] for row in report["tier_results"]] == list(
        range(1, requested_tier + 1)
    )
    assert all(
        row["execution_status"] == "NOT_RUN"
        for row in report["tier_results"]
    )
    assert set(report["native_diagnostics"]["tier_execution"]) == {
        str(depth) for depth in range(requested_tier + 1)
    }
    assert all(
        row["execution_status"] == "NOT_RUN"
        for row in report["native_diagnostics"]["tier_execution"].values()
    )


def test_normal_exception_keeps_denominator_without_inventing_prerequisite() -> None:
    validator = _validator("verifier-manifest-package-polish-2.schema.json")
    report = _normal_report()
    report["status"] = "UNKNOWN"
    report["native_diagnostics"]["status"] = "UNKNOWN"
    del report["native_diagnostics"]["prerequisites"]["2"]
    for tier in (2, 3):
        execution = report["native_diagnostics"]["tier_execution"][str(tier)]
        execution["execution_status"] = "NOT_RUN"
        execution["status"] = "UNKNOWN"
        execution["evidence_digest"] = None
        execution["blocking_prerequisite"] = {
            "tier": 2,
            "tier_name": "DYNAMICS",
            "required_status": "PASS",
            "observed_status": "UNKNOWN",
            "report_digest": None,
            "blockers": ["SYNTHETIC_TIER2_EXCEPTION"],
        }
    report["native_diagnostics"]["complete_tier_evidence_replay"] = None

    validator.validate(report)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_graph_reference",
        "missing_prerequisite_2",
        "missing_execution_2",
        "missing_execution_status_2",
        "wrong_execution_tier_2",
        "missing_tier_result_2",
        "empty_prerequisite_2",
    ],
)
def test_complete_tier3_capacity_receipt_requires_every_cumulative_ledger(
    mutation: str,
) -> None:
    validator = _validator(
        "verifier-manifest-package-polish-capacity-2.schema.json"
    )
    report = _capacity_report()
    validator.validate(report)

    invalid = deepcopy(report)
    if mutation == "missing_graph_reference":
        invalid["package_graph_reference"] = None
    elif mutation == "missing_prerequisite_2":
        del invalid["native_diagnostics"]["prerequisites"]["2"]
    elif mutation == "missing_execution_2":
        del invalid["native_diagnostics"]["tier_execution"]["2"]
    elif mutation == "missing_execution_status_2":
        del invalid["native_diagnostics"]["tier_execution"]["2"][
            "execution_status"
        ]
    elif mutation == "wrong_execution_tier_2":
        invalid["native_diagnostics"]["tier_execution"]["2"]["tier"] = 1
    elif mutation == "missing_tier_result_2":
        invalid["tier_results"][1]["tier"] = 1
    else:
        invalid["native_diagnostics"]["prerequisites"]["2"] = {}

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(invalid)


def test_not_retained_capacity_receipt_remains_schema_valid_fail_closed() -> None:
    validator = _validator(
        "verifier-manifest-package-polish-capacity-2.schema.json"
    )
    receipt = _capacity_report()
    receipt["package_graph_reference"] = None
    receipt["native_diagnostics"] = None
    receipt["tier_results"] = []
    receipt["denominator_status"] = "NOT_RETAINED"
    receipt["source_instance_count"] = 0
    receipt["obligation_index"]["instance_count"] = 0
    receipt["obligation_index"]["status_counts"] = {}
    receipt["obligation_index"]["entries"] = []
    receipt["omitted_sections"] = ["capacity_receipt_detail_unavailable"]

    validator.validate(receipt)


def test_complete_capacity_exception_keeps_explicit_not_run_denominator() -> None:
    validator = _validator(
        "verifier-manifest-package-polish-capacity-2.schema.json"
    )
    receipt = _capacity_report()
    receipt["native_diagnostics"]["status"] = "UNKNOWN"
    del receipt["native_diagnostics"]["prerequisites"]["2"]
    for tier in (2, 3):
        execution = receipt["native_diagnostics"]["tier_execution"][str(tier)]
        execution["execution_status"] = "NOT_RUN"
        execution["status"] = "UNKNOWN"
        execution["evidence_digest"] = None
        execution["blocking_prerequisite"] = {
            "tier": 2,
            "tier_name": "DYNAMICS",
            "required_status": "PASS",
            "observed_status": "UNKNOWN",
            "report_digest": None,
            "blockers": ["SYNTHETIC_TIER2_EXCEPTION"],
        }
    receipt["native_diagnostics"]["complete_tier_evidence_replay"] = None

    validator.validate(receipt)


@pytest.mark.parametrize(
    ("encoding_status", "digest", "byte_count"),
    [
        ("AVAILABLE", None, 1),
        ("AVAILABLE", DIGEST, None),
        ("UNAVAILABLE", DIGEST, None),
        ("UNAVAILABLE", None, 0),
    ],
)
def test_capacity_source_report_encoding_state_rejects_false_digest_claims(
    encoding_status: str,
    digest: str | None,
    byte_count: int | None,
) -> None:
    validator = _validator(
        "verifier-manifest-package-polish-capacity-2.schema.json"
    )
    receipt = _capacity_report()
    receipt["source_report_encoding_status"] = encoding_status
    receipt["source_report_digest"] = digest
    receipt["source_report_bytes"] = byte_count

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(receipt)

def test_unavailable_source_report_encoding_requires_explicit_nulls() -> None:
    validator = _validator(
        "verifier-manifest-package-polish-capacity-2.schema.json"
    )
    receipt = _capacity_report()
    receipt["denominator_status"] = "NOT_RETAINED"
    receipt["package_graph_reference"] = None
    receipt["native_diagnostics"] = None
    receipt["tier_results"] = []
    receipt["source_instance_count"] = 0
    receipt["obligation_index"]["instance_count"] = 0
    receipt["obligation_index"]["status_counts"] = {}
    receipt["obligation_index"]["entries"] = []
    receipt["omitted_sections"] = ["cumulative_tier_evidence_unavailable"]
    receipt["source_report_encoding_status"] = "UNAVAILABLE"
    receipt["source_report_digest"] = None
    receipt["source_report_bytes"] = None

    validator.validate(receipt)


def test_capacity_source_report_encoding_status_is_required() -> None:
    validator = _validator(
        "verifier-manifest-package-polish-capacity-2.schema.json"
    )
    receipt = _capacity_report()
    del receipt["source_report_encoding_status"]

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(receipt)


def test_former_empty_fake_complete_capacity_receipt_is_rejected() -> None:
    validator = _validator(
        "verifier-manifest-package-polish-capacity-2.schema.json"
    )
    receipt = _capacity_report()
    receipt["package_graph_reference"] = {}
    receipt["source_instance_count"] = 0
    receipt["obligation_index"]["instance_count"] = 0
    receipt["obligation_index"]["status_counts"] = {}
    receipt["obligation_index"]["entries"] = []

    errors = list(validator.iter_errors(receipt))

    assert errors
    assert any(
        tuple(error.absolute_path) == ("package_graph_reference",)
        or tuple(error.absolute_path) == ("source_instance_count",)
        or tuple(error.absolute_path) == ("obligation_index", "instance_count")
        or tuple(error.absolute_path) == ("obligation_index", "entries")
        for error in errors
    )


@pytest.mark.parametrize("report_kind", ["normal", "capacity"])
@pytest.mark.parametrize(
    "mutation",
    [
        "executed_without_evidence",
        "executed_with_blocker",
        "not_run_with_pass",
        "not_run_with_evidence",
        "not_run_without_blocker",
        "blank_reason",
        "wrong_tier_name",
    ],
)
def test_tier_execution_records_reject_incoherent_shapes(
    report_kind: str,
    mutation: str,
) -> None:
    if report_kind == "normal":
        validator = _validator("verifier-manifest-package-polish-2.schema.json")
        report = _normal_report()
    else:
        validator = _validator(
            "verifier-manifest-package-polish-capacity-2.schema.json"
        )
        report = _capacity_report()
    record = report["native_diagnostics"]["tier_execution"]["2"]

    if mutation == "executed_without_evidence":
        record["evidence_digest"] = None
    elif mutation == "executed_with_blocker":
        record["blocking_prerequisite"] = {"tier": 1}
    elif mutation == "not_run_with_pass":
        record["execution_status"] = "NOT_RUN"
        record["evidence_digest"] = None
        record["blocking_prerequisite"] = {"tier": 2}
    elif mutation == "not_run_with_evidence":
        record["execution_status"] = "NOT_RUN"
        record["status"] = "UNKNOWN"
        record["blocking_prerequisite"] = {"tier": 2}
    elif mutation == "not_run_without_blocker":
        record["execution_status"] = "NOT_RUN"
        record["status"] = "UNKNOWN"
        record["evidence_digest"] = None
    elif mutation == "blank_reason":
        record["reason"] = ""
    else:
        record["tier_name"] = "FACETS"

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(report)


def test_complete_capacity_requires_available_source_encoding() -> None:
    validator = _validator(
        "verifier-manifest-package-polish-capacity-2.schema.json"
    )
    receipt = _capacity_report()
    receipt["source_report_encoding_status"] = "UNAVAILABLE"
    receipt["source_report_digest"] = None
    receipt["source_report_bytes"] = None

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(receipt)


@pytest.mark.parametrize("tier", [1, 2, 3])
def test_complete_capacity_requires_nonempty_result_for_every_tier(
    tier: int,
) -> None:
    validator = _validator(
        "verifier-manifest-package-polish-capacity-2.schema.json"
    )
    receipt = _capacity_report()
    receipt["tier_results"][tier - 1]["instance_count"] = 0

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(receipt)


def test_not_retained_capacity_names_missing_cumulative_evidence() -> None:
    validator = _validator(
        "verifier-manifest-package-polish-capacity-2.schema.json"
    )
    receipt = _capacity_report()
    receipt["denominator_status"] = "NOT_RETAINED"
    receipt["omitted_sections"] = ["obligation_instances.evidence_bodies"]

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(receipt)
