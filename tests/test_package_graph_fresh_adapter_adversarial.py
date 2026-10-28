"""Adversarial boundaries for the package-root GRAPH-3.1 fresh adapter."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import jsonschema
import pytest

import test_package_polish_cumulative_schema as cumulative_schema
from verifier.core.namespace import NamespaceObject
from verifier.domains.contracts import graph_statics
from verifier.runtime.package_instance_evidence import InstanceEvidence
from verifier.runtime.namespace_contracts import namespace_registry
from verifier.runtime import package_manifest_migration
from verifier.runtime import package_polish_schema_validation
from verifier.runtime.tier_zero_profile import value_digest


def test_unenriched_package_root_does_not_activate_fresh_projection(
    tmp_path: Path,
) -> None:
    """The adapter is an enriched-package variant, not every root GRAPH route."""

    member = NamespaceObject.create("member", "OBJECT", {})
    nodes = [member.object_id]
    edges: list[dict[str, str]] = []
    graph = NamespaceObject.create(
        "package-root",
        "GRAPH",
        {
            "element_kind": "OBJECT",
            "scope": "retained_directed_graph",
            "nodes_digest": value_digest(nodes),
            "edges_digest": value_digest(edges),
        },
        {"members": nodes},
    )
    objects = (member, graph)
    declaration = {
        "objects": [
            {
                **item.to_dict(),
                "specializations": [],
                "surfaces": [],
                "reason": "Adversarial fixture representation.",
                "classification": {},
                "obligations": {},
            }
            for item in objects
        ]
    }
    evidence = InstanceEvidence(
        tmp_path,
        objects,
        declaration,
        package_graph_id=graph.object_id,
        representation_updates=[],
    )
    route = {
        "coordinate": graph_statics.COORDINATE,
        "semantic_version": graph_statics.SEMANTIC_VERSION,
        "proposition_digest": graph_statics.PROPOSITION_DIGEST,
    }

    assert evidence.evaluate(graph, route) is None


def _selected_package_graph_check() -> dict:
    reason = "The enriched package graph needs its bounded projection."
    boundary = "Package-root GRAPH-3.1 only."
    selection = {
        "schema_version": "verifier-package-graph-projection-selection-1",
        "coordinate": graph_statics.COORDINATE,
        "semantic_version": graph_statics.SEMANTIC_VERSION,
        "proposition_digest": graph_statics.PROPOSITION_DIGEST,
        "original_object_digest": "sha256:" + "1" * 64,
        "original_collection_digest": "sha256:" + "2" * 64,
        "projected_object_digest": "sha256:" + "3" * 64,
        "projected_collection_digest": "sha256:" + "4" * 64,
        "nodes_digest": "sha256:" + "5" * 64,
        "edges_digest": "sha256:" + "6" * 64,
        "source_refresh_coordinate": "sha256:" + "7" * 64,
        "source_semantic_profile_digest": "sha256:" + "8" * 64,
        "evidence_digest": "sha256:" + "9" * 64,
        "request_digest": "sha256:" + "a" * 64,
        "policy_digest": "sha256:" + "b" * 64,
        "certificate_digest": "sha256:" + "c" * 64,
        "adaptation_reason": reason,
        "claim_boundary": boundary,
    }
    replay = {
        "schema_version": "verifier-current-object-route-replay-1",
        "selection": {
            "semantic_version": graph_statics.SEMANTIC_VERSION,
            "objective": graph_statics.COORDINATE,
            "represented_kind": "GRAPH",
        },
        "replay_status": "REPRODUCED",
        "computational_status": "PASS",
        "native_result": {
            "status": "PASS",
            "semantic_version": graph_statics.SEMANTIC_VERSION,
            "coordinate": graph_statics.COORDINATE,
            "object_kind": "GRAPH",
            "scope": graph_statics.SCOPE,
            "object_profile_conformance": "NOT_ESTABLISHED",
            "graph_statics_tier_conformance": "NOT_ESTABLISHED",
            "legacy_graph_profile_conformance": "NOT_ESTABLISHED",
            "evaluation": {"outcome": "PASS"},
        },
        "certificate_sha256": selection["certificate_digest"],
        "request_sha256": selection["request_digest"],
        "policy_sha256": selection["policy_digest"],
        "claim_boundary": "One exact computational GRAPH route replay.",
    }
    check = {
        "schema_version": "verifier-package-graph-fresh-adapter-1",
        "adapter_id": "verifier-fresh-package-graph-statics-projection-1",
        "status": "PASS",
        "evidence_origin": "PACKAGE_GRAPH_BOUND_FRESH_REPLAY",
        "object_id": "package-root",
        "object_digest": selection["original_object_digest"],
        "collection_digest": selection["original_collection_digest"],
        "coordinate": graph_statics.COORDINATE,
        "semantic_version": graph_statics.SEMANTIC_VERSION,
        "proposition_digest": graph_statics.PROPOSITION_DIGEST,
        "checking_mechanism": (
            "verifier.domains.contracts.graph_statics."
            "recheck_graph_statics_certificate"
        ),
        "selection": selection,
        "selection_digest": value_digest(selection),
        "replay": replay,
        "reason": reason,
        "adaptation_reason": reason,
        "claim_boundary": boundary,
        "applicability_established": True,
        "applicability_reason": "The retained dependency graph claim is active.",
    }
    check["result_digest"] = value_digest(check)
    return check


def _manifest_selected_graph_check(
    origin: str = "MANIFEST_SELECTED_INSTANCE",
    *,
    object_id: str = "non-package-graph",
    object_digest: str = cumulative_schema.DIGEST,
    collection_digest: str = cumulative_schema.DIGEST,
) -> dict:
    return {
        "status": "PASS",
        "evidence_origin": origin,
        "object_id": object_id,
        "object_digest": object_digest,
        "collection_digest": collection_digest,
        "coordinate": graph_statics.COORDINATE,
        "obligation_id": "GRAPH-3.1-directed-graph",
        "semantic_version": graph_statics.SEMANTIC_VERSION,
        "proposition_digest": graph_statics.PROPOSITION_DIGEST,
        "checking_mechanism": (
            "verifier.domains.contracts.graph_statics."
            "recheck_graph_statics_certificate"
        ),
        "selection_digest": "sha256:" + "a" * 64,
        "selection": {"coordinate": graph_statics.COORDINATE},
        "replay": {"computational_status": "PASS"},
        "reason": "The exact selected instance replay passed.",
        "applicability_established": True,
    }


def _pass_report_with_graph_row(*, package_root: bool, origin: str) -> dict:
    report = cumulative_schema._pass_report(3)
    row = report["obligation_instances"][0]
    object_id = (
        report["package_graph"]["root_id"]
        if package_root
        else "non-package-graph"
    )
    row.update(
        object_id=object_id,
        object_kind="GRAPH",
        declared_kind="GRAPH",
        coordinate=graph_statics.COORDINATE,
        proposition_digest=graph_statics.PROPOSITION_DIGEST,
        selected_package_check=_manifest_selected_graph_check(
            origin,
            object_id=object_id,
            object_digest=row["object_digest"],
            collection_digest=report["package_graph"]["collection_digest"],
        ),
        checker_status="PASS",
        status="PASS",
        blockers=[],
        package_graph_replay_is_instance_evidence=package_root,
    )
    return cumulative_schema._reseal(report)


def test_fresh_package_graph_schema_requires_result_digest() -> None:
    """An inline adapter result must not lose its producer self-commitment."""

    root = Path(__file__).parents[1]
    schema = json.loads(
        (
            root
            / "src/verifier/schemas/verifier-manifest-package-polish-2.schema.json"
        ).read_bytes()
    )
    validator = jsonschema.Draft202012Validator(
        {
            "$ref": "#/$defs/packageGraphFreshReplaySelectedCheck",
            "$defs": schema["$defs"],
        }
    )
    selected_check = _selected_package_graph_check()
    validator.validate(selected_check)
    missing_commitment = deepcopy(selected_check)
    del missing_commitment["result_digest"]

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(missing_commitment)


@pytest.mark.parametrize(
    "mutation",
    ["result_digest", "selection_digest", "row_object", "native_status"],
)
def test_dependency_free_validator_rejects_graph_adapter_substitution(
    mutation: str,
) -> None:
    check = _selected_package_graph_check()
    row = {
        "object_id": "package-root",
        "object_digest": check["selection"]["original_object_digest"],
        "coordinate": graph_statics.COORDINATE,
        "proposition_digest": graph_statics.PROPOSITION_DIGEST,
        "object_kind": "GRAPH",
        "checker_status": "PASS",
        "status": "PASS",
        "package_graph_replay_is_instance_evidence": True,
        "selected_package_check": check,
    }
    report = {
        "package_graph": {
            "root_id": row["object_id"],
            "root_kind": "GRAPH",
            "collection_digest": check["selection"][
                "original_collection_digest"
            ],
        },
        "obligation_instances": [row],
    }
    if mutation == "result_digest":
        check["reason"] = "Substituted after the result commitment."
    elif mutation == "selection_digest":
        check["selection"]["nodes_digest"] = "sha256:" + "d" * 64
        check["result_digest"] = value_digest(
            {key: value for key, value in check.items() if key != "result_digest"}
        )
    elif mutation == "row_object":
        row["object_digest"] = "sha256:" + "e" * 64
    else:
        check["replay"]["native_result"]["status"] = "FAIL"
        check["result_digest"] = value_digest(
            {key: value for key, value in check.items() if key != "result_digest"}
        )

    issues = package_polish_schema_validation._Issues()
    package_polish_schema_validation._validate_package_graph_fresh_replays(
        report,
        issues,
        package_polish_schema_validation._WorkBudget(),
    )

    assert issues.values


def test_dependency_free_validator_accepts_bound_graph_adapter() -> None:
    check = _selected_package_graph_check()
    row = {
        "object_id": "package-root",
        "object_digest": check["selection"]["original_object_digest"],
        "coordinate": graph_statics.COORDINATE,
        "proposition_digest": graph_statics.PROPOSITION_DIGEST,
        "object_kind": "GRAPH",
        "checker_status": "PASS",
        "status": "PASS",
        "package_graph_replay_is_instance_evidence": True,
        "selected_package_check": check,
    }
    report = {
        "package_graph": {
            "root_id": row["object_id"],
            "root_kind": "GRAPH",
            "collection_digest": check["selection"][
                "original_collection_digest"
            ],
        },
        "obligation_instances": [row],
    }
    issues = package_polish_schema_validation._Issues()

    package_polish_schema_validation._validate_package_graph_fresh_replays(
        report,
        issues,
        package_polish_schema_validation._WorkBudget(),
    )

    assert issues.values == []


@pytest.mark.parametrize(
    "origin",
    ["MANIFEST_SELECTED_INSTANCE", "SOURCE_BOUND_FRESH_EXECUTION"],
)
def test_publication_validator_rejects_non_graph_origin_for_package_root_pass(
    origin: str,
) -> None:
    """A resealed PASS cannot revive the package root's retired evidence path."""

    report = _pass_report_with_graph_row(package_root=True, origin=origin)

    validation = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert not validation.valid
    assert any(
        "packageGraphReplayExclusivity" in error
        for error in validation.errors
    )


def test_publication_validator_preserves_non_root_manifest_graph_replay() -> None:
    """The package-root exception must not erase generic GRAPH evidence."""

    report = _pass_report_with_graph_row(
        package_root=False,
        origin="MANIFEST_SELECTED_INSTANCE",
    )

    validation = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert validation.valid, validation.errors


@pytest.mark.parametrize("status", ["FAIL", "UNKNOWN"])
def test_publication_validator_accepts_honest_nonpass_graph_adapter(
    status: str,
) -> None:
    """Non-PASS adapters self-seal without claiming a projection or replay."""

    report = cumulative_schema._normal_report()
    row = cumulative_schema._obligation_instance(1)
    result_body = {
        "schema_version": "verifier-package-graph-fresh-adapter-1",
        "adapter_id": "verifier-fresh-package-graph-statics-projection-1",
        "status": status,
        "evidence_origin": "PACKAGE_GRAPH_BOUND_FRESH_REPLAY",
        "selection": None,
        "selection_digest": None,
        "replay": None,
        "reason": "Fresh package GRAPH replay did not establish PASS.",
        "applicability_established": False,
    }
    selected_check = {
        **result_body,
        "result_digest": value_digest(result_body),
    }
    row.update(
        object_id="package",
        object_kind="GRAPH",
        declared_kind="GRAPH",
        coordinate=graph_statics.COORDINATE,
        proposition_digest=graph_statics.PROPOSITION_DIGEST,
        selected_package_check=selected_check,
        checker_status=status,
        status=status,
        blockers=["PACKAGE_GRAPH_FRESH_REPLAY_NONPASS"],
        package_graph_replay_is_instance_evidence=True,
    )
    report["obligation_instances"] = [row]
    report["tier_results"][0].update(
        instance_count=1,
        status_counts={status: 1},
        status=status,
        checker_status_counts={status: 1},
    )
    cumulative_schema._reseal(report)

    validation = package_polish_schema_validation.validate_package_polish_report(
        report
    )

    assert validation.valid, validation.errors


def test_dependency_free_validator_preserves_projected_graph_reference() -> None:
    reference = {
        "schema_version": "verifier-package-check-reference-1",
        "status": "PASS",
        "full_check_digest": "sha256:" + "1" * 64,
        "full_check_bytes": 4096,
        "transport": "DIGEST_BOUND_REFERENCE",
        "claim_boundary": "The complete focused check is digest-bound.",
        "evidence_origin": "PACKAGE_GRAPH_BOUND_FRESH_REPLAY",
        "applicability_established": True,
        "reason": "The package root requires GRAPH-3.1.",
    }
    report = {
        "package_graph": {
            "root_id": "package-root",
            "root_kind": "GRAPH",
            "collection_digest": "sha256:" + "2" * 64,
        },
        "obligation_instances": [{
            "object_id": "package-root",
            "selected_package_check": reference,
        }],
    }
    issues = package_polish_schema_validation._Issues()

    package_polish_schema_validation._validate_package_graph_fresh_replays(
        report,
        issues,
        package_polish_schema_validation._WorkBudget(),
    )

    assert issues.values == []


def test_migration_refuses_retirement_when_fresh_adapter_is_unavailable() -> None:
    """Cleanup must establish its replacement before removing selected evidence."""

    graph = NamespaceObject.create(
        "package-root",
        "GRAPH",
        {
            "element_kind": "OBJECT",
            "scope": "retained_directed_graph",
            "nodes_digest": "sha256:" + "1" * 64,
            "edges_digest": "sha256:" + "2" * 64,
        },
    )
    selected = {
        "object_id": graph.object_id,
        "coordinate": graph_statics.COORDINATE,
        "semantic_version": graph_statics.SEMANTIC_VERSION,
        "proposition_digest": graph_statics.PROPOSITION_DIGEST,
    }
    namespace = {
        "objects": [{**graph.to_dict(), "surfaces": []}],
        "instance_checks": [selected],
    }

    with pytest.raises(ValueError):
        package_manifest_migration._retire_package_graph_instance_check(
            namespace,
            namespace_registry(),
            graph.object_id,
            [],
            {},
        )

    assert namespace["instance_checks"] == [selected]
