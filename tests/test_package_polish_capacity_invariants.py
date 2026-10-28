"""Adversarial completeness checks for cumulative capacity receipts.

Terminology: directed acyclic graph (DAG).

Terminology: identifier (ID).

These tests deliberately exercise the compact-report boundary rather than the
full package evaluator.  A capacity receipt may call its denominator COMPLETE
only when every selected package tier and every native execution record through
the requested tier still coheres with the source report.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import jsonschema
import pytest

from verifier.runtime import core_obligation_union as binding
from verifier.runtime import core_tier_progression
from verifier.runtime import manifest_gate
from verifier.runtime import package_polish
from verifier.runtime import tier_zero_manifest
from verifier.runtime.package_kind_requirements import accepts_subject


_DIGEST = "sha256:" + "0" * 64
_DERIVED_CONDITIONAL_TRANSPORT = "RECONSTRUCT_FROM_PROJECTED_ROWS"
_DERIVED_COMMITMENT_SCHEMA = (
    "verifier-package-obligation-denominator-commitment-2"
)
_CAPTURED_TIER_TWO_INSTANCE_COUNT = 5_126
_CAPTURED_TIER_TWO_CONDITIONAL_COUNT = 2_628
_CAPACITY_DEFICIT_BYTES = 297_575
_REQUIRED_SIZE_MARGIN_BYTES = 1 * 1024 * 1024
def _digest(digit: str) -> str:
    return "sha256:" + digit * 64


def _fixture_rows() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    declarations = [
        ("capacity-package-graph", "GRAPH"),
        ("capacity-actor-1", "ACTOR"),
        ("capacity-actor-2", "ACTOR"),
        *[(f"capacity-object-{index}", "OBJECT") for index in range(23)],
    ]
    graph_objects = []
    rows = []
    cells = core_tier_progression.installed_core_route_inventory()[
        "family_cells"
    ]
    for object_id, kind in declarations:
        object_digest = binding.value_digest({
            "object_id": object_id,
            "kind": kind,
        })
        graph_objects.append({
            "object_id": object_id,
            "kind": kind,
            "object_digest": object_digest,
            "specializations": [],
        })
        for cell in cells:
            if cell["object_kind"] != kind or cell["tier"] > 3:
                continue
            for installed in cell["registered_route_memberships"]:
                route = {
                    **installed,
                    "object_kind": kind,
                    "tier": cell["tier"],
                }
                if not accepts_subject(route, kind):
                    continue
                identity = {
                    "object_id": object_id,
                    "object_digest": object_digest,
                    "coordinate": route["coordinate"],
                    "tier": route["tier"],
                    "proposition_digest": route["proposition_digest"],
                }
                rows.append({
                    **identity,
                    "object_kind": kind,
                    "declared_kind": kind,
                    "specializations": [],
                    "checking_mechanism": route["checking_mechanism"],
                    "scope": route["scope"],
                    "status": "UNKNOWN",
                    "checker_status": "NOT_RUN",
                    "instance_digest": binding.value_digest(identity),
                    "blockers": ["PACKAGE_INSTANCE_EVIDENCE_MISSING"],
                    "selected_package_check": None,
                })
    assert len(rows) == 101
    return rows, graph_objects


def _selected_instance_index(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    index = [{
        "object_id": row["object_id"],
        "object_kind": row["object_kind"],
        "coordinate": row["coordinate"],
        "tier": row["tier"],
        "instance_digest": row["instance_digest"],
    } for row in rows]
    index.sort(key=lambda item: (
        item["tier"], item["object_id"], item["coordinate"],
        item["object_kind"], item["instance_digest"],
    ))
    return index


def _commitment(rows: list[dict[str, Any]]) -> dict[str, Any]:
    index = _selected_instance_index(rows)
    conditional_refutations = []
    for row in rows:
        if row.get("checker_status") != "NOT_REQUIRED":
            continue
        check = row.get("selected_package_check")
        conditional_refutations.append({
            "object_id": row["object_id"],
            "object_kind": row["object_kind"],
            "coordinate": row["coordinate"],
            "tier": row["tier"],
            "instance_digest": row["instance_digest"],
            "status": row["status"],
            "checker_status": row["checker_status"],
            "reason": check.get("reason", "") if type(check) is dict else "",
            "evidence_digest": (
                binding.value_digest(check) if type(check) is dict else _DIGEST
            ),
        })
    conditional_refutations.sort(key=lambda item: (
        item["tier"], item["object_id"], item["coordinate"],
        item["instance_digest"],
    ))
    body = {
        "schema_version":
            "verifier-package-obligation-denominator-commitment-1",
        "status": "COMMITTED",
        "selected_instance_count": len(index),
        "selected_instance_index_digest": binding.value_digest(index),
        "conditional_refutation_count": len(conditional_refutations),
        "conditional_refutations": conditional_refutations,
        "conditional_refutations_digest":
            binding.value_digest(conditional_refutations),
        "claim_boundary": "Synthetic exact denominator commitment.",
    }
    return {**body, "commitment_digest": binding.value_digest(body)}


def _reseal_commitment(commitment: dict[str, Any]) -> None:
    commitment["commitment_digest"] = binding.value_digest({
        key: value for key, value in commitment.items()
        if key != "commitment_digest"
    })


def _make_row_conditionally_not_required(
    row: dict[str, Any], route: dict[str, Any] | None = None,
) -> None:
    """Install one complete, self-bound conditional non-trigger on a fixture row."""

    if route is None:
        route = next(
            route for route in manifest_gate.obligation_catalog()
            if route["object_kind"] == row["object_kind"]
            and route["tier"] == row["tier"]
            and route["coordinate"] == row["coordinate"]
            and route["proposition_digest"] == row["proposition_digest"]
            and route["checking_mechanism"] == row["checking_mechanism"]
            and route["scope"] == row["scope"]
        )
    assert route["applicability"]["mode"] == "CONDITIONAL"
    source_obligation_id = (
        f"{route['object_kind']}-{route['tier']}.90-source-representation-"
        + {1: "facets", 2: "dynamics", 3: "statics"}[route["tier"]]
    )
    reason = (
        "The selected package object is the exact reviewed source "
        "representation, not the retained runtime-domain record required by "
        "this native route. Its necessary adaptation passed at "
        + source_obligation_id + "."
    )
    check_body = {
        "status": "PASS",
        "evidence_origin": "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW",
        "object_id": row["object_id"],
        "object_digest": row["object_digest"],
        "collection_digest": _digest("2"),
        "reason": reason,
        "applicability_established": True,
        "applicability_classification": "CONDITION_NOT_MET",
        "fulfillment_required": False,
        "native_coordinate": row["coordinate"],
        "conditional_coordinate": row["coordinate"],
        "adaptation_obligation_id": source_obligation_id,
        "adaptation_result_digest": _digest("d"),
        "condition": route["applicability"]["condition"],
        "applicability_digest": route["applicability_digest"],
        "condition_status": "NOT_TRIGGERED",
    }
    row.update(
        status="PASS",
        checker_status="NOT_REQUIRED",
        blockers=[],
        verifier_id="capacity-verifier",
        reason="The retained runtime variant is conditional for this source object.",
        repository_realization={
            "explanation": "Replay the exact installed source-variant review.",
            "claim_boundary": "The runtime-domain condition remains false.",
        },
        native_specimen_is_instance_evidence=False,
        package_graph_replay_is_instance_evidence=False,
        applicability={
            "status": "PASS",
            "classification": "CONDITION_NOT_MET",
            "assessment_required": True,
            "reason": check_body["reason"],
        },
        selected_package_check={
            **check_body,
            "result_digest": binding.value_digest(check_body),
        },
    )


def _projected_conditional_report() -> tuple[
    dict[str, Any], list[dict[str, Any]],
]:
    """Return a source-coherent report whose PASS row has been projected."""

    report = _valid_tier_three_report()
    _make_row_conditionally_not_required(report["obligation_instances"][0])
    _recommit(report)
    conditional_ledger = package_polish._conditional_refutation_index(
        report["obligation_instances"]
    )
    assert package_polish._attach_successful_instance_projection(
        report, force=True,
    )
    return report, conditional_ledger


def _captured_tier_two_rows() -> list[dict[str, Any]]:
    """Model the retained 5,126-row/2,628-non-trigger capacity incident."""

    routes = {
        tier: next(
            route for route in manifest_gate.obligation_catalog()
            if route["object_kind"] == "OBJECT"
            and route["tier"] == tier
            and route["applicability"]["mode"] == "CONDITIONAL"
        )
        for tier in (1, 2)
    }
    rows = []
    for index in range(_CAPTURED_TIER_TWO_INSTANCE_COUNT):
        conditional = index < _CAPTURED_TIER_TWO_CONDITIONAL_COUNT
        tier = 1 if index % 2 == 0 else 2
        object_id = f"captured-object-{index:04d}"
        route = routes[tier]
        coordinate = route["coordinate"]
        identity = {
            "object_id": object_id,
            "object_digest": binding.value_digest({"object_id": object_id}),
            "coordinate": coordinate,
            "tier": tier,
            "proposition_digest": route["proposition_digest"],
        }
        row = {
            **identity,
            "instance_digest": binding.value_digest(identity),
            "object_kind": "OBJECT",
            "declared_kind": "OBJECT",
            "specializations": [],
            "verifier_id": "captured-verifier",
            "checking_mechanism": route["checking_mechanism"],
            "scope": route["scope"],
            "reason": "The selected package route requires this exact check.",
            "repository_realization": {
                "explanation": "Replay the exact selected package mechanism.",
                "claim_boundary": "The result is bounded to this package source.",
            },
            "applicability": {
                "status": "PASS",
                "classification": "NECESSARY",
                "assessment_required": True,
                "reason": "The installed route applies to this selected object.",
            },
            "selected_package_check": {
                "status": "PASS",
                "evidence_origin": "CAPTURED_TIER_TWO_FIXTURE",
                "report_digest": binding.value_digest({"row": index}),
            },
            "checker_status": "PASS",
            "status": "PASS",
            "blockers": [],
            "native_specimen_is_instance_evidence": False,
            "package_graph_replay_is_instance_evidence": False,
        }
        if conditional:
            _make_row_conditionally_not_required(row, route)
        rows.append(row)

    # Preserve one actionable non-PASS row while retaining the captured total.
    rows[-1].update(
        status="UNKNOWN",
        checker_status="NOT_RUN",
        blockers=["CAPTURED_NONPASS_EVIDENCE_MISSING"],
        selected_package_check=None,
        applicability={
            "status": "UNKNOWN",
            "classification": "UNDETERMINED",
            "assessment_required": True,
            "reason": "The captured non-PASS row remains directly actionable.",
        },
    )
    return rows


def _recompute_tier_results(report: dict[str, Any]) -> None:
    rows = report["obligation_instances"]
    report["tier_results"] = []
    for tier in range(1, 4):
        selected = [row for row in rows if row["tier"] <= tier]
        statuses = {
            status: sum(row["status"] == status for row in selected)
            for status in {row["status"] for row in selected}
        }
        checkers = {
            status: sum(row["checker_status"] == status for row in selected)
            for status in {row["checker_status"] for row in selected}
        }
        report["tier_results"].append({
            "tier": tier,
            "instance_count": len(selected),
            "status_counts": statuses,
            "status": (
                "FAIL" if statuses.get("FAIL", 0) else
                "PASS" if statuses.get("PASS", 0) == len(selected) else
                "UNKNOWN"
            ),
            "checker_status_counts": checkers,
            "prerequisite_tiers": list(range(tier)),
        })


def _recommit(report: dict[str, Any]) -> None:
    _recompute_tier_results(report)
    report["verifier_execution"][
        "obligation_denominator_commitment"
    ] = _commitment(report["obligation_instances"])


def _execution_record(
    tier: int,
    name: str,
    evidence_digest: str,
) -> dict[str, Any]:
    body = {
        "schema_version": "verifier-self-polish-tier-execution-1",
        "tier": tier,
        "tier_name": name,
        "execution_status": "EXECUTED",
        "status": "PASS",
        "reason": f"Fresh Tier {tier} execution completed.",
        "evidence_digest": evidence_digest,
        "blocking_prerequisite": None,
    }
    return {**body, "execution_record_digest": binding.value_digest(body)}


def _reseal_execution(record: dict[str, Any]) -> None:
    record["execution_record_digest"] = binding.value_digest({
        key: value for key, value in record.items()
        if key != "execution_record_digest"
    })


def _valid_tier_three_report() -> dict[str, Any]:
    rows, graph_objects = _fixture_rows()
    validation_repository = "https://example.invalid/verifier.git"
    validation_revision = "a" * 40
    validation_manifest = tier_zero_manifest.manifest_template(
        repository=validation_repository,
        revision=validation_revision,
    )
    validation = tier_zero_manifest.validate_manifest(
        validation_manifest,
        expected_repository=validation_repository,
        expected_revision=validation_revision,
    )
    source_coordinate = {
        "source_head": "1" * 40,
        "source_tree": "2" * 40,
        "source_worktree_status_digest": _digest("3"),
        "source_manifest_digest": _digest("4"),
    }
    source_coordinate_digest = binding.value_digest(source_coordinate)
    tier_results = []
    for tier in range(1, 4):
        count = sum(row["tier"] <= tier for row in rows)
        tier_results.append({
            "tier": tier,
            "instance_count": count,
            "status_counts": {"UNKNOWN": count},
            "status": "UNKNOWN",
            "checker_status_counts": {"NOT_RUN": count},
            "prerequisite_tiers": list(range(tier)),
        })
    prerequisite_digests = {
        str(tier): _digest(str(tier + 6)) for tier in range(3)
    }
    tier_names = ("ADMISSION", "FACETS", "DYNAMICS", "STATICS")
    tier_execution = {
        str(tier): _execution_record(
            tier,
            tier_names[tier],
            prerequisite_digests.get(str(tier), _digest("9")),
        )
        for tier in range(4)
    }
    prerequisites = {
        "0": {
            "status": "PASS",
            "report_digest": prerequisite_digests["0"],
            "manifest_digest": _digest("1"),
            "obligation_count": 9,
            "obligation_status_counts": {"PASS": 9, "FAIL": 0, "UNKNOWN": 0},
            "obligations": [
                {
                    "coordinate": f"VSTD-T0.{index}",
                    "status": "PASS",
                    "assessment_reason": "Repository admission obligation passed.",
                }
                for index in range(1, 10)
            ],
        },
        "1": {
            "schema_version": "verifier-self-polish-tier-assessment-7",
            "tier": 1,
            "status": "PASS",
            "report_digest": prerequisite_digests["1"],
            "source_coordinate_digest": _digest("4"),
            "post_replay_full_source_recapture": "PASS",
            "obligation_count": 1,
            "obligation_status_counts": {"PASS": 1},
        },
        "2": {
            "schema_version": "verifier-self-polish-tier-assessment-7",
            "tier": 2,
            "status": "PASS",
            "report_digest": prerequisite_digests["2"],
            "source_coordinate_digest": _digest("4"),
            "post_replay_full_source_recapture": "PASS",
            "obligation_count": 1,
            "obligation_status_counts": {"PASS": 1},
        },
    }
    report = {
        "schema_version": package_polish.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": (
            package_polish.namespace_contracts.kind_denominators()
        ),
        "requested_tier": 3,
        "status": "UNKNOWN",
        "blockers": ["PACKAGE_INSTANCE_EVIDENCE_INCOMPLETE"],
        "manifest": {
            "path": "objects.vstd",
            "status": "SELECTED",
            "digest": _digest("1"),
            "validation": validation,
        },
        "source_coordinate": source_coordinate,
        "source_coordinate_digest": source_coordinate_digest,
        "mechanism_digest": _digest("5"),
        "package_graph": {
            "status": "PASS",
            "root_id": "capacity-package-graph",
            "root_kind": "GRAPH",
            "object_count": 26,
            "objects": graph_objects,
            "declaration_count": 3,
            "manifest_digest": _digest("1"),
            "collection_digest": _digest("2"),
            "declaration_digest": _digest("3"),
            "object_payloads_transport": "DIGEST_ONLY",
        },
        "native_diagnostics": {
            "schema_version": "verifier-native-diagnostic-reference-1",
            "status": "PASS",
            "report_digest": _DIGEST,
            "complete_tier_evidence_replay": {
                "status": "PASS",
                "evidence_digest": tier_execution["3"]["evidence_digest"],
                "receipt_digest": tier_execution["3"]["evidence_digest"],
                "transport": "DIGEST_BOUND_REFERENCE",
            },
            "prerequisites": prerequisites,
            "tier_execution": tier_execution,
        },
        "tier_results": tier_results,
        "obligation_instances": rows,
    }
    for depth in (1, 2):
        report["native_diagnostics"]["prerequisites"][str(depth)][
            "source_coordinate_digest"
        ] = source_coordinate_digest
    report["verifier_execution"] = {
        "object_id": "capacity-package-verifier",
        "object_digest": _digest("0"),
        "subject_id": "capacity-package-verifier",
        "subject_kind": "VERIFIER",
        "verified_graph_id": "capacity-package-graph",
        "verified_graph_kind": "GRAPH",
        "subject_collection_digest": _digest("2"),
        "manifest_digest": _digest("1"),
        "mechanism_digest": _digest("5"),
        "requested_tier": 3,
        "native_diagnostic_report_digest": _DIGEST,
        "obligation_denominator_commitment": _commitment(rows),
    }
    return report


def _valid_report_through_tier(requested_tier: int) -> dict[str, Any]:
    """Project the exact cumulative source denominator through one tier."""

    assert requested_tier in {1, 2, 3}
    report = _valid_tier_three_report()
    report["requested_tier"] = requested_tier
    report["verifier_execution"]["requested_tier"] = requested_tier
    report["obligation_instances"] = [
        row for row in report["obligation_instances"]
        if row["tier"] <= requested_tier
    ]
    report["tier_results"] = [
        result for result in report["tier_results"]
        if result["tier"] <= requested_tier
    ]
    report["native_diagnostics"]["tier_execution"] = {
        str(depth): report["native_diagnostics"]["tier_execution"][str(depth)]
        for depth in range(requested_tier + 1)
    }
    report["native_diagnostics"]["prerequisites"] = {
        str(depth): report["native_diagnostics"]["prerequisites"][str(depth)]
        for depth in range(min(requested_tier, 2) + 1)
    }
    if requested_tier < 3:
        report["native_diagnostics"].pop("complete_tier_evidence_replay", None)
    report["verifier_execution"][
        "obligation_denominator_commitment"
    ] = _commitment(report["obligation_instances"])
    return report


def _fixture_source_capacity_binding(
    requested_tier: int = 3,
) -> dict[str, Any]:
    """Independent source replay result for the compact synthetic reports.

    The fixture report is deliberately not a real repository checkout. Tests
    therefore install this immutable source-side view rather than allowing a
    mutated report to authenticate itself. Dedicated tests below retain access
    to the real replay function for the current repository root.
    """

    report = _valid_tier_three_report()
    graph = report["package_graph"]
    graph_fields = (
        "status", "root_id", "root_kind", "manifest_digest",
        "collection_digest", "object_count", "declaration_count",
        "declaration_digest", "object_payloads_transport", "objects",
    )
    return {
        "source_coordinate": deepcopy(report["source_coordinate"]),
        "manifest": deepcopy(report["manifest"]),
        "selected_instance_index": [
            row for row in _selected_instance_index(
                report["obligation_instances"]
            )
            if row["tier"] <= requested_tier
        ],
        "conditional_source_authority": {},
        "declaration_profiles": {
            item["object_id"]: {
                "declared_kind": item["kind"],
                "specializations": deepcopy(item["specializations"]),
            }
            for item in graph["objects"]
        },
        "package_graph": {
            key: deepcopy(graph[key])
            for key in graph_fields
            if key in graph
        },
    }


def _install_conditional_source_authority(
    monkeypatch: pytest.MonkeyPatch,
    report: dict[str, Any],
) -> None:
    """Install the independent source checks expected by a conditional fixture."""

    source_binding = _fixture_source_capacity_binding(report["requested_tier"])
    source_binding["conditional_source_authority"] = {
        (row["object_id"], row["coordinate"]): deepcopy(
            row["selected_package_check"]
        )
        for row in report["obligation_instances"]
        if row.get("checker_status") == "NOT_REQUIRED"
    }
    monkeypatch.setattr(
        package_polish,
        "_source_capacity_binding",
        lambda _source_root, _requested_tier: deepcopy(source_binding),
    )


def test_capacity_source_route_prefers_fresh_graph_replay_over_refutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fresh package-GRAPH result wins before a native-variant refutation."""

    route = {
        "object_kind": "GRAPH",
        "tier": 3,
        "coordinate": "GRAPH-3.1",
    }
    item = SimpleNamespace(object_id="vstd-package-graph")
    replay = {
        "status": "PASS",
        "evidence_origin": "PACKAGE_GRAPH_BOUND_FRESH_REPLAY",
    }
    forbidden_refutation = {
        "status": "PASS",
        "condition_status": "NOT_TRIGGERED",
    }
    calls: list[str] = []

    class Evidence:
        def evaluate(self, selected: Any, selected_route: Any) -> dict[str, Any]:
            assert selected is item
            assert selected_route is route
            calls.append("positive")
            return replay

    class SourceAssessment:
        def refute_native_runtime_variant(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
            calls.append("refutation")
            return forbidden_refutation

    monkeypatch.setattr(
        package_polish.package_source_contracts,
        "is_route",
        lambda selected_route: False,
    )
    monkeypatch.setattr(
        package_polish.package_execution,
        "route_mechanism",
        lambda selected_route: None,
    )

    positive, refutation = package_polish._capacity_source_route_outcome(
        SourceAssessment(),
        Evidence(),
        item,
        route,
        object_kind="GRAPH",
        tier=3,
    )

    assert positive == replay
    assert refutation is None
    assert calls == ["positive"]


def test_capacity_source_route_retains_refutation_without_positive_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ordering repair must not erase a real conditional non-trigger."""

    route = {
        "object_kind": "OBJECT",
        "tier": 1,
        "coordinate": "OBJECT-1.1",
    }
    item = SimpleNamespace(object_id="vstd-package-object")
    expected = {
        "status": "PASS",
        "condition_status": "NOT_TRIGGERED",
    }

    class Evidence:
        def evaluate(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    class SourceAssessment:
        def refute_native_runtime_variant(
            self, *_args: Any, **_kwargs: Any,
        ) -> dict[str, Any]:
            return expected

    monkeypatch.setattr(
        package_polish.package_source_contracts,
        "is_route",
        lambda selected_route: False,
    )
    monkeypatch.setattr(
        package_polish.package_execution,
        "route_mechanism",
        lambda selected_route: None,
    )

    positive, refutation = package_polish._capacity_source_route_outcome(
        SourceAssessment(),
        Evidence(),
        item,
        route,
        object_kind="OBJECT",
        tier=1,
    )

    assert positive is None
    assert refutation == expected


def test_capacity_source_route_prefers_fresh_execution_before_refutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Execution-backed routes use their fresh result before source refutation."""

    route = {
        "object_kind": "SIM",
        "tier": 2,
        "coordinate": "SIM-2.4",
    }
    item = SimpleNamespace(object_id="vstd-sim")
    replay = {
        "status": "PASS",
        "evidence_origin": "INSTALLED_FRESH_EXECUTION",
    }
    evidence = SimpleNamespace()
    calls: list[str] = []

    class SourceAssessment:
        def refute_native_runtime_variant(self, *_args: Any, **_kwargs: Any) -> None:
            calls.append("refutation")
            return None

    monkeypatch.setattr(
        package_polish.package_source_contracts,
        "is_route",
        lambda selected_route: False,
    )
    monkeypatch.setattr(
        package_polish.package_execution,
        "route_mechanism",
        lambda selected_route: object(),
    )

    def execute(
        selected_evidence: Any,
        selected_item: Any,
        selected_route: Any,
    ) -> dict[str, Any]:
        assert selected_evidence is evidence
        assert selected_item is item
        assert selected_route is route
        calls.append("execution")
        return replay

    monkeypatch.setattr(package_polish.package_execution, "evaluate", execute)

    positive, refutation = package_polish._capacity_source_route_outcome(
        SourceAssessment(),
        evidence,
        item,
        route,
        object_kind="SIM",
        tier=2,
    )

    assert positive == replay
    assert refutation is None
    assert calls == ["execution"]


@pytest.mark.parametrize(
    "source_replay",
    [
        {"status": "PASS", "evidence_origin": "OWNED_SOURCE_REVIEW"},
        {"status": "FAIL", "evidence_origin": "OWNED_SOURCE_REVIEW"},
        None,
    ],
)
def test_capacity_source_route_never_refutes_a_source_owned_route(
    monkeypatch: pytest.MonkeyPatch,
    source_replay: dict[str, Any] | None,
) -> None:
    """Source-owned routes retain producer precedence even when unavailable."""

    route = {
        "object_kind": "POLICY",
        "tier": 2,
        "coordinate": "POLICY-2.1",
    }
    item = SimpleNamespace(object_id="vstd-policy")
    calls: list[str] = []

    class SourceAssessment:
        def evaluate(self, selected: Any, selected_route: Any) -> dict[str, Any] | None:
            assert selected is item
            assert selected_route is route
            calls.append("source-evaluation")
            return source_replay

        def refute_native_runtime_variant(
            self, *_args: Any, **_kwargs: Any,
        ) -> dict[str, Any]:
            pytest.fail("a source-owned route must never use native refutation")

    monkeypatch.setattr(
        package_polish.package_execution,
        "route_mechanism",
        lambda selected_route: calls.append("execution-classification") or object(),
    )
    monkeypatch.setattr(
        package_polish.package_source_contracts,
        "is_route",
        lambda selected_route: calls.append("source-classification") or True,
    )
    monkeypatch.setattr(
        package_polish.package_execution,
        "evaluate",
        lambda *_args, **_kwargs: pytest.fail(
            "source-owned route must win over execution replay"
        ),
    )

    positive, refutation = package_polish._capacity_source_route_outcome(
        SourceAssessment(),
        SimpleNamespace(),
        item,
        route,
        object_kind="POLICY",
        tier=2,
    )

    assert positive is source_replay
    assert refutation is None
    assert calls == [
        "execution-classification",
        "source-classification",
        "source-evaluation",
    ]


@pytest.mark.parametrize(
    "expected_refutation",
    [
        {"status": "PASS", "condition_status": "NOT_TRIGGERED"},
        None,
    ],
)
def test_capacity_source_route_execution_miss_uses_exact_refutation(
    monkeypatch: pytest.MonkeyPatch,
    expected_refutation: dict[str, Any] | None,
) -> None:
    """An unavailable execution replay falls back with exact route identity."""

    route = {
        "object_kind": "SIM",
        "tier": 2,
        "coordinate": "SIM-2.4",
    }
    item = SimpleNamespace(object_id="vstd-sim")
    evidence = SimpleNamespace()
    calls: list[str] = []

    class SourceAssessment:
        def refute_native_runtime_variant(
            self,
            selected: Any,
            selected_route: Any,
            *,
            object_kind: str,
            tier: int,
        ) -> dict[str, Any] | None:
            assert selected is item
            assert selected_route is route
            assert object_kind == "SIM"
            assert tier == 2
            calls.append("refutation")
            return expected_refutation

    monkeypatch.setattr(
        package_polish.package_execution,
        "route_mechanism",
        lambda selected_route: object(),
    )
    monkeypatch.setattr(
        package_polish.package_source_contracts,
        "is_route",
        lambda selected_route: False,
    )

    def execute(
        selected_evidence: Any,
        selected_item: Any,
        selected_route: Any,
    ) -> None:
        assert selected_evidence is evidence
        assert selected_item is item
        assert selected_route is route
        calls.append("execution")
        return None

    monkeypatch.setattr(package_polish.package_execution, "evaluate", execute)

    positive, refutation = package_polish._capacity_source_route_outcome(
        SourceAssessment(),
        evidence,
        item,
        route,
        object_kind="SIM",
        tier=2,
    )

    assert positive is None
    assert refutation is expected_refutation
    assert calls == ["execution", "refutation"]


@pytest.mark.parametrize("status", ["FAIL", "UNKNOWN"])
def test_capacity_source_route_nonpass_generic_replay_suppresses_refutation(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    """A generic non-PASS replay is observed, not grounds to refute it."""

    route = {
        "object_kind": "GRAPH",
        "tier": 3,
        "coordinate": "GRAPH-3.1",
    }
    item = SimpleNamespace(object_id="vstd-package-graph")
    replay = {
        "status": status,
        "evidence_origin": "PACKAGE_GRAPH_BOUND_FRESH_REPLAY",
    }

    class Evidence:
        def evaluate(self, selected: Any, selected_route: Any) -> dict[str, Any]:
            assert selected is item
            assert selected_route is route
            return replay

    class SourceAssessment:
        def refute_native_runtime_variant(
            self, *_args: Any, **_kwargs: Any,
        ) -> dict[str, Any]:
            pytest.fail("a concrete replay result must suppress refutation")

    monkeypatch.setattr(
        package_polish.package_execution,
        "route_mechanism",
        lambda selected_route: None,
    )
    monkeypatch.setattr(
        package_polish.package_source_contracts,
        "is_route",
        lambda selected_route: False,
    )

    positive, refutation = package_polish._capacity_source_route_outcome(
        SourceAssessment(),
        Evidence(),
        item,
        route,
        object_kind="GRAPH",
        tier=3,
    )

    assert positive is replay
    assert refutation is None


@pytest.fixture(autouse=True)
def _authoritative_source_capacity_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[[str | Path | None, int], dict[str, Any]]:
    """Keep synthetic ledgers behind a fixed, separately built source view."""

    replay = package_polish._source_capacity_binding
    monkeypatch.setattr(
        package_polish,
        "_source_capacity_binding",
        lambda _source_root, requested_tier: deepcopy(
            _fixture_source_capacity_binding(requested_tier)
        ),
    )
    return replay


def _capacity_schema_validator() -> jsonschema.Draft202012Validator:
    schema = json.loads((
        Path(__file__).resolve().parents[1]
        / "src/verifier/schemas/verifier-manifest-package-polish-capacity-2.schema.json"
    ).read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


def _remove_native_tier(report: dict[str, Any]) -> None:
    del report["native_diagnostics"]["tier_execution"]["2"]


def _wrong_native_tier(report: dict[str, Any]) -> None:
    record = report["native_diagnostics"]["tier_execution"]["2"]
    record["tier"] = 7
    _reseal_execution(record)


def _wrong_execution_digest(report: dict[str, Any]) -> None:
    report["native_diagnostics"]["tier_execution"]["2"][
        "execution_record_digest"
    ] = _digest("f")


def _break_prerequisite_coherence(report: dict[str, Any]) -> None:
    record = report["native_diagnostics"]["tier_execution"]["1"]
    record["evidence_digest"] = _digest("e")
    _reseal_execution(record)


def _remove_package_tier_result(report: dict[str, Any]) -> None:
    report["tier_results"] = [
        result for result in report["tier_results"] if result["tier"] != 2
    ]


def _wrong_instance_count(report: dict[str, Any]) -> None:
    report["tier_results"][1]["instance_count"] = 2


def _wrong_tier_status(report: dict[str, Any]) -> None:
    report["tier_results"][1]["status"] = "PASS"


def _wrong_status_counter(report: dict[str, Any]) -> None:
    report["tier_results"][1]["status_counts"] = {"PASS": 1}


def _wrong_checker_counter(report: dict[str, Any]) -> None:
    report["tier_results"][1]["checker_status_counts"] = {"PASS": 1}


def _remove_tier_two_rows(report: dict[str, Any]) -> None:
    report["obligation_instances"] = [
        row for row in report["obligation_instances"] if row["tier"] != 2
    ]


def _remove_tier_three_rows(report: dict[str, Any]) -> None:
    report["obligation_instances"] = [
        row for row in report["obligation_instances"] if row["tier"] != 3
    ]


def _remove_graph_reference_source(report: dict[str, Any]) -> None:
    report["package_graph"] = None


def _native_pass_with_tier_three_not_run(report: dict[str, Any]) -> None:
    record = report["native_diagnostics"]["tier_execution"]["3"]
    record.update(
        execution_status="NOT_RUN",
        status="UNKNOWN",
        evidence_digest=None,
        blocking_prerequisite={
            "tier": 3,
            "tier_name": "STATICS",
            "required_status": "PASS",
            "observed_status": "UNKNOWN",
            "report_digest": None,
            "blockers": ["STATICS_EXECUTION_NOT_COMPLETED"],
        },
    )
    _reseal_execution(record)


def _tier_zero_pass_with_unknown_obligation(report: dict[str, Any]) -> None:
    zero = report["native_diagnostics"]["prerequisites"]["0"]
    zero["obligations"][0]["status"] = "UNKNOWN"
    zero["obligation_status_counts"] = {"PASS": 8, "FAIL": 0, "UNKNOWN": 1}


def _tier_zero_manifest_mismatch(report: dict[str, Any]) -> None:
    report["native_diagnostics"]["prerequisites"]["0"][
        "manifest_digest"
    ] = _digest("e")


def _tier_zero_missing_assessment_reason(report: dict[str, Any]) -> None:
    del report["native_diagnostics"]["prerequisites"]["0"][
        "obligations"
    ][0]["assessment_reason"]


def _extra_native_prerequisite(report: dict[str, Any]) -> None:
    report["native_diagnostics"]["prerequisites"]["extra"] = {
        "status": "PASS",
        "report_digest": _digest("e"),
    }


def _not_run_tier_followed_by_execution(report: dict[str, Any]) -> None:
    record = report["native_diagnostics"]["tier_execution"]["1"]
    record.update(
        execution_status="NOT_RUN",
        status="UNKNOWN",
        evidence_digest=None,
        blocking_prerequisite={
            "tier": 1,
            "tier_name": "FACETS",
            "required_status": "PASS",
            "observed_status": "UNKNOWN",
            "report_digest": None,
            "blockers": ["FACETS_EXECUTION_NOT_COMPLETED"],
        },
    )
    _reseal_execution(record)


def _native_prerequisite_source_mismatch(report: dict[str, Any]) -> None:
    report["native_diagnostics"]["prerequisites"]["1"][
        "source_coordinate_digest"
    ] = _digest("e")


def _ghost_graph_object_binding(report: dict[str, Any]) -> None:
    report["obligation_instances"][0]["object_id"] = "ghost-not-in-graph"


def _route_semantics_mismatch(report: dict[str, Any]) -> None:
    report["obligation_instances"][0]["proposition_digest"] = _digest("e")


def _executed_failure_followed_by_execution(report: dict[str, Any]) -> None:
    prerequisite = report["native_diagnostics"]["prerequisites"]["1"]
    prerequisite["status"] = "FAIL"
    record = report["native_diagnostics"]["tier_execution"]["1"]
    record["status"] = "FAIL"
    _reseal_execution(record)
    report["native_diagnostics"]["status"] = "FAIL"


def _set_not_run_tail(
    report: dict[str, Any], *, different_final_anchor: bool = False,
) -> None:
    anchor = {
        "tier": 2,
        "tier_name": "DYNAMICS",
        "required_status": "PASS",
        "observed_status": "UNKNOWN",
        "report_digest": None,
        "blockers": ["DYNAMICS_EXECUTION_NOT_COMPLETED"],
    }
    for tier in (2, 3):
        selected_anchor = anchor
        if tier == 3 and different_final_anchor:
            selected_anchor = {
                **anchor,
                "tier": 3,
                "tier_name": "STATICS",
                "blockers": ["STATICS_EXECUTION_NOT_COMPLETED"],
            }
        record = report["native_diagnostics"]["tier_execution"][str(tier)]
        record.update(
            execution_status="NOT_RUN",
            status="UNKNOWN",
            evidence_digest=None,
            blocking_prerequisite=selected_anchor,
        )
        _reseal_execution(record)
    report["native_diagnostics"]["status"] = "UNKNOWN"


def _wrong_not_run_anchor(report: dict[str, Any]) -> None:
    _set_not_run_tail(report)
    wrong = {
        "tier": 1,
        "tier_name": "FACETS",
        "required_status": "PASS",
        "observed_status": "UNKNOWN",
        "report_digest": None,
        "blockers": ["FACETS_STATUS_UNKNOWN"],
    }
    for tier in (2, 3):
        record = report["native_diagnostics"]["tier_execution"][str(tier)]
        record["blocking_prerequisite"] = wrong
        _reseal_execution(record)
    del report["native_diagnostics"]["prerequisites"]["2"]


def _different_not_run_anchors(report: dict[str, Any]) -> None:
    _set_not_run_tail(report, different_final_anchor=True)
    del report["native_diagnostics"]["prerequisites"]["2"]


def _unexecuted_tier_retains_prerequisite(report: dict[str, Any]) -> None:
    _set_not_run_tail(report)


def _undeclared_route_kind(report: dict[str, Any]) -> None:
    route = next(
        item for item in manifest_gate.obligation_catalog()
        if item["tier"] == 1 and item["object_kind"] == "SIM"
    )
    row = report["obligation_instances"][0]
    row.update(
        object_kind=route["object_kind"],
        coordinate=route["coordinate"],
        tier=route["tier"],
        proposition_digest=route["proposition_digest"],
        checking_mechanism=route["checking_mechanism"],
        scope=route["scope"],
    )


def _pass_status_with_failed_checker(report: dict[str, Any]) -> None:
    row = report["obligation_instances"][0]
    row.update(status="PASS", checker_status="FAIL", blockers=[])


def _remove_one_mandatory_route(report: dict[str, Any]) -> None:
    report["obligation_instances"].pop()
    _recommit(report)


def _duplicate_route_with_fresh_fake_digest(report: dict[str, Any]) -> None:
    duplicate = deepcopy(report["obligation_instances"][0])
    duplicate["instance_digest"] = _digest("e")
    report["obligation_instances"].append(duplicate)
    _recommit(report)


def _omit_lower_tier_route_for_one_object(report: dict[str, Any]) -> None:
    target = next(
        row for row in report["obligation_instances"]
        if row["object_id"] == "capacity-object-0"
        and row["coordinate"] == "OBJECT-1.2"
    )
    report["obligation_instances"].remove(target)
    _recommit(report)


def _arbitrary_instance_digest(report: dict[str, Any]) -> None:
    report["obligation_instances"][0]["instance_digest"] = "not-a-digest"
    _recommit(report)


def _missing_mechanism_digest(report: dict[str, Any]) -> None:
    report["mechanism_digest"] = None
    report["verifier_execution"]["mechanism_digest"] = None


def _missing_source_coordinate_digest(report: dict[str, Any]) -> None:
    report["source_coordinate_digest"] = None
    for depth in (1, 2):
        report["native_diagnostics"]["prerequisites"][str(depth)][
            "source_coordinate_digest"
        ] = None


def _not_required_without_exact_refutation(report: dict[str, Any]) -> None:
    row = report["obligation_instances"][0]
    row.update(
        status="PASS",
        checker_status="NOT_REQUIRED",
        blockers=[],
        package_graph_replay_is_instance_evidence=False,
        applicability={
            "status": "PASS",
            "classification": "CONDITION_NOT_MET",
            "assessment_required": True,
            "reason": "A condition was claimed not to apply.",
        },
        selected_package_check={
            "status": "PASS",
            "fulfillment_required": False,
            "condition_status": "NOT_TRIGGERED",
        },
    )
    _recommit(report)


def _stale_native_diagnostic_digest(report: dict[str, Any]) -> None:
    report["native_diagnostics"]["report_digest"] = _digest("e")


def _executed_failure_tail(
    report: dict[str, Any], *, anchor_blockers: list[str],
) -> None:
    prerequisite = report["native_diagnostics"]["prerequisites"]["1"]
    prerequisite.update(status="FAIL", blockers=["ACTUAL_CAUSE"])
    record = report["native_diagnostics"]["tier_execution"]["1"]
    record["status"] = "FAIL"
    _reseal_execution(record)
    anchor = {
        "tier": 1,
        "tier_name": "FACETS",
        "required_status": "PASS",
        "observed_status": "FAIL",
        "report_digest": prerequisite["report_digest"],
        "blockers": anchor_blockers,
    }
    for depth in (2, 3):
        record = report["native_diagnostics"]["tier_execution"][str(depth)]
        record.update(
            execution_status="NOT_RUN",
            status="UNKNOWN",
            evidence_digest=None,
            blocking_prerequisite=anchor,
        )
        _reseal_execution(record)
    # Tier 3 did not execute, so the required cumulative reference is null.
    # Retaining its former PASS digest would make this otherwise coherent
    # executed-failure fixture contradict the production schema.
    report["native_diagnostics"]["complete_tier_evidence_replay"] = None
    del report["native_diagnostics"]["prerequisites"]["2"]
    report["native_diagnostics"]["status"] = "FAIL"


def _unrelated_blocking_anchor_reason(report: dict[str, Any]) -> None:
    _executed_failure_tail(report, anchor_blockers=["UNRELATED_CAUSE"])


def _unsupported_source_report_schema(report: dict[str, Any]) -> None:
    report["schema_version"] = "verifier-manifest-package-polish-99"


def _append_tier_four_row(report: dict[str, Any]) -> None:
    route = next(
        item for item in manifest_gate.obligation_catalog()
        if item["tier"] == 4 and item["object_kind"] == "GRAPH"
    )
    template = next(
        row for row in report["obligation_instances"]
        if row["object_id"] == "capacity-package-graph"
    )
    identity = {
        "object_id": template["object_id"],
        "object_digest": template["object_digest"],
        "coordinate": route["coordinate"],
        "tier": route["tier"],
        "proposition_digest": route["proposition_digest"],
    }
    report["obligation_instances"].append({
        **template,
        **identity,
        "object_kind": route["object_kind"],
        "checking_mechanism": route["checking_mechanism"],
        "scope": route["scope"],
        "instance_digest": binding.value_digest(identity),
    })
    _recommit(report)


_INVALID_MUTATIONS: tuple[tuple[str, Callable[[dict[str, Any]], None]], ...] = (
    ("missing native tier execution", _remove_native_tier),
    ("wrong native tier identity", _wrong_native_tier),
    ("wrong native execution digest", _wrong_execution_digest),
    ("native prerequisite digest incoherent", _break_prerequisite_coherence),
    ("missing package tier result", _remove_package_tier_result),
    ("inconsistent package instance count", _wrong_instance_count),
    ("inconsistent package tier status", _wrong_tier_status),
    ("inconsistent package status counter", _wrong_status_counter),
    ("inconsistent package checker counter", _wrong_checker_counter),
    ("no Tier 2 obligation rows", _remove_tier_two_rows),
    ("no Tier 3 obligation rows", _remove_tier_three_rows),
    ("missing package graph reference source", _remove_graph_reference_source),
    ("native PASS with Tier 3 not run", _native_pass_with_tier_three_not_run),
    ("Tier 0 PASS with an UNKNOWN obligation", _tier_zero_pass_with_unknown_obligation),
    ("Tier 0 manifest differs", _tier_zero_manifest_mismatch),
    ("Tier 0 assessment reason missing", _tier_zero_missing_assessment_reason),
    ("extra native prerequisite retained", _extra_native_prerequisite),
    ("NOT_RUN tier followed by execution", _not_run_tier_followed_by_execution),
    ("native prerequisite source differs", _native_prerequisite_source_mismatch),
    ("obligation object absent from graph", _ghost_graph_object_binding),
    ("installed route semantics differ", _route_semantics_mismatch),
    ("executed failure followed by execution", _executed_failure_followed_by_execution),
    ("wrong NOT_RUN anchor", _wrong_not_run_anchor),
    ("different NOT_RUN anchors", _different_not_run_anchors),
    ("unexecuted tier retains prerequisite", _unexecuted_tier_retains_prerequisite),
    ("route kind not declared or specialized", _undeclared_route_kind),
    ("PASS status with failed checker", _pass_status_with_failed_checker),
    ("one mandatory route omitted", _remove_one_mandatory_route),
    ("duplicate route with fresh fake digest", _duplicate_route_with_fresh_fake_digest),
    ("lower-tier route omitted for one object", _omit_lower_tier_route_for_one_object),
    ("arbitrary instance digest", _arbitrary_instance_digest),
    ("mechanism digest missing", _missing_mechanism_digest),
    ("source coordinate digest missing", _missing_source_coordinate_digest),
    ("NOT_REQUIRED lacks exact refutation", _not_required_without_exact_refutation),
    ("native diagnostic digest stale", _stale_native_diagnostic_digest),
    ("blocking anchor reason differs", _unrelated_blocking_anchor_reason),
    ("unsupported source report schema", _unsupported_source_report_schema),
    ("row exceeds requested tier", _append_tier_four_row),
)


@pytest.mark.parametrize(
    ("requested_tier", "expected_instance_count"),
    [(1, 49), (2, 75)],
)
def test_complete_lower_tier_capacity_receipt_matches_exact_cumulative_shape(
    requested_tier: int,
    expected_instance_count: int,
) -> None:
    receipt = package_polish._capacity_receipt(
        _valid_report_through_tier(requested_tier)
    )

    assert receipt["denominator_status"] == "COMPLETE"
    assert receipt["source_instance_count"] == expected_instance_count
    assert receipt["obligation_index"]["instance_count"] \
        == expected_instance_count
    assert [result["tier"] for result in receipt["tier_results"]] \
        == list(range(1, requested_tier + 1))
    assert [result["instance_count"] for result in receipt["tier_results"]] \
        == ([49] if requested_tier == 1 else [49, 75])
    _capacity_schema_validator().validate(receipt)


def test_complete_capacity_receipt_projects_large_pass_index_by_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _valid_report_through_tier(1)
    monkeypatch.setattr(
        package_polish, "MAX_INLINE_CAPACITY_INDEX_ENTRIES", 1,
    )

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "COMPLETE"
    assert receipt["obligation_index"]["schema_version"] == (
        "verifier-package-obligation-index-2"
    )
    reconstructed = package_polish._expand_capacity_obligation_index(
        receipt["obligation_index"]
    )
    assert reconstructed is not None
    assert len(reconstructed) == receipt["source_instance_count"]
    _capacity_schema_validator().validate(receipt)


@pytest.mark.parametrize("requested_tier", [1, 2])
@pytest.mark.parametrize(
    "mutation",
    [
        "missing_execution",
        "extra_execution",
        "missing_execution_seal",
        "stale_execution_seal",
        "misbound_evidence_digest",
        "missing_executed_prerequisite",
        "extra_prerequisite",
    ],
)
def test_complete_lower_tier_capacity_runtime_rejects_incoherent_native_prefix(
    requested_tier: int,
    mutation: str,
) -> None:
    report = _valid_report_through_tier(requested_tier)
    native = report["native_diagnostics"]
    execution = native["tier_execution"]
    prerequisites = native["prerequisites"]
    if mutation == "missing_execution":
        del execution[str(requested_tier)]
    elif mutation == "extra_execution":
        extra = requested_tier + 1
        execution[str(extra)] = deepcopy(
            _valid_tier_three_report()["native_diagnostics"]["tier_execution"]
            [str(extra)]
        )
    elif mutation == "missing_execution_seal":
        del execution[str(requested_tier)]["execution_record_digest"]
    elif mutation == "stale_execution_seal":
        execution[str(requested_tier)]["execution_record_digest"] = _digest("f")
    elif mutation == "misbound_evidence_digest":
        execution[str(requested_tier)]["evidence_digest"] = _digest("f")
        _reseal_execution(execution[str(requested_tier)])
    elif mutation == "missing_executed_prerequisite":
        del prerequisites[str(requested_tier)]
    else:
        extra = "2" if requested_tier == 1 else "extra"
        prerequisites[extra] = deepcopy(
            _valid_tier_three_report()["native_diagnostics"]["prerequisites"]
            ["2"]
        )

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "NOT_RETAINED"
    _capacity_schema_validator().validate(receipt)


@pytest.mark.parametrize("requested_tier", [1, 2])
@pytest.mark.parametrize(
    "mutation", ["missing_execution", "extra_execution", "unsealed_execution"],
)
def test_complete_lower_tier_capacity_schema_requires_exact_native_prefix(
    requested_tier: int,
    mutation: str,
) -> None:
    receipt = package_polish._capacity_receipt(
        _valid_report_through_tier(requested_tier)
    )
    assert receipt["denominator_status"] == "COMPLETE"
    execution = receipt["native_diagnostics"]["tier_execution"]
    if mutation == "missing_execution":
        del execution[str(requested_tier)]
    elif mutation == "extra_execution":
        extra = requested_tier + 1
        execution[str(extra)] = deepcopy(
            _valid_tier_three_report()["native_diagnostics"]["tier_execution"]
            [str(extra)]
        )
    else:
        del execution[str(requested_tier)]["execution_record_digest"]

    with pytest.raises(jsonschema.ValidationError):
        _capacity_schema_validator().validate(receipt)


@pytest.mark.parametrize("requested_tier", [1, 2])
def test_complete_lower_tier_capacity_retains_nonpass_and_not_run_tail(
    requested_tier: int,
) -> None:
    report = _valid_report_through_tier(requested_tier)
    native = report["native_diagnostics"]
    zero = native["prerequisites"]["0"]
    zero.update(
        status="FAIL",
        blockers=["SYNTHETIC_ADMISSION_FAILURE"],
        obligation_status_counts={"PASS": 8, "FAIL": 1, "UNKNOWN": 0},
    )
    zero["obligations"][0]["status"] = "FAIL"
    executed = native["tier_execution"]["0"]
    executed["status"] = "FAIL"
    _reseal_execution(executed)
    anchor = {
        "tier": 0,
        "tier_name": "ADMISSION",
        "required_status": "PASS",
        "observed_status": "FAIL",
        "report_digest": zero["report_digest"],
        "blockers": ["SYNTHETIC_ADMISSION_FAILURE"],
    }
    for depth in range(1, requested_tier + 1):
        record = native["tier_execution"][str(depth)]
        record.update(
            execution_status="NOT_RUN",
            status="UNKNOWN",
            evidence_digest=None,
            blocking_prerequisite=anchor,
        )
        _reseal_execution(record)
        del native["prerequisites"][str(depth)]
    native["status"] = "FAIL"

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "COMPLETE"
    assert receipt["native_diagnostics"]["status"] == "FAIL"
    assert all(
        receipt["native_diagnostics"]["tier_execution"][str(depth)][
            "execution_status"
        ] == "NOT_RUN"
        for depth in range(1, requested_tier + 1)
    )
    _capacity_schema_validator().validate(receipt)


@pytest.mark.parametrize("requested_tier", [1, 2])
def test_lower_tier_capacity_rejects_execution_after_native_nonpass(
    requested_tier: int,
) -> None:
    report = _valid_report_through_tier(requested_tier)
    native = report["native_diagnostics"]
    zero = native["prerequisites"]["0"]
    zero.update(
        status="FAIL",
        blockers=["SYNTHETIC_ADMISSION_FAILURE"],
        obligation_status_counts={"PASS": 8, "FAIL": 1, "UNKNOWN": 0},
    )
    zero["obligations"][0]["status"] = "FAIL"
    execution = native["tier_execution"]["0"]
    execution["status"] = "FAIL"
    _reseal_execution(execution)
    native["status"] = "FAIL"

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "NOT_RETAINED"


@pytest.mark.parametrize("requested_tier", [1, 2, 3])
def test_complete_capacity_schema_accepts_exact_selected_manifest(
    requested_tier: int,
) -> None:
    receipt = package_polish._capacity_receipt(
        _valid_report_through_tier(requested_tier)
    )
    assert receipt["denominator_status"] == "COMPLETE"
    assert receipt["manifest"] == {
        "path": "objects.vstd",
        "status": "SELECTED",
        "digest": _digest("1"),
    }
    _capacity_schema_validator().validate(receipt)


@pytest.mark.parametrize("requested_tier", [1, 2, 3])
def test_complete_capacity_runtime_accepts_exact_source_manifest(
    requested_tier: int,
) -> None:
    receipt = package_polish._capacity_receipt(
        _valid_report_through_tier(requested_tier)
    )

    assert receipt["denominator_status"] == "COMPLETE"


def test_complete_capacity_runtime_rejects_duplicate_installed_route_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catalog ambiguity cannot be hidden by the indexed lookup fast path."""

    report = _valid_tier_three_report()
    source_binding = _fixture_source_capacity_binding()
    catalog = manifest_gate.obligation_catalog()
    monkeypatch.setattr(
        package_polish,
        "_source_capacity_binding",
        lambda _source_root, _requested_tier: deepcopy(source_binding),
    )
    monkeypatch.setattr(
        manifest_gate,
        "obligation_catalog",
        lambda: catalog + [deepcopy(catalog[0])],
    )

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "NOT_RETAINED"
    _capacity_schema_validator().validate(receipt)


def test_source_selected_effective_roles_survive_projection_but_fabrication_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The source preflight, not the declared-kind spelling, owns selection.

    Ubiquitous OBJECT inheritance, a source-derived role, and an extensible
    declared kind whose internal NamespaceObject is OBJECT must all survive
    projection. A fabricated SIM row that the same source preflight did not
    select must remain fail-closed.
    """

    report = _valid_tier_three_report()
    actor = next(
        item for item in report["package_graph"]["objects"]
        if item["object_id"] == "capacity-actor-1"
    )
    extensible = next(
        item for item in report["package_graph"]["objects"]
        if item["object_id"] == "capacity-object-0"
    )
    catalog = manifest_gate.obligation_catalog()

    def append_kind_rows(
        target: dict[str, Any], kind: str, *, declared_kind: str,
        source_selected: bool = False,
    ) -> None:
        for route in catalog:
            if route["object_kind"] != kind or route["tier"] > 3:
                continue
            if not source_selected and not accepts_subject(route, kind):
                continue
            identity = {
                "object_id": target["object_id"],
                "object_digest": target["object_digest"],
                "coordinate": route["coordinate"],
                "tier": route["tier"],
                "proposition_digest": route["proposition_digest"],
            }
            report["obligation_instances"].append({
                **identity,
                "object_kind": kind,
                "declared_kind": declared_kind,
                "specializations": target["specializations"],
                "checking_mechanism": route["checking_mechanism"],
                "scope": route["scope"],
                "status": "UNKNOWN",
                "checker_status": "NOT_RUN",
                "instance_digest": binding.value_digest(identity),
                "blockers": ["PACKAGE_INSTANCE_EVIDENCE_MISSING"],
                "selected_package_check": None,
            })
        _recommit(report)

    # Ubiquitous base roles and source-derived necessary roles are additive to
    # the explicit ACTOR declaration without appearing as specializations.
    append_kind_rows(actor, "OBJECT", declared_kind="ACTOR")
    append_kind_rows(actor, "RECEIPT", declared_kind="ACTOR")

    # Extensible kinds are represented by the core NamespaceObject as OBJECT,
    # while the selected declaration and package rows retain the actual kind.
    for row in report["obligation_instances"]:
        if row["object_id"] == extensible["object_id"]:
            row["declared_kind"] = "SENSOR"
    append_kind_rows(
        extensible, "SENSOR", declared_kind="SENSOR", source_selected=True,
    )
    source_binding = _fixture_source_capacity_binding()
    source_binding["declaration_profiles"][extensible["object_id"]][
        "declared_kind"
    ] = "SENSOR"
    source_binding["selected_instance_index"] = _selected_instance_index(
        report["obligation_instances"]
    )
    monkeypatch.setattr(
        package_polish,
        "_source_capacity_binding",
        lambda _source_root, _requested_tier: deepcopy(source_binding),
    )

    inherited = package_polish._capacity_receipt(report)

    assert inherited["denominator_status"] == "COMPLETE"
    assert any(
        entry["object_id"] == actor["object_id"]
        and entry["object_kind"] == "OBJECT"
        for entry in inherited["obligation_index"]["entries"]
    )
    assert any(
        entry["object_id"] == actor["object_id"]
        and entry["object_kind"] == "RECEIPT"
        for entry in inherited["obligation_index"]["entries"]
    )
    assert any(
        entry["object_id"] == extensible["object_id"]
        and entry["object_kind"] == "SENSOR"
        for entry in inherited["obligation_index"]["entries"]
    )

    append_kind_rows(actor, "SIM", declared_kind="ACTOR")
    fabricated = package_polish._capacity_receipt(report)

    assert fabricated["denominator_status"] == "NOT_RETAINED"


@pytest.mark.parametrize("requested_tier", [1, 2, 3])
@pytest.mark.parametrize(
    "mutation",
    ["missing_path", "missing_validation", "wrong_path", "extra_field"],
)
def test_complete_capacity_runtime_rejects_malformed_source_manifest(
    requested_tier: int,
    mutation: str,
) -> None:
    report = _valid_report_through_tier(requested_tier)
    if mutation == "missing_path":
        del report["manifest"]["path"]
    elif mutation == "missing_validation":
        del report["manifest"]["validation"]
    elif mutation == "wrong_path":
        report["manifest"]["path"] = "nested/objects.vstd"
    else:
        report["manifest"]["unexpected"] = "not producer-owned"

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "NOT_RETAINED"
    _capacity_schema_validator().validate(receipt)


@pytest.mark.parametrize("requested_tier", [1, 2, 3])
def test_complete_capacity_runtime_accepts_producer_manifest_validation(
    requested_tier: int,
) -> None:
    repository = "https://example.invalid/verifier.git"
    revision = "a" * 40
    manifest = tier_zero_manifest.manifest_template(
        repository=repository,
        revision=revision,
    )
    validation = tier_zero_manifest.validate_manifest(
        manifest,
        expected_repository=repository,
        expected_revision=revision,
    )
    report = _valid_report_through_tier(requested_tier)
    report["manifest"]["validation"] = validation
    # Tier-0 validation covers its retained 26-object admission graph.  The
    # package collection is a separately scoped graph and must not be forced to
    # reuse that digest in order for the producer receipt to be accepted.
    assert report["package_graph"]["collection_digest"] \
        != validation["graph_digest"]

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "COMPLETE"
    assert receipt["manifest"] == {
        "path": "objects.vstd",
        "status": "SELECTED",
        "digest": _digest("1"),
    }
    _capacity_schema_validator().validate(receipt)


@pytest.mark.parametrize("requested_tier", [1, 2, 3])
def test_complete_capacity_runtime_rejects_collapsed_admission_and_package_graphs(
    requested_tier: int,
) -> None:
    report = _valid_report_through_tier(requested_tier)
    admission_graph_digest = report["manifest"]["validation"]["graph_digest"]
    # Mutate both package references coherently.  The receipt must reject the
    # scope collapse itself, not merely a broken execution-to-graph link.
    report["package_graph"]["collection_digest"] = admission_graph_digest
    report["verifier_execution"][
        "subject_collection_digest"
    ] = admission_graph_digest

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "NOT_RETAINED"
    _capacity_schema_validator().validate(receipt)


def _substitute_collection_digest(report: dict[str, Any]) -> None:
    replacement = _digest("e")
    report["package_graph"]["collection_digest"] = replacement
    report["verifier_execution"]["subject_collection_digest"] = replacement


def _substitute_object_rows_and_commitment(report: dict[str, Any]) -> None:
    selected = report["package_graph"]["objects"][1]
    replacement = _digest("e")
    selected["object_digest"] = replacement
    for row in report["obligation_instances"]:
        if row["object_id"] != selected["object_id"]:
            continue
        row["object_digest"] = replacement
        identity = {
            "object_id": row["object_id"],
            "object_digest": replacement,
            "coordinate": row["coordinate"],
            "tier": row["tier"],
            "proposition_digest": row["proposition_digest"],
        }
        row["instance_digest"] = binding.value_digest(identity)
    _recommit(report)


def _substitute_manifest_digest_references(report: dict[str, Any]) -> None:
    replacement = _digest("e")
    report["manifest"]["digest"] = replacement
    report["package_graph"]["manifest_digest"] = replacement
    report["verifier_execution"]["manifest_digest"] = replacement
    native = report.get("native_diagnostics")
    if type(native) is dict:
        zero = native.get("prerequisites", {}).get("0")
        if type(zero) is dict:
            zero["manifest_digest"] = replacement


@pytest.mark.parametrize("requested_tier", [1, 2, 3])
@pytest.mark.parametrize(
    "mutate",
    [
        _substitute_collection_digest,
        _substitute_object_rows_and_commitment,
        _substitute_manifest_digest_references,
    ],
    ids=[
        "collection-and-execution-digest",
        "graph-object-rows-and-commitment",
        "manifest-and-all-retained-references",
    ],
)
def test_capacity_complete_rejects_coordinated_source_substitution(
    requested_tier: int,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    report = _valid_report_through_tier(requested_tier)
    mutate(report)

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "NOT_RETAINED"
    _capacity_schema_validator().validate(receipt)


_VALIDATION_MUTATIONS = {
    "schema_version": "verifier-tier-zero-manifest-validation-forged",
    "status": "UNKNOWN",
    "profile_digest": _digest("f"),
    "object_count": len(tuple(tier_zero_manifest.ObjectKind)) + 1,
    "object_kind_digest": _digest("f"),
    "graph_digest": _digest("f"),
    "semantic_version": "forged-semantic-version",
    "slot_count": -1,
    "route_count": -1,
    "slot_digest": _digest("f"),
    "route_identity_digest": _digest("f"),
    "surface_rule_count": -1,
    "surface_rule_digest": _digest("f"),
    "reason_provider_selection_status": "NOT_SELECTED",
    "node_reconciler_selection_status": "NOT_SELECTED",
    "attachment_selection_digest": _digest("f"),
    "adversarial_corpus_status": "FAIL",
    "adversarial_corpus_digest": _digest("f"),
    "claim_boundary": "Forged nonempty claim boundary.",
}


@pytest.mark.parametrize("field", sorted(_VALIDATION_MUTATIONS))
def test_complete_capacity_runtime_rejects_every_forged_validation_field(
    field: str,
) -> None:
    repository = "https://example.invalid/verifier.git"
    revision = "a" * 40
    manifest = tier_zero_manifest.manifest_template(
        repository=repository,
        revision=revision,
    )
    validation = tier_zero_manifest.validate_manifest(
        manifest,
        expected_repository=repository,
        expected_revision=revision,
    )
    report = _valid_tier_three_report()
    report["manifest"]["validation"] = validation
    replacement = _VALIDATION_MUTATIONS[field]
    if field in {"slot_count", "route_count", "surface_rule_count"}:
        replacement = validation[field] + 1
    validation[field] = replacement

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "NOT_RETAINED"
    _capacity_schema_validator().validate(receipt)


def test_complete_capacity_runtime_fails_closed_when_canonical_validation_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _valid_tier_three_report()

    def unavailable(
        _source_root: str | Path | None,
        _requested_tier: int,
    ) -> dict[str, Any]:
        raise OSError("synthetic source replay failure")

    monkeypatch.setattr(
        package_polish,
        "_source_capacity_binding",
        unavailable,
    )

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "NOT_RETAINED"
    _capacity_schema_validator().validate(receipt)


def test_complete_capacity_runtime_fails_closed_when_source_replay_exhausts_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second capacity exception must not escape the compact receipt path."""

    def exhausted(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise package_polish.PackagePolishCapacity

    monkeypatch.setattr(
        package_polish,
        "_source_capacity_binding",
        exhausted,
    )

    receipt = package_polish._capacity_receipt(_valid_tier_three_report())

    assert receipt["denominator_status"] == "NOT_RETAINED"
    _capacity_schema_validator().validate(receipt)


@pytest.mark.parametrize("requested_tier", [1, 2, 3])
def test_capacity_replay_receives_only_the_exact_requested_tier(
    monkeypatch: pytest.MonkeyPatch,
    requested_tier: int,
) -> None:
    """Lower-tier receipts must not depend on the Tier-3 denominator."""

    selected = _fixture_source_capacity_binding()
    observed_tiers: list[int] = []

    def replay(
        _source_root: str | Path | None,
        replay_tier: int,
    ) -> dict[str, Any]:
        observed_tiers.append(replay_tier)
        source_binding = deepcopy(selected)
        source_binding["selected_instance_index"] = [
            row for row in source_binding["selected_instance_index"]
            if row["tier"] <= replay_tier
        ]
        return source_binding

    monkeypatch.setattr(package_polish, "_source_capacity_binding", replay)

    receipt = package_polish._capacity_receipt(
        _valid_report_through_tier(requested_tier)
    )

    assert observed_tiers == [requested_tier]
    assert receipt["denominator_status"] == "COMPLETE"


def test_source_capacity_replay_rejects_nonmanifest_source_change(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    _authoritative_source_capacity_replay: Callable[..., dict[str, Any]],
) -> None:
    """Recapture the whole source after replay, not just objects.vstd."""

    raw = b"{}"
    graph_object = SimpleNamespace(
        object_id="capacity-package-graph",
        kind=SimpleNamespace(value="GRAPH"),
        digest=_digest("1"),
    )
    document = {
        "namespace": {
            "objects": [{
                "object_id": graph_object.object_id,
                "kind": "GRAPH",
                "specializations": [],
            }],
        },
    }
    manifest = {
        "objects": [{
            "object_id": graph_object.object_id,
            "object_kind": "GRAPH",
        }],
    }
    selected_coordinate = {
        "source_head": "1" * 40,
        "source_tree": "2" * 40,
        "source_worktree_status_digest": _digest("3"),
        "source_manifest_digest": _digest("4"),
    }
    changed_coordinate = {
        **selected_coordinate,
        "source_worktree_status_digest": _digest("5"),
    }
    captures = iter((selected_coordinate, changed_coordinate))
    observed_preflight_tiers: list[int] = []

    class Requirements:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def recapture(self) -> None:
            pass

    monkeypatch.setattr(package_polish, "_read_manifest", lambda _root: raw)
    monkeypatch.setattr(
        package_polish.tier_zero_manifest,
        "_strict_json_document",
        lambda _raw: document,
    )
    monkeypatch.setattr(
        package_polish.self_polish_estate,
        "_git_coordinate",
        lambda _root: {"repository": "example", "revision": "a" * 40},
    )
    monkeypatch.setattr(
        package_polish.package_manifest,
        "select",
        lambda *_args, **_kwargs: (manifest, {}, [graph_object]),
    )
    monkeypatch.setattr(
        package_polish.namespace,
        "composition_digest",
        lambda _objects: _digest("6"),
    )
    monkeypatch.setattr(
        package_polish.namespace,
        "assess_composition",
        # A PASS must bind the selected collection digest and object count.
        lambda *_args, **_kwargs: package_polish.namespace.CompositionAssessment(
            package_polish.namespace.Verdict.PASS, _digest("6"),
            "synthetic composition binds the one selected graph object", 1,
        ),
    )
    monkeypatch.setattr(package_polish, "KindRequirements", Requirements)
    monkeypatch.setattr(
        package_polish,
        "_obligation_selection_preflight",
        lambda replay_tier, *_args, **_kwargs: (
            observed_preflight_tiers.append(replay_tier),
            [],
        ),
    )
    monkeypatch.setattr(
        package_polish,
        "_graph_declaration_profile",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        package_polish.self_polish_statics,
        "_capture_coordinate",
        lambda _root: next(captures),
    )

    with pytest.raises(
        ValueError,
        match="PACKAGE_CAPACITY_SOURCE_CHANGED_DURING_REPLAY",
    ):
        _authoritative_source_capacity_replay(tmp_path, 1)
    assert observed_preflight_tiers == [1]


def test_source_capacity_replay_evaluates_only_refutable_routes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    _authoritative_source_capacity_replay: Callable[..., dict[str, Any]],
) -> None:
    """Keep every selected row while replaying only possible refutations."""

    def route(coordinate: str, mode: str, scope: str) -> dict[str, Any]:
        applicability = {
            "mode": mode,
            "condition": coordinate + " condition",
            "when_condition_met": "NECESSARY",
            "unknown_condition": "NOT_EXEMPT",
            "reason": coordinate + " reason",
        }
        return {
            "object_kind": "OBJECT",
            "tier": 1,
            "coordinate": coordinate,
            "scope": scope,
            "applicability": applicability,
            "applicability_digest": binding.value_digest(applicability),
        }

    source = route("OBJECT-1.91", "CONDITIONAL", "source-specific")
    generic = route(
        "OBJECT-1.1",
        "CONDITIONAL",
        "generic_canonical_representation_and_address",
    )
    necessary = route("OBJECT-1.92", "NECESSARY", "necessary-specific")
    conditional = route("OBJECT-1.2", "CONDITIONAL", "conditional-specific")
    routes = [source, generic, necessary, conditional]
    raw = b"{}"
    graph_object = SimpleNamespace(
        object_id="capacity-package-graph",
        kind=SimpleNamespace(value="GRAPH"),
        digest=_digest("1"),
    )
    document = {
        "namespace": {
            "objects": [{
                "object_id": graph_object.object_id,
                "kind": "GRAPH",
                "specializations": [],
            }],
        },
    }
    manifest = {
        "objects": [{
            "object_id": graph_object.object_id,
            "object_kind": "GRAPH",
        }],
    }
    selected = [{
        "object_id": graph_object.object_id,
        "object_kind": item["object_kind"],
        "tier": item["tier"],
        "coordinate": item["coordinate"],
        "instance_digest": _digest(str(index + 1)),
    } for index, item in enumerate(routes)]
    source_coordinate = {
        "source_head": "1" * 40,
        "source_tree": "2" * 40,
        "source_worktree_status_digest": _digest("3"),
        "source_manifest_digest": _digest("4"),
    }

    class Requirements:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def recapture(self) -> None:
            pass

    monkeypatch.setattr(package_polish, "_read_manifest", lambda _root: raw)
    monkeypatch.setattr(
        package_polish.tier_zero_manifest,
        "_strict_json_document",
        lambda _raw: document,
    )
    monkeypatch.setattr(
        package_polish.self_polish_estate,
        "_git_coordinate",
        lambda _root: {"repository": "example", "revision": "a" * 40},
    )
    monkeypatch.setattr(
        package_polish.package_manifest,
        "select",
        lambda *_args, **_kwargs: (manifest, {}, [graph_object]),
    )
    monkeypatch.setattr(
        package_polish.namespace,
        "composition_digest",
        lambda _objects: _digest("6"),
    )
    monkeypatch.setattr(
        package_polish.namespace,
        "assess_composition",
        # A PASS must bind the selected collection digest and object count.
        lambda *_args, **_kwargs: package_polish.namespace.CompositionAssessment(
            package_polish.namespace.Verdict.PASS, _digest("6"),
            "synthetic composition binds the one selected graph object", 1,
        ),
    )
    monkeypatch.setattr(package_polish, "KindRequirements", Requirements)
    monkeypatch.setattr(
        package_polish,
        "_obligation_selection_preflight",
        lambda *_args, **_kwargs: ([], selected),
    )
    monkeypatch.setattr(
        package_polish,
        "_graph_declaration_profile",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        package_polish.self_polish_statics,
        "_capture_coordinate",
        lambda _root: deepcopy(source_coordinate),
    )
    monkeypatch.setattr(
        package_polish.package_source_contracts,
        "is_route",
        lambda selected_route: selected_route is source,
    )
    monkeypatch.setattr(
        package_polish.package_source_contracts,
        "SourceContractAssessment",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        package_polish,
        "InstanceEvidence",
        lambda *_args, **_kwargs: object(),
    )
    calls: list[tuple[str, str, int]] = []
    refutation = {"status": "PASS", "reason": "Exact conditional non-trigger."}

    def evaluate(
        _source_assessment: Any,
        _instance_evidence: Any,
        _item: Any,
        selected_route: dict[str, Any],
        *,
        object_kind: str,
        tier: int,
    ) -> tuple[None, dict[str, str]]:
        assert selected_route is conditional
        calls.append((selected_route["coordinate"], object_kind, tier))
        return None, refutation

    monkeypatch.setattr(package_polish, "_capacity_source_route_outcome", evaluate)

    duplicate_catalog = routes + [deepcopy(source)]
    monkeypatch.setattr(
        manifest_gate, "obligation_catalog", lambda: duplicate_catalog,
    )
    with pytest.raises(
        ValueError,
        match="PACKAGE_CAPACITY_SOURCE_ROUTE_CATALOG_AMBIGUOUS",
    ):
        _authoritative_source_capacity_replay(tmp_path, 1)

    monkeypatch.setattr(manifest_gate, "obligation_catalog", lambda: routes)
    result = _authoritative_source_capacity_replay(tmp_path, 1)

    assert calls == [("OBJECT-1.2", "OBJECT", 1)]
    assert result["selected_instance_index"] == selected
    assert result["conditional_source_authority"] == {
        (graph_object.object_id, "OBJECT-1.2"): refutation,
    }


def test_complete_capacity_runtime_requires_caller_selected_source_root(
    monkeypatch: pytest.MonkeyPatch,
    _authoritative_source_capacity_replay:
        Callable[[str | Path | None, int], dict[str, Any]],
) -> None:
    monkeypatch.setattr(
        package_polish,
        "_source_capacity_binding",
        _authoritative_source_capacity_replay,
    )

    receipt = package_polish._capacity_receipt(_valid_tier_three_report())

    assert receipt["denominator_status"] == "NOT_RETAINED"
    _capacity_schema_validator().validate(receipt)


@pytest.mark.parametrize("requested_tier", [1, 2, 3])
def test_source_manifest_contract_accepts_actual_assessor_shape(
    monkeypatch: pytest.MonkeyPatch,
    requested_tier: int,
    _authoritative_source_capacity_replay:
        Callable[[str | Path | None, int], dict[str, Any]],
) -> None:
    root = Path(__file__).resolve().parents[1]

    def stop_after_graph_representation(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise package_polish.PackagePolishCapacity

    # Stop only after the assessor has selected the manifest, retained its real
    # Tier-0 validation receipt, and built the full package GRAPH.  Returning
    # the unsealed report compares the contract against the actual producer
    # rather than a hand-maintained fixture approximation.
    monkeypatch.setattr(
        package_polish,
        "_verifier_selection",
        stop_after_graph_representation,
    )
    monkeypatch.setattr(
        package_polish,
        "_seal",
        lambda report, **_kwargs: report,
    )

    report = package_polish.assess_package_polish(requested_tier, root)
    source_binding = _authoritative_source_capacity_replay(
        root, requested_tier
    )

    selected_instance_count = len(source_binding["selected_instance_index"])
    assert 0 < selected_instance_count <= package_polish.MAX_OBLIGATION_INSTANCES
    assert package_polish._selected_source_manifest_complete(
        report["manifest"], report["package_graph"], source_binding
    )
    assert source_binding["source_coordinate"] == report["source_coordinate"]
    for field in (
        "status", "root_id", "root_kind", "manifest_digest",
        "collection_digest", "object_count", "declaration_count",
        "declaration_digest", "object_payloads_transport",
    ):
        assert source_binding["package_graph"].get(field) \
            == report["package_graph"].get(field)


@pytest.mark.parametrize(
    "mutation",
    [
        "extra_validation_field",
        "wrong_validation_status",
        "invalid_graph_digest",
        "wrong_object_count",
    ],
)
def test_complete_capacity_runtime_rejects_malformed_manifest_validation(
    mutation: str,
) -> None:
    repository = "https://example.invalid/verifier.git"
    revision = "a" * 40
    manifest = tier_zero_manifest.manifest_template(
        repository=repository,
        revision=revision,
    )
    validation = tier_zero_manifest.validate_manifest(
        manifest,
        expected_repository=repository,
        expected_revision=revision,
    )
    report = _valid_tier_three_report()
    report["manifest"]["validation"] = validation
    if mutation == "extra_validation_field":
        validation["unexpected"] = "not producer-owned"
    elif mutation == "wrong_validation_status":
        validation["status"] = "UNKNOWN"
    elif mutation == "invalid_graph_digest":
        validation["graph_digest"] = "not-a-digest"
    else:
        validation["object_count"] += 1

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "NOT_RETAINED"
    _capacity_schema_validator().validate(receipt)


@pytest.mark.parametrize("requested_tier", [1, 2, 3])
@pytest.mark.parametrize(
    "mutation",
    [
        "null",
        "missing_path",
        "missing_status",
        "missing_digest",
        "wrong_path",
        "wrong_status",
        "null_digest",
        "invalid_digest",
        "extra_field",
    ],
)
def test_complete_capacity_schema_rejects_malformed_selected_manifest(
    requested_tier: int,
    mutation: str,
) -> None:
    receipt = package_polish._capacity_receipt(
        _valid_report_through_tier(requested_tier)
    )
    assert receipt["denominator_status"] == "COMPLETE"
    manifest = receipt["manifest"]
    if mutation == "null":
        receipt["manifest"] = None
    elif mutation.startswith("missing_"):
        del manifest[mutation.removeprefix("missing_")]
    elif mutation == "wrong_path":
        manifest["path"] = "nested/objects.vstd"
    elif mutation == "wrong_status":
        manifest["status"] = "NOT_SELECTED"
    elif mutation == "null_digest":
        manifest["digest"] = None
    elif mutation == "invalid_digest":
        manifest["digest"] = "sha256:not-a-digest"
    else:
        manifest["validation"] = {"status": "PASS"}

    with pytest.raises(jsonschema.ValidationError):
        _capacity_schema_validator().validate(receipt)


@pytest.mark.parametrize("requested_tier", [1, 2])
def test_complete_lower_tier_capacity_schema_rejects_fabricated_empty_report(
    requested_tier: int,
) -> None:
    receipt = package_polish._capacity_receipt(
        _valid_report_through_tier(requested_tier)
    )
    assert receipt["denominator_status"] == "COMPLETE"
    receipt["source_instance_count"] = 0
    receipt["obligation_index"].update(
        instance_count=0,
        status_counts={},
        entries=[],
    )
    receipt["tier_results"] = []

    with pytest.raises(jsonschema.ValidationError):
        _capacity_schema_validator().validate(receipt)


@pytest.mark.parametrize("requested_tier", [1, 2])
@pytest.mark.parametrize(
    "field",
    [
        "source_report_schema",
        "source_report_encoding_status",
        "source_coordinate_digest",
        "mechanism_digest",
        "package_graph_reference",
        "source_instance_count",
        "obligation_index",
        "tier_results",
    ],
)
def test_complete_lower_tier_capacity_schema_rejects_missing_common_field(
    requested_tier: int,
    field: str,
) -> None:
    receipt = package_polish._capacity_receipt(
        _valid_report_through_tier(requested_tier)
    )
    assert receipt["denominator_status"] == "COMPLETE"
    del receipt[field]

    with pytest.raises(jsonschema.ValidationError):
        _capacity_schema_validator().validate(receipt)


@pytest.mark.parametrize("requested_tier", [1, 2])
@pytest.mark.parametrize(
    "mutation",
    [
        "unsupported_source_schema",
        "unavailable_source_encoding",
        "null_source_coordinate_digest",
        "null_mechanism_digest",
        "null_graph_reference",
        "zero_source_instance_count",
        "zero_index_instance_count",
        "empty_index_status_counts",
        "empty_index_entries",
        "empty_tier_results",
        "extra_tier_result",
    ],
)
def test_complete_lower_tier_capacity_schema_rejects_invalid_common_evidence(
    requested_tier: int,
    mutation: str,
) -> None:
    receipt = package_polish._capacity_receipt(
        _valid_report_through_tier(requested_tier)
    )
    assert receipt["denominator_status"] == "COMPLETE"
    if mutation == "unsupported_source_schema":
        receipt["source_report_schema"] = "verifier-manifest-package-polish-99"
    elif mutation == "unavailable_source_encoding":
        receipt.update(
            source_report_encoding_status="UNAVAILABLE",
            source_report_digest=None,
            source_report_bytes=None,
        )
    elif mutation == "null_source_coordinate_digest":
        receipt["source_coordinate_digest"] = None
    elif mutation == "null_mechanism_digest":
        receipt["mechanism_digest"] = None
    elif mutation == "null_graph_reference":
        receipt["package_graph_reference"] = None
    elif mutation == "zero_source_instance_count":
        receipt["source_instance_count"] = 0
    elif mutation == "zero_index_instance_count":
        receipt["obligation_index"]["instance_count"] = 0
    elif mutation == "empty_index_status_counts":
        receipt["obligation_index"]["status_counts"] = {}
    elif mutation == "empty_index_entries":
        receipt["obligation_index"]["entries"] = []
    elif mutation == "empty_tier_results":
        receipt["tier_results"] = []
    else:
        tier_three_receipt = package_polish._capacity_receipt(
            _valid_tier_three_report()
        )
        receipt["tier_results"].append(
            deepcopy(tier_three_receipt["tier_results"][requested_tier])
        )

    with pytest.raises(jsonschema.ValidationError):
        _capacity_schema_validator().validate(receipt)


def test_complete_tier_three_capacity_receipt_retains_actionable_denominator() -> None:
    report = _valid_tier_three_report()

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "COMPLETE"
    assert receipt["source_instance_count"] == 101
    assert receipt["obligation_index"]["instance_count"] == 101
    assert set(receipt["native_diagnostics"]["tier_execution"]) == {
        "0", "1", "2", "3",
    }
    assert [result["tier"] for result in receipt["tier_results"]] == [1, 2, 3]
    entries = receipt["obligation_index"]["entries"]
    assert {entry["tier"] for entry in entries} == {1, 2, 3}
    for entry in entries:
        route = next(
            candidate for candidate in manifest_gate.obligation_catalog()
            if candidate["coordinate"] == entry["coordinate"]
        )
        assert entry["actions"]
        assert entry["actions"][0]["gate_id"] == "instance-evidence"
        assert entry["rerun_argv"] == [
            "vstd",
            "gate",
            "--object",
            entry["object_id"],
            "--obligation",
            route["obligation_id"],
        ]
    assert all(
        finding["rerun_argv"]
        for finding in receipt["findings"]
    )


def test_minimal_capacity_receipt_retains_actionable_diagnostic_and_omission_count() -> None:
    report = {
        "schema_version": package_polish.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": (
            package_polish.namespace_contracts.kind_denominators()
        ),
        "requested_tier": 3,
        "status": "UNKNOWN",
        "blockers": ["PACKAGE_REPORT_CAPACITY_EXHAUSTED"],
        "obligation_instances": [],
        "findings": [
            {"code": "FIRST_OMITTED"},
            {"code": "SECOND_OMITTED"},
        ],
    }

    receipt = package_polish._minimal_capacity_receipt(report)

    assert receipt["finding_count"] == len(receipt["findings"]) == 1
    assert receipt["omitted_finding_count"] == 2
    finding = receipt["findings"][0]
    assert finding["code"] == "PACKAGE_REPORT_CAPACITY_EXHAUSTED"
    assert finding["scope"] == "repository"
    assert finding["obligation_id"] == (
        "PACKAGE-PREREQUISITE-package-report-capacity-exhausted"
    )
    assert finding["gate_id"].strip()
    assert finding["reason"] == finding["explanation"]
    assert finding["next_action"].strip()
    assert finding["rerun_argv"] == ["vstd", "polish", "3", "--json"]


def test_package_live_source_drift_finding_has_canonical_obligation_and_rerun() -> None:
    finding = package_polish._live_source_drift_finding(
        "CANDIDATE_SOURCE_MUTATED", 3,
    )

    assert finding["status"] == "UNKNOWN"
    assert finding["gate_id"] == "source-freshness"
    assert finding["obligation_id"] == (
        "VSTD-T0.7-source-and-mechanism-freshness"
    )
    assert finding["reason"] == finding["explanation"]
    assert finding["next_action"].strip()
    assert finding["rerun_argv"] == ["vstd", "polish", "3", "--json"]


def test_capacity_receipt_rejects_cross_coordinate_source_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A coherent old report cannot borrow a newer source replay."""

    report = _valid_tier_three_report()
    source_binding = _fixture_source_capacity_binding(report["requested_tier"])
    source_binding["source_coordinate"]["source_manifest_digest"] = _digest("f")
    monkeypatch.setattr(
        package_polish,
        "_source_capacity_binding",
        lambda _source_root, _requested_tier: deepcopy(source_binding),
    )

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "NOT_RETAINED"
    assert "cumulative_tier_evidence_unavailable" in receipt["omitted_sections"]
    _capacity_schema_validator().validate(receipt)


def test_complete_receipt_accepts_matching_executed_failure_anchor() -> None:
    report = _valid_tier_three_report()
    _executed_failure_tail(report, anchor_blockers=["ACTUAL_CAUSE"])

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "COMPLETE"
    assert receipt["native_diagnostics"]["status"] == "FAIL"


def test_complete_receipt_accepts_exact_conditional_refutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _valid_tier_three_report()
    row = report["obligation_instances"][0]
    _make_row_conditionally_not_required(row)
    _recommit(report)
    _install_conditional_source_authority(monkeypatch, report)

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "COMPLETE"
    commitment = receipt["package_graph_reference"][
        "obligation_denominator_commitment"
    ]
    assert commitment["conditional_refutation_count"] == 1
    assert commitment["conditional_refutations"][0]["instance_digest"] \
        == row["instance_digest"]


def test_every_emitted_not_required_row_binds_installed_conditional_route(
) -> None:
    report = _valid_tier_three_report()
    routes = {
        (route["object_kind"], route["tier"], route["coordinate"]): route
        for route in manifest_gate.obligation_catalog()
    }
    expected = 0
    for row in report["obligation_instances"]:
        route = routes[(row["object_kind"], row["tier"], row["coordinate"])]
        if route["applicability"]["mode"] != "CONDITIONAL":
            continue
        _make_row_conditionally_not_required(row, route)
        expected += 1

    retained = package_polish._conditional_refutation_index(
        report["obligation_instances"]
    )

    assert len(retained) == expected > 0
    for row in report["obligation_instances"]:
        if row.get("checker_status") != "NOT_REQUIRED":
            continue
        route = routes[(row["object_kind"], row["tier"], row["coordinate"])]
        check = row["selected_package_check"]
        assert route["applicability"]["mode"] == "CONDITIONAL"
        assert check["condition"] == route["applicability"]["condition"]
        assert check["applicability_digest"] == route["applicability_digest"]


def test_capacity_rejects_forged_conditional_applicability_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even matching mocked source authority cannot invent route applicability."""

    report = _valid_tier_three_report()
    row = report["obligation_instances"][0]
    _make_row_conditionally_not_required(row)
    check = row["selected_package_check"]
    check["applicability_digest"] = _digest("f")
    check["result_digest"] = binding.value_digest({
        key: value for key, value in check.items()
        if key != "result_digest"
    })
    _recommit(report)
    # Deliberately make the synthetic source replay repeat the same forgery.
    # The capacity validator must still compare it with the installed route.
    _install_conditional_source_authority(monkeypatch, report)

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "NOT_RETAINED"
    assert "cumulative_tier_evidence_unavailable" in receipt["omitted_sections"]


def test_complete_receipt_rejects_recommitted_not_required_to_pass_forgery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _valid_tier_three_report()
    row = report["obligation_instances"][0]
    _make_row_conditionally_not_required(row)
    _recommit(report)
    _install_conditional_source_authority(monkeypatch, report)

    row.update(
        checker_status="PASS",
        package_graph_replay_is_instance_evidence=True,
        applicability={
            "status": "PASS",
            "classification": "NECESSARY",
            "assessment_required": True,
            "reason": "A forged report-local PASS replaced the source non-trigger.",
        },
    )
    _recommit(report)

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "NOT_RETAINED"


def test_projected_report_derives_exact_conditional_ledger_and_capacity_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, conditional_ledger = _projected_conditional_report()
    _install_conditional_source_authority(monkeypatch, report)
    source_commitment = report["verifier_execution"][
        "obligation_denominator_commitment"
    ]

    assert source_commitment["schema_version"] == _DERIVED_COMMITMENT_SCHEMA
    assert source_commitment["conditional_refutations_transport"] == (
        _DERIVED_CONDITIONAL_TRANSPORT
    )
    assert "conditional_refutations" not in source_commitment
    assert source_commitment["conditional_refutation_count"] == len(
        conditional_ledger
    ) == 1
    assert source_commitment["conditional_refutations_digest"] == (
        binding.value_digest(conditional_ledger)
    )
    source_digest = binding.bytes_digest(binding.canonical_bytes(report))

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "COMPLETE"
    receipt_commitment = receipt["package_graph_reference"][
        "obligation_denominator_commitment"
    ]
    assert receipt_commitment["schema_version"] == (
        "verifier-package-obligation-denominator-commitment-3"
    )
    assert "conditional_refutations" not in receipt_commitment
    assert receipt_commitment["conditional_refutations_transport"] == (
        "REPLAY_FROM_DIGEST_BOUND_SOURCE_REPORT"
    )
    assert receipt_commitment["source_report_digest"] == source_digest
    assert receipt_commitment["conditional_refutations_digest"] == (
        binding.value_digest(conditional_ledger)
    )
    # Receipt construction must not mutate the normal report's transport.
    assert source_commitment["schema_version"] == _DERIVED_COMMITMENT_SCHEMA
    assert "conditional_refutations" not in source_commitment
    _capacity_schema_validator().validate(receipt)


def test_v3_capacity_receipt_reconstructs_projected_pass_denominator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Capacity fallback consumes all semantic rows behind the v3 transport."""

    report, conditional_ledger = _projected_conditional_report()
    _install_conditional_source_authority(monkeypatch, report)
    assert package_polish._attach_successful_instance_projection(
        report, force=True,
    )
    projection = report["obligation_instance_projection"]
    assert projection["schema_version"] == "verifier-pass-instance-projection-3"
    assert len(report["obligation_instances"]) == projection[
        "expanded_nonpass_count"
    ] == 100
    assert projection["pass_reference_count"] == 1
    source_body = {
        key: value for key, value in report.items() if key != "report_digest"
    }
    source_encoded = binding.canonical_bytes(source_body)

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "COMPLETE"
    assert receipt["source_instance_count"] == projection["source_instance_count"]
    assert receipt["obligation_index"]["instance_count"] == projection[
        "source_instance_count"
    ]
    receipt_commitment = receipt["package_graph_reference"][
        "obligation_denominator_commitment"
    ]
    assert receipt_commitment["conditional_refutation_count"] == len(
        conditional_ledger
    )
    assert receipt_commitment["conditional_refutations_digest"] == (
        binding.value_digest(conditional_ledger)
    )
    assert receipt_commitment["conditional_refutations_transport"] == (
        "REPLAY_FROM_DIGEST_BOUND_SOURCE_REPORT"
    )
    assert receipt_commitment["source_report_digest"] == binding.bytes_digest(
        source_encoded
    )
    assert receipt["source_report_digest"] == binding.bytes_digest(source_encoded)
    assert receipt["source_report_bytes"] == len(source_encoded)
    _capacity_schema_validator().validate(receipt)

    tampered = deepcopy(report)
    tampered["obligation_instance_projection"]["pass_entries"][0][3] = _digest(
        "f"
    )
    rejected = package_polish._capacity_receipt(tampered)
    assert rejected["denominator_status"] == "NOT_RETAINED"


def test_seal_upgrades_existing_v2_before_preencoding_capacity_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retainable v3 table must be tried before refusing its bulky v2 source."""

    report, _ = _projected_conditional_report()
    assert report["obligation_instance_projection"]["schema_version"] == (
        "verifier-pass-instance-projection-2"
    )
    original_refusal = package_polish._preencoding_refusal

    def refuse_only_v2_source(
        value: Any, *, byte_limit: int | None = None,
    ) -> str | None:
        projection = value.get("obligation_instance_projection") \
            if type(value) is dict else None
        if (
            value is report
            and byte_limit is None
            and type(projection) is dict
            and projection.get("schema_version")
            == "verifier-pass-instance-projection-2"
        ):
            return "PACKAGE_REPORT_PREENCODING_BYTES_EXCEEDED"
        return original_refusal(value, byte_limit=byte_limit)

    monkeypatch.setattr(
        package_polish, "_preencoding_refusal", refuse_only_v2_source,
    )

    sealed = package_polish._seal(report)

    assert sealed["schema_version"] == package_polish.EXTENSIBLE_REPORT_SCHEMA
    assert sealed["obligation_instance_projection"]["schema_version"] == (
        "verifier-pass-instance-projection-3"
    )
    assert "PACKAGE_REPORT_CAPACITY_EXHAUSTED" not in sealed.get("blockers", [])


@pytest.mark.parametrize(
    "shape",
    ["marker_without_projection", "both", "neither"],
)
def test_capacity_completeness_refuses_invalid_conditional_transport_shape(
    shape: str,
) -> None:
    if shape == "marker_without_projection":
        report = _valid_tier_three_report()
        _make_row_conditionally_not_required(report["obligation_instances"][0])
        _recommit(report)
        commitment = report["verifier_execution"][
            "obligation_denominator_commitment"
        ]
        commitment["schema_version"] = _DERIVED_COMMITMENT_SCHEMA
        commitment.pop("conditional_refutations")
        commitment["conditional_refutations_transport"] = (
            _DERIVED_CONDITIONAL_TRANSPORT
        )
    else:
        report, conditional_ledger = _projected_conditional_report()
        commitment = report["verifier_execution"][
            "obligation_denominator_commitment"
        ]
        if shape == "both":
            commitment["conditional_refutations"] = conditional_ledger
        else:
            commitment.pop("conditional_refutations_transport")
    _reseal_commitment(commitment)

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "NOT_RETAINED"
    assert "cumulative_tier_evidence_unavailable" in receipt["omitted_sections"]


@pytest.mark.parametrize(
    "shape",
    ["missing_source_digest", "wrong_transport", "wrong_schema"],
)
def test_capacity_schema_rejects_unbound_source_replay_transport(
    shape: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, _ = _projected_conditional_report()
    _install_conditional_source_authority(monkeypatch, report)
    receipt = package_polish._capacity_receipt(report)
    assert receipt["denominator_status"] == "COMPLETE"
    commitment = receipt["package_graph_reference"][
        "obligation_denominator_commitment"
    ]
    if shape == "missing_source_digest":
        commitment.pop("source_report_digest")
    elif shape == "wrong_transport":
        commitment["conditional_refutations_transport"] = (
            _DERIVED_CONDITIONAL_TRANSPORT
        )
    else:
        commitment["schema_version"] = _DERIVED_COMMITMENT_SCHEMA
    _reseal_commitment(commitment)

    with pytest.raises(jsonschema.ValidationError):
        _capacity_schema_validator().validate(receipt)


def test_captured_tier_two_derived_ledger_saves_deficit_plus_one_mib_margin(
) -> None:
    rows = _captured_tier_two_rows()
    report = {
        "schema_version": package_polish.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": (
            package_polish.namespace_contracts.kind_denominators()
        ),
        "obligation_instances": rows,
        "verifier_execution": {
            "obligation_denominator_commitment": _commitment(rows),
        },
    }
    nonpass_before = deepcopy(rows[-1])
    conditional_ledger = package_polish._conditional_refutation_index(rows)

    assert len(rows) == _CAPTURED_TIER_TWO_INSTANCE_COUNT
    assert len(conditional_ledger) == _CAPTURED_TIER_TWO_CONDITIONAL_COUNT
    assert package_polish._attach_successful_instance_projection(
        report, force=True,
    )
    derived_commitment = report["verifier_execution"][
        "obligation_denominator_commitment"
    ]
    assert derived_commitment["schema_version"] == _DERIVED_COMMITMENT_SCHEMA
    assert derived_commitment["conditional_refutations_transport"] == (
        _DERIVED_CONDITIONAL_TRANSPORT
    )
    assert "conditional_refutations" not in derived_commitment
    capacity_commitment = package_polish._capacity_denominator_commitment(
        report, rows, source_report_digest=_DIGEST,
    )
    assert capacity_commitment is not None
    assert capacity_commitment["schema_version"] == (
        "verifier-package-obligation-denominator-commitment-3"
    )
    assert capacity_commitment["conditional_refutation_count"] == len(
        conditional_ledger
    )
    assert capacity_commitment["conditional_refutations_digest"] == (
        binding.value_digest(conditional_ledger)
    )
    assert capacity_commitment["conditional_refutations_transport"] == (
        "REPLAY_FROM_DIGEST_BOUND_SOURCE_REPORT"
    )
    assert capacity_commitment["source_report_digest"] == _DIGEST
    assert "conditional_refutations" not in capacity_commitment
    assert len(binding.canonical_bytes(capacity_commitment)) < 2_048

    inline_report = deepcopy(report)
    inline_commitment = inline_report["verifier_execution"][
        "obligation_denominator_commitment"
    ]
    inline_commitment["schema_version"] = (
        "verifier-package-obligation-denominator-commitment-1"
    )
    inline_commitment.pop("conditional_refutations_transport")
    inline_commitment["conditional_refutations"] = conditional_ledger
    _reseal_commitment(inline_commitment)
    saved_bytes = (
        len(binding.canonical_bytes(inline_report))
        - len(binding.canonical_bytes(report))
    )

    assert saved_bytes >= (
        _CAPACITY_DEFICIT_BYTES + _REQUIRED_SIZE_MARGIN_BYTES
    )
    assert report["verifier_execution"][
        "obligation_denominator_commitment"
    ]["conditional_refutations_digest"] == binding.value_digest(
        conditional_ledger
    )
    retained_nonpass = next(
        row for row in report["obligation_instances"]
        if row["instance_digest"] == nonpass_before["instance_digest"]
    )
    assert retained_nonpass == nonpass_before


@pytest.mark.parametrize(
    ("case", "mutate"),
    _INVALID_MUTATIONS,
    ids=[case for case, _ in _INVALID_MUTATIONS],
)
def test_incomplete_or_incoherent_tier_three_receipt_is_not_retained(
    case: str,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    del case  # Parameter name remains visible in pytest's generated test ID.
    report = deepcopy(_valid_tier_three_report())
    mutate(report)

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "NOT_RETAINED"
    assert "cumulative_tier_evidence_unavailable" in receipt["omitted_sections"]


def test_unencodable_source_report_is_not_retained() -> None:
    report = _valid_tier_three_report()
    report["unencodable"] = object()

    receipt = package_polish._capacity_receipt(report)

    assert receipt["denominator_status"] == "NOT_RETAINED"
    assert receipt["source_report_encoding_status"] == "UNAVAILABLE"
    assert receipt["source_report_digest"] is None
    assert receipt["source_report_bytes"] is None


@pytest.mark.parametrize(
    "mutation",
    [
        "unsupported_source_schema",
        "wrong_tier_one_prerequisite_schema",
        "wrong_tier_two_prerequisite_identity",
        "missing_tier_one_source_digest",
        "null_tier_two_source_digest",
        "pass_missing_full_source_recapture",
        "pass_nonpass_full_source_recapture",
        "pass_with_failed_checker",
    ],
)
def test_complete_capacity_schema_rejects_structural_false_passes(
    mutation: str,
) -> None:
    schema = json.loads((
        Path(__file__).resolve().parents[1]
        / "src/verifier/schemas/verifier-manifest-package-polish-capacity-2.schema.json"
    ).read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    receipt = package_polish._capacity_receipt(_valid_tier_three_report())
    assert receipt["denominator_status"] == "COMPLETE"
    if mutation == "unsupported_source_schema":
        receipt["source_report_schema"] = "verifier-manifest-package-polish-99"
    elif mutation == "wrong_tier_one_prerequisite_schema":
        receipt["native_diagnostics"]["prerequisites"]["1"][
            "schema_version"
        ] = "verifier-self-polish-tier-assessment-6"
    elif mutation == "wrong_tier_two_prerequisite_identity":
        receipt["native_diagnostics"]["prerequisites"]["2"]["tier"] = 1
    elif mutation == "missing_tier_one_source_digest":
        del receipt["native_diagnostics"]["prerequisites"]["1"][
            "source_coordinate_digest"
        ]
    elif mutation == "null_tier_two_source_digest":
        receipt["native_diagnostics"]["prerequisites"]["2"][
            "source_coordinate_digest"
        ] = None
    elif mutation == "pass_missing_full_source_recapture":
        del receipt["native_diagnostics"]["prerequisites"]["1"][
            "post_replay_full_source_recapture"
        ]
    elif mutation == "pass_nonpass_full_source_recapture":
        receipt["native_diagnostics"]["prerequisites"]["2"][
            "post_replay_full_source_recapture"
        ] = "FAIL"
    else:
        entry = receipt["obligation_index"]["entries"][0]
        entry.update(status="PASS", checker_status="FAIL")

    with pytest.raises(jsonschema.ValidationError):
        validator.validate(receipt)


def test_complete_capacity_schema_retains_source_bound_nonpass_prerequisite() -> None:
    schema = json.loads((
        Path(__file__).resolve().parents[1]
        / "src/verifier/schemas/verifier-manifest-package-polish-capacity-2.schema.json"
    ).read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    receipt = package_polish._capacity_receipt(_valid_tier_three_report())
    native = receipt["native_diagnostics"]
    native["status"] = "FAIL"
    prerequisite = native["prerequisites"]["1"]
    prerequisite["status"] = "FAIL"
    del prerequisite["post_replay_full_source_recapture"]

    validator.validate(receipt)


# Pre-encoding envelope adversaries.  Each shape is shallow at the top level and
# would be materialized by a naive whole-report canonical encoding.  The spy
# refuses that encoding instead of allocating it, so a regression fails closed
# without consuming the payload the envelope exists to reject.


class _WholeReportEncodingAttempted(Exception):
    """A spy refused a whole-report encoding instead of allocating its bytes."""


def _refuse_whole_encoding(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    attempts: list[str] = []
    real_canonical_bytes = binding.canonical_bytes

    def spy(value: Any) -> bytes:
        if type(value) is dict and value.get("schema_version") in {
            package_polish.REPORT_SCHEMA,
            package_polish.EXTENSIBLE_REPORT_SCHEMA,
        }:
            attempts.append(value["schema_version"])
            raise _WholeReportEncodingAttempted(value["schema_version"])
        return real_canonical_bytes(value)

    monkeypatch.setattr(binding, "canonical_bytes", spy)
    return attempts


def _envelope_base_report() -> dict[str, Any]:
    return {
        "schema_version": package_polish.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": package_polish.namespace_contracts.kind_denominators(),
        "requested_tier": 3,
        "status": "UNKNOWN",
        "blockers": ["PACKAGE_INSTANCE_EVIDENCE_INCOMPLETE"],
        "manifest": {"path": "objects.vstd", "status": "SELECTED", "digest": _DIGEST},
        "source_coordinate_digest": None,
        "mechanism_digest": None,
        "obligation_instances": [],
        "tier_results": [],
    }


def _pass_row(index: int, realization: Any) -> dict[str, Any]:
    return {
        "object_id": f"subject-{index}",
        "object_kind": "OBJECT",
        "coordinate": "OBJECT-1.2",
        "tier": 1,
        "status": "PASS",
        "checker_status": "PASS",
        "blockers": [],
        "repository_realization": realization,
    }


def _adversarial_report(shape: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    report = _envelope_base_report()
    if shape == "deep-nesting":
        nested: list[Any] = []
        cursor = nested
        for _ in range(10_000):
            child: list[Any] = []
            cursor.append(child)
            cursor = child
        report["extra_payload"] = nested
    elif shape == "shared-dag":
        dag: Any = {"leaf": "shared"}
        for _ in range(64):
            dag = {"left": dag, "right": dag}
        report["extra_payload"] = dag
    elif shape == "cyclic":
        loop: list[Any] = []
        loop.append(loop)
        report["extra_payload"] = loop
    elif shape == "huge-shared-string":
        shared_payload = {"mechanism_bindings": ["s" * (1 << 20)]}
        report["obligation_instances"] = [
            _pass_row(index, shared_payload) for index in range(300)
        ]
    elif shape == "wide-fan-out":
        monkeypatch.setattr(package_polish, "MAX_REPORT_BYTES", 1024)
        report["obligation_instances"] = [
            _pass_row(index, {"index": index}) for index in range(50_000)
        ]
    else:
        raise AssertionError(shape)
    return report


@pytest.mark.parametrize(
    "shape",
    ["deep-nesting", "shared-dag", "cyclic", "huge-shared-string", "wide-fan-out"],
)
def test_pre_encoding_adversaries_never_reach_whole_report_encoding(
    monkeypatch: pytest.MonkeyPatch, shape: str,
) -> None:
    """RED: each adversary must route to capacity before any whole encoding."""

    report = _adversarial_report(shape, monkeypatch)
    attempts = _refuse_whole_encoding(monkeypatch)

    receipt = package_polish._seal(report)

    assert attempts == []
    assert receipt["schema_version"] == package_polish.CAPACITY_REPORT_SCHEMA
    assert receipt["source_report_encoding_status"] == "UNAVAILABLE"
    assert receipt["source_report_digest"] is None
    assert receipt["denominator_status"] == "NOT_RETAINED"
    assert receipt["whole_package_conformance"] == "NOT_ESTABLISHED"
    assert receipt["polished"] is False
    assert "PACKAGE_REPORT_CAPACITY_EXHAUSTED" in receipt["blockers"]


def test_preencoding_visits_stay_bounded_for_duplicated_and_deep_shapes() -> None:
    """RED: traversal work is bounded by unique structure and depth budgets.

    A 64-level shared-identity DAG expands to 2**64 leaves.  Its memoized
    lower bound must exceed the envelope after a few dozen visits.  A 10,000-
    deep chain must stop at the explicit depth budget without recursing.
    """

    dag: Any = {"leaf": "shared"}
    for _ in range(64):
        dag = {"left": dag, "right": dag}
    dag_verdict = package_polish._assess_preencoding_envelope(dag)
    assert dag_verdict.within_envelope is False
    assert dag_verdict.visits <= 1_000

    deep: list[Any] = []
    cursor = deep
    for _ in range(10_000):
        child: list[Any] = []
        cursor.append(child)
        cursor = child
    deep_verdict = package_polish._assess_preencoding_envelope(deep)
    assert deep_verdict.within_envelope is False
    assert deep_verdict.reason == "PACKAGE_REPORT_PREENCODING_DEPTH_EXCEEDED"
    assert deep_verdict.visits <= package_polish.MAX_PREENCODING_DEPTH + 16


def test_preencoding_visit_budget_is_a_reasoned_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED: a wide, non-shared fan-out stops at the explicit visit budget."""

    monkeypatch.setattr(package_polish, "MAX_PREENCODING_VISITS", 10)

    verdict = package_polish._assess_preencoding_envelope(
        [{"index": index} for index in range(1_000)]
    )

    assert verdict.within_envelope is False
    assert verdict.reason == "PACKAGE_REPORT_PREENCODING_VISITS_EXCEEDED"
    assert verdict.visits <= 11


def test_projected_source_envelope_retains_ninth_report_multiple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lossless projected source gets bounded headroom before compaction."""

    monkeypatch.setattr(package_polish, "MAX_REPORT_BYTES", 1_024)
    source = {"projected": "x" * 8_300}

    verdict = package_polish._assess_preencoding_envelope(source)

    assert len(binding.canonical_bytes(source)) > 8 * 1_024
    assert verdict.within_envelope is True
    assert verdict.lower_bound_bytes <= 9 * 1_024


def test_preencoding_visit_budget_covers_bounded_projection_density() -> None:
    """The finite visit bound covers 64 nodes per admitted obligation."""

    assert package_polish.MAX_PREENCODING_VISITS >= (
        64 * package_polish.MAX_OBLIGATION_INSTANCES
    )


def test_pre_encoding_refusals_cover_cycles_and_unencodable_leaves() -> None:
    cyclic: list[Any] = []
    cyclic.append(cyclic)

    cycle = package_polish._assess_preencoding_envelope(cyclic)
    unencodable = package_polish._assess_preencoding_envelope({"value": object()})
    non_finite = package_polish._assess_preencoding_envelope({"value": float("nan")})

    assert cycle.within_envelope is False
    assert cycle.reason == "PACKAGE_REPORT_PREENCODING_CYCLIC"
    assert unencodable.within_envelope is False
    assert unencodable.reason == "PACKAGE_REPORT_PREENCODING_UNENCODABLE"
    assert non_finite.within_envelope is False
    assert non_finite.reason == "PACKAGE_REPORT_PREENCODING_UNENCODABLE"


@pytest.mark.parametrize(
    "value",
    [
        None, True, False, 0, -(10**40), 1.5,
        "", "quote \" slash \\ newline \n control \x01 é lambda λ 🤖",
        [], {}, [[], {}], {"b": [1, None], "a": {"c": True}}, ("tuple", 1),
        {"k" * 300: "v" * 300},
        [{"index": index, "text": "é" * index} for index in range(40)],
    ],
)
def test_lower_bound_never_exceeds_canonical_length(value: Any) -> None:
    """Differential oracle: the preflight may underestimate, never overstate."""

    verdict = package_polish._assess_preencoding_envelope(value)

    assert verdict.within_envelope is True
    assert verdict.lower_bound_bytes <= len(binding.canonical_bytes(value))


def test_twenty_two_thousand_row_structure_is_linear_and_sound() -> None:
    """A 22,136-row shape with small evidence stays inside the envelope.

    The structure is visited once per unique object, not once per shared
    reference, and the lower bound remains a sound underestimate of the actual
    canonical encoding.
    """

    shared_realization = {"explanation": "x", "mechanism_bindings": []}
    report = _envelope_base_report()
    report["obligation_instances"] = [
        {
            "object_id": f"subject-{index}",
            "object_kind": "OBJECT",
            "coordinate": "OBJECT-1.2",
            "tier": 1,
            "status": "UNKNOWN",
            "checker_status": "NOT_RUN",
            "instance_digest": _DIGEST,
            "blockers": ["PACKAGE_INSTANCE_EVIDENCE_MISSING"],
            "selected_package_check": None,
            "repository_realization": shared_realization,
        }
        for index in range(22_136)
    ]

    verdict = package_polish._assess_preencoding_envelope(report)

    assert verdict.within_envelope is True
    assert verdict.visits <= 32 * 22_136
    assert verdict.lower_bound_bytes <= len(binding.canonical_bytes(report))
