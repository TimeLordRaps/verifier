"""Project-level acceptance tests for recursive Verifier Standard self-polish."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from verifier.core import namespace
from verifier.runtime import core_obligation_union
from verifier.runtime import package_self_polish as package
from verifier.runtime import polish_requirements
from verifier.runtime import self_polish_estate
from verifier.runtime import self_polish_tiers


def _source_coordinate() -> dict[str, str]:
    return {
        "source_head": "1" * 40,
        "source_tree": "2" * 40,
        "source_worktree_status_digest": "sha256:" + "3" * 64,
        "source_manifest_digest": "sha256:" + "4" * 64,
    }


def _tier1_report(source_coordinate: dict[str, str]) -> dict:
    report = {
        "schema_version": self_polish_tiers.REPORT_SCHEMA,
        "tier": 1,
        "tier_name": "FACETS",
        "status": "PASS",
        "selected_tier_status": "PASS",
        "whole_tier_conformance": "PASS",
        "source_binding_status": "PASS",
        "source_coordinate": deepcopy(source_coordinate),
        "source_coordinate_digest": core_obligation_union.value_digest(
            source_coordinate
        ),
        "core_self_polish_attempt": {"status": "PASS"},
        "complete_self_representation": {
            "status": "PASS",
            "subject": {
                "object_id": package.POLISH_VERIFIER_ID,
                "object_kind": "VERIFIER",
            },
            "represented_tiers": [1],
        },
        "polished": False,
        "release_authorized": False,
        "blockers": [],
    }
    report["report_digest"] = core_obligation_union.value_digest(report)
    return report


def _redigest(report: dict) -> dict:
    report.pop("report_digest", None)
    report["report_digest"] = core_obligation_union.value_digest(report)
    return report


def _package_schema() -> dict:
    return json.loads(Path(
        "src/verifier/schemas/"
        "verifier-package-graph-self-polish-assessment-1.schema.json"
    ).read_text(encoding="utf-8"))


def test_package_report_schema_accepts_complete_and_unavailable_reports() -> None:
    schema = json.loads(Path(
        "src/verifier/schemas/"
        "verifier-package-graph-self-polish-assessment-1.schema.json"
    ).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    validator.validate(package.assess_package_self_polish(_source_coordinate()))
    validator.validate(package.unavailable_package_report(
        numeric_tier1_report={}
    ))


def test_package_report_schema_rejects_nested_field_injection() -> None:
    schema = json.loads(Path(
        "src/verifier/schemas/"
        "verifier-package-graph-self-polish-assessment-1.schema.json"
    ).read_text(encoding="utf-8"))
    report = package.assess_package_self_polish(_source_coordinate())
    report["tier_zero_representation_cells"][0]["unbound_claim"] = "PASS"

    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(report)


def test_package_report_schema_rejects_hollow_or_substituted_sections() -> None:
    schema = json.loads(Path(
        "src/verifier/schemas/"
        "verifier-package-graph-self-polish-assessment-1.schema.json"
    ).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    baseline = package.assess_package_self_polish(_source_coordinate())

    mutations = []
    hollow_graph = deepcopy(baseline)
    hollow_graph["package_graph"] = {}
    mutations.append(hollow_graph)
    empty_grid = deepcopy(baseline)
    empty_grid["core_family_cells"] = []
    mutations.append(empty_grid)
    substituted_subject = deepcopy(baseline)
    substituted_subject["self_verifier_tier1"]["subject"] = {
        "object_id": "attacker",
        "object_kind": "VERIFIER",
    }
    mutations.append(substituted_subject)
    forged_absent_owner = deepcopy(baseline)
    forged_absent_owner["owner_decision_admission"]["owner_id"] = "attacker"
    mutations.append(forged_absent_owner)
    owner_fail_hidden_by_unknown = deepcopy(baseline)
    admission = owner_fail_hidden_by_unknown["owner_decision_admission"]
    admission["status"] = "FAIL"
    admission["error"] = "SYNTHETIC_OWNER_FAILURE"
    admission.pop("admission_digest")
    admission["admission_digest"] = core_obligation_union.value_digest(
        admission
    )
    mutations.append(owner_fail_hidden_by_unknown)

    for report in mutations:
        _redigest(report)
        with pytest.raises(ValidationError):
            validator.validate(report)


def test_package_graph_represents_every_object_kind_once() -> None:
    coordinate = _source_coordinate()
    objects = package.build_package_graph(coordinate)

    assert len(objects) == len(namespace.ObjectKind) == 26
    assert {item.kind for item in objects} == set(namespace.ObjectKind)
    assert len({item.kind for item in objects}) == len(objects)
    assert all(
        item.payload["source_coordinate_digest"]
        == core_obligation_union.value_digest(coordinate)
        for item in objects
    )

    root = next(item for item in objects if item.object_id == package.PACKAGE_GRAPH_ID)
    polish = next(item for item in objects if item.object_id == package.POLISH_VERIFIER_ID)
    assert root.kind is namespace.ObjectKind.GRAPH
    assert root.payload["element_kind"] == "OBJECT"
    assert dict(root.operands)["members"] == tuple(
        sorted(item.object_id for item in objects if item is not root)
    )
    assert polish.kind is namespace.ObjectKind.VERIFIER
    assert any(item.kind is namespace.ObjectKind.EVENT for item in objects)

    expected = namespace.composition_digest(objects)
    assessment = namespace.assess_composition(objects, expected_digest=expected)
    assert assessment.verdict.value == "PASS"
    assert assessment.collection_digest == expected
    assert assessment.objects_checked == 26


@pytest.mark.parametrize("value", [None, 1, [], {}])
def test_package_graph_rejects_non_string_owner_admission_status(value) -> None:
    with pytest.raises(
        ValueError, match="PACKAGE_OWNER_DECISION_ADMISSION_STATUS_INVALID"
    ):
        package.build_package_graph(
            _source_coordinate(),
            owner_decision_admission_status=value,
        )


def test_package_graph_rejects_owner_pass_without_candidate_pass() -> None:
    with pytest.raises(
        ValueError, match="PACKAGE_OWNER_DECISION_WITHOUT_CANDIDATE_PASS"
    ):
        package.build_package_graph(
            _source_coordinate(),
            owner_decision_admission_status="PASS",
            owner_decision_admission_digest="sha256:" + "5" * 64,
        )


def test_package_graph_binds_source_run_and_verifier_mechanisms() -> None:
    evidence = {
        "source_manifest_digest": "sha256:" + "a" * 64,
        "candidate_source_census_digest": "sha256:" + "b" * 64,
        "candidate_source_file_count": 3,
        "candidate_source_bytes": 99,
        "tracked_file_count": 2,
        "untracked_nonignored_file_count": 1,
    }
    report_digest = "sha256:" + "c" * 64
    candidate_digest = "sha256:" + "d" * 64
    tier_zero_digest = "sha256:" + "e" * 64
    tier_zero_profile = "sha256:" + "f" * 64
    objects = package.build_package_graph(
        _source_coordinate(),
        self_verifier_report_digest=report_digest,
        self_verifier_report_status="PASS",
        source_evidence=evidence,
        candidate_selection_digest=candidate_digest,
        candidate_selection_status="PASS",
        tier_zero_report_digest=tier_zero_digest,
        tier_zero_report_status="PASS",
        tier_zero_profile_digest=tier_zero_profile,
    )
    evidence_digest = core_obligation_union.value_digest(evidence)
    assert all(
        item.payload["source_evidence_status"] == "BOUND"
        and item.payload["source_evidence_digest"] == evidence_digest
        for item in objects
    )
    event = next(item for item in objects if item.kind.value == "EVENT")
    receipt = next(item for item in objects if item.kind.value == "RECEIPT")
    verifier = next(item for item in objects if item.kind.value == "VERIFIER")
    assert event.payload["execution_status"] == "PASS"
    assert event.payload["execution_report_digest"] == report_digest
    assert receipt.payload["retained_report_digest"] == report_digest
    assert verifier.payload["candidate_selection_digest"] == candidate_digest
    assert verifier.payload["tier_zero_report_digest"] == tier_zero_digest
    assert verifier.payload["tier_zero_report_status"] == "PASS"
    assert verifier.payload["tier_zero_profile_digest"] == tier_zero_profile
    assert event.payload["tier_zero_execution_report_digest"] \
        == tier_zero_digest
    assert receipt.payload["tier_zero_retained_report_digest"] \
        == tier_zero_digest
    assert verifier.payload["package_gate_mechanism_digest"].startswith(
        "sha256:"
    )


def test_project_gate_exposes_exact_denominators_and_fails_closed() -> None:
    report = package.assess_package_self_polish(_source_coordinate())

    assert report["schema_version"] == package.REPORT_SCHEMA
    assert report["status"] == report["project_gate_status"] == "UNKNOWN"
    assert report["polished"] is report["release_authorized"] is False
    assert report["package_graph"]["status"] == "PASS"
    assert report["package_graph"]["root_kind"] == "GRAPH"
    assert report["package_graph"]["polish_object_kind"] == "VERIFIER"
    assert report["denominators"] == {
        "object_kind_count": 26,
        "tier_zero_representation_cell_count": 26,
        "core_tier_count": 9,
        "core_family_cell_count": 234,
        "registered_core_route_membership_count": 408,
        "corrigibility_extension_cell_count": 26,
        "core_and_tier_zero_cell_count": 260,
        "tracked_assessment_cell_count": 286,
    }
    assert len(report["tier_zero_representation_cells"]) == 26
    admission = report["tier_zero_repository_admission"]
    assert admission["status"] == "NOT_ESTABLISHED"
    assert admission["report_digest"] is None
    assert admission["assessment_reason_count"] == 0
    assert "TIER_ZERO_REPOSITORY_ADMISSION_NOT_ESTABLISHED" \
        in report["blockers"]
    assert len(report["core_family_cells"]) == 234
    assert len(report["corrigibility_extension_cells"]) == 26
    assert all(
        cell["structural_representation_status"] == "PASS"
        and cell["native_facets_discrimination_status"] == "PASS"
        and cell["repository_admission_status"] == "NOT_ESTABLISHED"
        and cell["repository_admission_report_digest"] is None
        and cell["semantic_obligation_status"] == "NOT_ESTABLISHED"
        and cell["assessment_reason"]
        and cell["status"] == "UNKNOWN"
        and cell["owner_decision_refs"] == []
        for cell in report["tier_zero_representation_cells"]
    )
    native = report["native_facets_replay"]
    assert native["status"] == "PASS"
    assert native["object_count"] == 26
    assert native["objective_count"] == 52
    assert native["pass_count"] == 52
    assert native["fail_count"] == native["unknown_count"] == 0
    assert native["case_count"] == 156
    assert native["positive_case_count"] == 52
    assert native["negative_case_count"] == 52
    assert native["unknown_case_count"] == 52
    assert len(native["results"]) == 26
    assert all(row["status"] == "PASS" for row in native["results"])
    assert all(
        row["generic_object_facets"]["status"] == "PASS"
        and row["typed_facets"]["status"] == "PASS"
        for row in native["results"]
    )
    assert len(report["core_route_memberships"]) == 408
    assert report["core_route_projection"]["status"] == "PASS"
    assert report["core_route_projection"][
        "mapped_checker_discrimination_count"
    ] == 27
    assert report["core_route_projection"]["not_run_count"] == 381
    assert len({
        (row["object_kind"], row["tier"], row["semantic_version"],
         row["coordinate"])
        for row in report["core_route_memberships"]
    }) == 408
    assert all(row["status"] == "UNKNOWN"
               for row in report["core_route_memberships"])
    assert all(cell["status"] == "UNKNOWN"
               for cell in report["core_family_cells"])
    assert all(cell["status"] == "UNKNOWN"
               for cell in report["corrigibility_extension_cells"])
    assert report["self_verifier_tier1"]["status"] == "NOT_ESTABLISHED"
    assert report["self_verifier_tier1"]["retention_status"] \
        == "NOT_SELECTED"
    assert report["blockers"] == sorted(set(report["blockers"]))
    assert {
        "SELF_VERIFIER_TIER1_REPORT_UNAVAILABLE",
        "CORE_FAMILY_CELL_CLOSURE_NOT_ESTABLISHED",
        "CORRIGIBILITY_EXTENSION_NOT_ESTABLISHED",
    }.issubset(report["blockers"])
    assert "TIER_ZERO_REPRESENTATION_NOT_PASS" not in report["blockers"]
    body = {key: value for key, value in report.items()
            if key != "report_digest"}
    assert report["report_digest"] == core_obligation_union.value_digest(body)


def test_hand_built_self_verifier_report_is_rejected() -> None:
    coordinate = _source_coordinate()
    tier1 = _tier1_report(coordinate)

    report = package.assess_package_self_polish(
        coordinate, self_verifier_tier1_report=tier1,
    )

    assert report["status"] == "FAIL"
    assert report["self_verifier_tier1"]["status"] == "FAIL"
    assert "SELF_VERIFIER_TIER1_REPORT_INVALID" in report["blockers"]
    event = next(
        row for row in report["package_graph"]["object_records"]
        if row["kind"] == "EVENT"
    )
    assert event["payload"]["execution_status"] == "REJECTED"


def test_strictly_retained_self_verifier_pass_cannot_promote_package(
        monkeypatch: pytest.MonkeyPatch) -> None:
    coordinate = _source_coordinate()
    tier1 = _tier1_report(coordinate)
    monkeypatch.setattr(
        self_polish_tiers,
        "_retained_tier1",
        lambda *_args, **_kwargs: deepcopy(tier1),
    )

    report = package.assess_package_self_polish(
        coordinate,
        self_verifier_tier1_report=tier1,
    )

    assert report["self_verifier_tier1"]["status"] == "PASS"
    assert report["status"] == "UNKNOWN"
    assert "SELF_VERIFIER_TIER1_REPORT_UNAVAILABLE" not in report["blockers"]
    assert "CORE_FAMILY_CELL_CLOSURE_NOT_ESTABLISHED" in report["blockers"]
    assert "CORRIGIBILITY_EXTENSION_NOT_ESTABLISHED" in report["blockers"]
    verifier = next(
        row for row in report["package_graph"]["object_records"]
        if row["kind"] == "VERIFIER"
    )
    assert verifier["payload"]["self_verifier_report_digest"] \
        == tier1["report_digest"]
    assert verifier["payload"]["self_verifier_report_status"] == "PASS"


def test_self_verifier_report_from_another_source_is_rejected() -> None:
    coordinate = _source_coordinate()
    other = deepcopy(coordinate)
    other["source_head"] = "f" * 40
    tier1 = _tier1_report(other)

    report = package.assess_package_self_polish(
        coordinate, self_verifier_tier1_report=tier1,
    )

    assert report["status"] == "FAIL"
    assert report["self_verifier_tier1"]["status"] == "FAIL"
    assert "SELF_VERIFIER_TIER1_SOURCE_DIFFERS" in report["blockers"]
    assert report["polished"] is report["release_authorized"] is False
    verifier = next(
        row for row in report["package_graph"]["object_records"]
        if row["kind"] == "VERIFIER"
    )
    assert verifier["payload"]["self_verifier_report_digest"] is None
    assert verifier["payload"]["self_verifier_report_status"] is None


def test_strict_numeric_unknown_remains_unknown(
        monkeypatch: pytest.MonkeyPatch) -> None:
    coordinate = _source_coordinate()
    tier1 = _tier1_report(coordinate)
    tier1.update(
        status="UNKNOWN",
        selected_tier_status="UNKNOWN",
        whole_tier_conformance="NOT_ESTABLISHED",
    )
    tier1["complete_self_representation"]["status"] = "UNKNOWN"
    _redigest(tier1)
    monkeypatch.setattr(
        self_polish_tiers,
        "_retained_tier1",
        lambda *_args, **_kwargs: deepcopy(tier1),
    )

    report = package.assess_package_self_polish(
        coordinate,
        self_verifier_tier1_report=tier1,
    )

    assert report["status"] == "UNKNOWN"
    assert report["self_verifier_tier1"]["status"] == "UNKNOWN"
    assert report["self_verifier_tier1"]["retention_status"] == "RETAINED"
    assert report["self_verifier_tier1"]["subject"] is None
    assert report["self_verifier_tier1"]["represented_tiers"] == []
    assert report["self_verifier_tier1"]["source_binding_status"] \
        == "NOT_ESTABLISHED"
    assert "SELF_VERIFIER_TIER1_NOT_PASS" in report["blockers"]


@pytest.mark.parametrize("error", [
    polish_requirements.MechanismBindingUnavailable("git unavailable"),
    self_polish_estate.EstateError("GIT_STATE_UNAVAILABLE"),
])
def test_strict_retention_git_unavailability_remains_unknown(
        monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    coordinate = _source_coordinate()
    tier1 = _tier1_report(coordinate)

    def unavailable(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(self_polish_tiers, "_retained_tier1", unavailable)

    report = package.assess_package_self_polish(
        coordinate,
        self_verifier_tier1_report=tier1,
    )

    assert report["status"] == "UNKNOWN"
    assert report["self_verifier_tier1"]["status"] == "UNKNOWN"
    assert report["self_verifier_tier1"]["retention_status"] == "UNAVAILABLE"
    assert "SELF_VERIFIER_TIER1_REPORT_UNAVAILABLE" in report["blockers"]
    assert "SELF_VERIFIER_TIER1_REPORT_INVALID" not in report["blockers"]


def test_numeric_failure_survives_retention_unavailability(
        monkeypatch: pytest.MonkeyPatch) -> None:
    coordinate = _source_coordinate()
    tier1 = _tier1_report(coordinate)
    tier1.update(
        status="FAIL",
        selected_tier_status="FAIL",
        whole_tier_conformance="NOT_ESTABLISHED",
    )
    tier1["complete_self_representation"]["status"] = "FAIL"
    _redigest(tier1)
    monkeypatch.setattr(
        self_polish_tiers,
        "_retained_tier1",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            polish_requirements.MechanismBindingUnavailable("git unavailable")
        ),
    )

    report = package.assess_package_self_polish(
        coordinate,
        self_verifier_tier1_report=tier1,
    )

    assert report["status"] == report["project_gate_status"] == "FAIL"
    assert report["self_verifier_tier1"]["status"] == "FAIL"
    assert report["self_verifier_tier1"]["retention_status"] == "UNAVAILABLE"
    assert "SELF_VERIFIER_TIER1_REPORT_UNAVAILABLE" in report["blockers"]
    assert "NUMERIC_SELF_VERIFIER_TIER1_FAILED" in report["blockers"]


def test_untrusted_unknown_report_fields_are_not_echoed() -> None:
    coordinate = _source_coordinate()
    report = self_polish_tiers._base_report(
        1, self_polish_tiers._denominators(package.POLISH_VERIFIER_ID)
    )
    report["source_coordinate"] = deepcopy(coordinate)
    report["source_coordinate_digest"] = core_obligation_union.value_digest(
        coordinate
    )
    report["source_binding_status"] = "PASS"
    report["complete_self_representation"] = {
        "status": "UNKNOWN",
        "subject": {"object_id": "attacker", "object_kind": "HUMAN"},
        "represented_tiers": list(range(1, 10)),
    }
    _redigest(report)

    assessed = package.assess_package_self_polish(
        coordinate, self_verifier_tier1_report=report
    )

    assert assessed["status"] == "UNKNOWN"
    assert assessed["self_verifier_tier1"]["status"] == "UNKNOWN"
    assert assessed["self_verifier_tier1"]["subject"] is None
    assert assessed["self_verifier_tier1"]["represented_tiers"] == []
    assert assessed["self_verifier_tier1"]["source_binding_status"] \
        == "NOT_ESTABLISHED"


def test_invalid_unknown_report_fails_integrity_and_is_not_bound() -> None:
    coordinate = _source_coordinate()
    tier1 = _tier1_report(coordinate)
    tier1.update(status="UNKNOWN", selected_tier_status="UNKNOWN")
    tier1["report_digest"] = "malformed"

    report = package.assess_package_self_polish(
        coordinate, self_verifier_tier1_report=tier1
    )

    assert report["status"] == "FAIL"
    assert report["self_verifier_tier1"]["status"] == "FAIL"
    assert report["self_verifier_tier1"]["retention_status"] == "REJECTED"
    verifier = next(
        row for row in report["package_graph"]["object_records"]
        if row["kind"] == "VERIFIER"
    )
    assert verifier["payload"]["self_verifier_report_digest"] is None


def test_unavailable_wrapper_preserves_numeric_fail() -> None:
    numeric = {
        "status": "FAIL",
        "report_digest": "sha256:" + "a" * 64,
    }
    report = package.unavailable_package_report(
        numeric_tier1_report=numeric
    )

    assert report["status"] == report["project_gate_status"] == "FAIL"
    assert report["self_verifier_tier1"]["status"] == "FAIL"
    assert "NUMERIC_SELF_VERIFIER_TIER1_FAILED" in report["blockers"]


def test_unavailable_package_assessment_preserves_numeric_unknown() -> None:
    numeric = {
        "status": "UNKNOWN",
        "report_digest": "sha256:" + "a" * 64,
        "source_coordinate": _source_coordinate(),
    }
    report = package.package_assessment_unavailable_report(
        numeric_tier1_report=numeric
    )

    assert report["schema_version"] == package.REPORT_SCHEMA
    assert report["status"] == report["project_gate_status"] == "UNKNOWN"
    assert report["self_verifier_tier1"]["status"] == "UNKNOWN"
    assert report["blockers"] == [
        "PACKAGE_SELF_POLISH_ASSESSMENT_UNAVAILABLE"
    ]


def test_unavailable_package_report_survives_mechanism_read_outage(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package,
        "mechanism_digest",
        lambda: (_ for _ in ()).throw(OSError("mechanism unavailable")),
    )

    report = package.package_assessment_unavailable_report(
        numeric_tier1_report={
            "status": "UNKNOWN",
            "report_digest": "sha256:" + "a" * 64,
            "source_coordinate": _source_coordinate(),
        }
    )

    assert report["schema_version"] == package.REPORT_SCHEMA
    assert report["status"] == "UNKNOWN"
    assert report["mechanism_digest"] is None
    Draft202012Validator(_package_schema()).validate(report)


def test_contradiction_report_survives_malformed_source_coordinate() -> None:
    report = package.package_assessment_contradiction_report(
        numeric_tier1_report={"status": "UNKNOWN"},
        source_coordinate={"malformed": True},
        blocker="PACKAGE_SELF_POLISH_CONTRACT_VIOLATION",
    )

    assert report["status"] == "FAIL"
    assert report["source_coordinate"] is None
    assert "PACKAGE_SELF_POLISH_CONTRACT_VIOLATION" in report["blockers"]
    Draft202012Validator(_package_schema()).validate(report)


def test_contradiction_report_preserves_numeric_failure() -> None:
    report = package.package_assessment_contradiction_report(
        numeric_tier1_report={"status": "FAIL"},
        source_coordinate=_source_coordinate(),
        blocker="PACKAGE_CORE_ROUTE_INVENTORY_CONTRADICTION",
    )

    assert report["status"] == report["project_gate_status"] == "FAIL"
    assert report["blockers"] == [
        "NUMERIC_SELF_VERIFIER_TIER1_FAILED",
        "PACKAGE_CORE_ROUTE_INVENTORY_CONTRADICTION",
    ]


def test_source_recapture_mismatch_fails_package(
        monkeypatch: pytest.MonkeyPatch) -> None:
    observed = {
        "git_head": "f" * 40,
        "git_tree": "e" * 40,
        "worktree_status_digest": "sha256:" + "d" * 64,
        "candidate_source_census_digest": "sha256:" + "c" * 64,
        "candidate_source_file_count": 3,
        "candidate_source_bytes": 99,
        "tracked_file_count": 2,
        "untracked_nonignored_file_count": 1,
    }
    monkeypatch.setattr(
        package.polish_requirements,
        "capture_core_self_polish_source",
        lambda _root: deepcopy(observed),
    )

    report = package.assess_package_self_polish(
        _source_coordinate(), source_root="selected-source"
    )

    assert report["status"] == "FAIL"
    assert report["source_recapture_binding"]["status"] == "FAIL"
    assert "PACKAGE_SOURCE_RECAPTURE_FAILED" in report["blockers"]
    assert all(
        row["payload"]["source_evidence_status"] == "NOT_SELECTED"
        and row["payload"]["source_evidence_digest"] is None
        for row in report["package_graph"]["object_records"]
    )


def test_installed_inventory_contradiction_is_fail_not_unknown(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package.core_tier_progression,
        "installed_core_route_inventory",
        lambda: (_ for _ in ()).throw(RuntimeError("synthetic contradiction")),
    )

    report = package.assess_package_self_polish(_source_coordinate())

    assert report["status"] == report["project_gate_status"] == "FAIL"
    assert report["package_graph"] is None
    assert report["blockers"] == [
        "CORE_FAMILY_CELL_CLOSURE_NOT_ESTABLISHED",
        "CORRIGIBILITY_EXTENSION_NOT_ESTABLISHED",
        "PACKAGE_CORE_ROUTE_INVENTORY_CONTRADICTION",
        "SELF_VERIFIER_TIER1_REPORT_UNAVAILABLE",
        "TIER_ZERO_REPOSITORY_ADMISSION_NOT_ESTABLISHED",
    ]


def test_route_projection_rejects_native_identity_drift() -> None:
    report = package.assess_package_self_polish(_source_coordinate())
    native = deepcopy(report["native_facets_replay"])
    native["results"][0]["typed_facets"]["checking_mechanism"] = (
        "attacker.recheck"
    )

    projection = package._core_route_memberships(
        package.core_tier_progression.installed_core_route_inventory(),
        native,
        report["installed_native_case_replay"],
    )

    assert projection["status"] == "FAIL"
    assert any(
        row["native_route_identity_status"] == "FAIL"
        and row["status"] == "FAIL"
        for row in projection["memberships"]
    )


def test_composition_fail_cannot_leave_tier_zero_pass(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package,
        "assess_composition",
        lambda *_args, **_kwargs: namespace.CompositionAssessment(
            namespace.Verdict.FAIL, "sha256:" + "0" * 64,
            "synthetic refutation", 0,
        ),
    )

    report = package.assess_package_self_polish(_source_coordinate())

    assert report["status"] == "FAIL"
    assert report["package_graph"]["status"] == "FAIL"
    assert all(
        row["structural_representation_status"] == "FAIL"
        for row in report["tier_zero_representation_cells"]
    )
    assert "TIER_ZERO_REPRESENTATION_NOT_PASS" in report["blockers"]


def test_composition_unknown_remains_unknown_in_tier_zero(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package,
        "assess_composition",
        lambda *_args, **_kwargs: namespace.CompositionAssessment(
            namespace.Verdict.UNKNOWN, "sha256:" + "0" * 64,
            "synthetic unavailable composition", 0,
        ),
    )

    report = package.assess_package_self_polish(_source_coordinate())

    assert report["status"] == "UNKNOWN"
    assert all(
        row["structural_representation_status"] == "UNKNOWN"
        for row in report["tier_zero_representation_cells"]
    )
    assert "TIER_ZERO_OBJECT_ADMISSION_NOT_ESTABLISHED" \
        in report["blockers"]


class _UnavailableJson:
    """Exact failure double; a named class stays visible to source admission."""

    @staticmethod
    def loads(*_args, **_kwargs):
        raise RecursionError("synthetic bounded recursion exhaustion")


def test_round_trip_resource_exhaustion_remains_unknown(
        monkeypatch: pytest.MonkeyPatch) -> None:
    objects = package.build_package_graph(_source_coordinate())
    expected_digest = namespace.composition_digest(objects)
    monkeypatch.setattr(package, "json", _UnavailableJson)

    assessment, _wire_digest, exact = package._round_trip_composition(
        objects, expected_digest
    )

    assert assessment.verdict is namespace.Verdict.UNKNOWN
    assert exact is False


def test_source_recapture_unavailable_does_not_bind_graph_evidence(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package.polish_requirements,
        "capture_core_self_polish_source",
        lambda _root: (_ for _ in ()).throw(
            package.polish_requirements.MechanismBindingUnavailable(
                "synthetic git unavailability"
            )
        ),
    )

    report = package.assess_package_self_polish(
        _source_coordinate(), source_root="selected-source"
    )

    assert report["status"] == "UNKNOWN"
    assert report["source_recapture_binding"]["status"] == "UNKNOWN"
    assert "PACKAGE_SOURCE_RECAPTURE_UNAVAILABLE" in report["blockers"]
    assert all(
        row["payload"]["source_evidence_status"] == "NOT_SELECTED"
        and row["payload"]["source_evidence_digest"] is None
        for row in report["package_graph"]["object_records"]
    )


def test_partial_installed_replay_preserves_completed_tier_counts(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package.self_polish_native_replay,
        "build_installed_replay_manifest",
        lambda *_args, **_kwargs: b"{}",
    )
    calls = 0

    def replay(*_args: object, **_kwargs: object) -> dict:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic tier-two unavailability")
        return {
            "status": "PASS",
            "manifest_digest": "sha256:" + "1" * 64,
            "receipt_digest": "sha256:" + "2" * 64,
            "membership_count": 1,
            "case_count": 3,
            "invalidators": [],
            "memberships": [{"coordinate": "VERIFIER-1.1"}],
        }

    monkeypatch.setattr(
        package.self_polish_native_replay,
        "replay_native_obligations",
        replay,
    )

    result = package._installed_native_case_replay(
        tmp_path, core_obligation_union.value_digest(_source_coordinate())
    )

    assert result["status"] == "UNKNOWN"
    assert result["membership_count"] == 1
    assert result["case_count"] == 3


def test_partial_installed_replay_preserves_prior_tier_failure(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package.self_polish_native_replay,
        "build_installed_replay_manifest",
        lambda *_args, **_kwargs: b"{}",
    )
    calls = 0

    def replay(*_args: object, **_kwargs: object) -> dict:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic tier-two unavailability")
        return {
            "status": "FAIL",
            "manifest_digest": "sha256:" + "1" * 64,
            "receipt_digest": "sha256:" + "2" * 64,
            "membership_count": 1,
            "case_count": 3,
            "invalidators": ["SYNTHETIC_REFUTATION"],
            "memberships": [{"coordinate": "VERIFIER-1.1"}],
        }

    monkeypatch.setattr(
        package.self_polish_native_replay,
        "replay_native_obligations",
        replay,
    )

    result = package._installed_native_case_replay(
        tmp_path, core_obligation_union.value_digest(_source_coordinate())
    )

    assert result["status"] == "FAIL"
    assert result["membership_count"] == 1
    assert result["case_count"] == 3


def test_installed_digest_outage_carries_prior_failure(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package.self_polish_native_replay,
        "build_installed_replay_manifest",
        lambda *_args, **_kwargs: b"{}",
    )
    monkeypatch.setattr(
        package.self_polish_native_replay,
        "replay_native_obligations",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            package.self_polish_native_replay.NativeReplayResourceError(
                failure_observed=True
            )
        ),
    )

    result = package._installed_native_case_replay(
        tmp_path, core_obligation_union.value_digest(_source_coordinate())
    )

    assert result["status"] == "FAIL"


def test_partial_installed_tier_failure_does_not_refute_unrun_next_tier(
        monkeypatch: pytest.MonkeyPatch) -> None:
    source_digest = core_obligation_union.value_digest(_source_coordinate())
    monkeypatch.setattr(
        package,
        "_installed_native_case_replay",
        lambda *_args, **_kwargs: {
            "schema_version": "verifier-package-installed-native-case-replay-1",
            "status": "FAIL",
            "resource_status": "UNAVAILABLE",
            "source_coordinate_digest": source_digest,
            "tier_results": [{
                "tier": 1,
                "status": "FAIL",
                "manifest_digest": "sha256:" + "1" * 64,
                "receipt_digest": "sha256:" + "2" * 64,
                "membership_count": 0,
                "case_count": 0,
                "invalidators": ["SYNTHETIC_TIER_ONE_REFUTATION"],
            }],
            "memberships": [],
            "membership_count": 0,
            "case_count": 0,
            "claim_boundary": "synthetic partial installed replay",
            "replay_digest": "sha256:" + "3" * 64,
        },
    )

    report = package.assess_package_self_polish(_source_coordinate())
    tier_one = [
        row for row in report["core_route_memberships"] if row["tier"] == 1
    ]
    tier_two = [
        row for row in report["core_route_memberships"] if row["tier"] == 2
    ]

    assert tier_one and tier_two
    assert all(row["installed_specimen_replay_status"] == "UNKNOWN"
               for row in tier_one)
    assert all(row["installed_specimen_replay_status"] == "UNKNOWN"
               for row in tier_two)


def test_late_resource_interruption_preserves_native_failure(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package,
        "_native_facets_replay",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            package.PackageAssessmentUnavailable(
                "PACKAGE_NATIVE_FACETS_REPLAY_FAILED"
            )
        ),
    )

    report = package.assess_package_self_polish(_source_coordinate())

    assert report["status"] == report["project_gate_status"] == "FAIL"
    assert report["package_graph"] is None
    assert "PACKAGE_SELF_POLISH_ASSESSMENT_UNAVAILABLE" in report["blockers"]
    assert "PACKAGE_NATIVE_FACETS_REPLAY_FAILED" in report["blockers"]


def test_late_native_request_digest_outage_preserves_observed_failure(
        monkeypatch: pytest.MonkeyPatch) -> None:
    objects = package.build_package_graph(_source_coordinate())
    source_digest = core_obligation_union.value_digest(_source_coordinate())
    selected_request: dict[str, object] = {}
    original_request = package.object_facets.object_facets_request
    original_recheck = (
        package.object_facets.recheck_object_facets_certificate
    )
    original_digest = core_obligation_union.value_digest
    replay_count = 0

    def capture_request(*args, **kwargs):
        request = original_request(*args, **kwargs)
        selected_request.setdefault("value", request)
        return request

    def refute_negative_case(*args, **kwargs):
        nonlocal replay_count
        result = original_recheck(*args, **kwargs)
        if replay_count == 1:
            result = {**result, "status": "PASS"}
        replay_count += 1
        return result

    def fail_after_cases(value):
        if value is selected_request.get("value"):
            raise MemoryError("synthetic late request-digest outage")
        return original_digest(value)

    monkeypatch.setattr(
        package.object_facets, "object_facets_request", capture_request
    )
    monkeypatch.setattr(
        package.object_facets,
        "recheck_object_facets_certificate",
        refute_negative_case,
    )
    monkeypatch.setattr(
        package.core_obligation_union, "value_digest", fail_after_cases
    )

    replay = package._native_facets_replay(objects, source_digest)

    assert replay["status"] == "FAIL"
    assert replay["results"][0]["status"] == "FAIL"
    assert replay["results"][0]["resource_status"] == "UNAVAILABLE"


def test_inventory_outage_preserves_prior_source_failure(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package,
        "_source_recapture_binding",
        lambda *_args, **_kwargs: {
            "status": "FAIL", "matches_selected_source": False,
            "observed_source_coordinate": None,
            "observed_source_evidence": None,
            "claim_boundary": "synthetic source contradiction",
        },
    )
    monkeypatch.setattr(
        package.core_tier_progression,
        "installed_core_route_inventory",
        lambda: (_ for _ in ()).throw(OSError("synthetic inventory outage")),
    )

    report = package.assess_package_self_polish(
        _source_coordinate(), source_root="selected-source"
    )

    assert report["status"] == report["project_gate_status"] == "FAIL"
    assert "PACKAGE_SOURCE_RECAPTURE_FAILED" in report["blockers"]
    assert "PACKAGE_SELF_POLISH_ASSESSMENT_UNAVAILABLE" in report["blockers"]


def test_late_core_cell_outage_preserves_projection_failure(
        monkeypatch: pytest.MonkeyPatch) -> None:
    original = package._core_route_memberships

    def failed_projection(*args, **kwargs):
        result = original(*args, **kwargs)
        result["status"] = "FAIL"
        return result

    monkeypatch.setattr(package, "_core_route_memberships", failed_projection)
    monkeypatch.setattr(
        package,
        "_core_cells",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            MemoryError("synthetic late outage")
        ),
    )

    report = package.assess_package_self_polish(_source_coordinate())

    assert report["status"] == report["project_gate_status"] == "FAIL"
    assert "CORE_ROUTE_NATIVE_PROJECTION_FAILED" in report["blockers"]


def test_installed_replay_attribute_contradiction_is_fail(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package.self_polish_native_replay,
        "build_installed_replay_manifest",
        lambda *_args, **_kwargs: b"{}",
    )
    monkeypatch.setattr(
        package.self_polish_native_replay,
        "replay_native_obligations",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AttributeError("synthetic installed replay contradiction")
        ),
    )

    result = package._installed_native_case_replay(
        tmp_path, core_obligation_union.value_digest(_source_coordinate())
    )

    assert result["status"] == "FAIL"


def test_positive_only_rubber_stamp_cannot_qualify_native_replay(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package.typed_facets,
        "recheck_typed_facets_certificate",
        lambda *_args, **_kwargs: {
            "status": "PASS",
            "authority": "NOT_ESTABLISHED",
            "payload_semantics": "NOT_ESTABLISHED",
        },
    )

    report = package.assess_package_self_polish(_source_coordinate())

    assert report["status"] == "FAIL"
    assert report["native_facets_replay"]["status"] == "FAIL"
    assert report["core_route_projection"]["status"] == "FAIL"
    assert report["core_route_projection"][
        "route_identity_projection_status"
    ] == "PASS"
    assert "PACKAGE_NATIVE_FACETS_REPLAY_FAILED" in report["blockers"]
    assert "CORE_ROUTE_NATIVE_PROJECTION_FAILED" in report["blockers"]
    assert any(
        row["selected_package_native_replay_status"] == "FAIL"
        and row["status"] == "FAIL"
        for row in report["core_route_memberships"]
    )


def test_real_projection_attributes_only_sim_24_specimen_unknown(
        ) -> None:
    coordinate = _source_coordinate()
    source_digest = core_obligation_union.value_digest(coordinate)
    objects = package.build_package_graph(coordinate)
    native = package._native_facets_replay(objects, source_digest)
    installed = package._installed_native_case_replay(
        Path(__file__).parents[1], source_digest
    )
    inventory = package.core_tier_progression.installed_core_route_inventory()

    projection = package._core_route_memberships(
        inventory, native, installed
    )

    assert projection["route_identity_projection_status"] == "PASS"
    assert projection["status"] == "UNKNOWN"
    assert projection["unavailable_selected_count"] == 0
    assert projection["installed_specimen_unknown_count"] == 1
    assert projection["unknown_causes"] == ["SIM:SIM-2.4"]

    drifted = deepcopy(installed)
    drifted["memberships"][0]["membership"]["proposition_digest"] = (
        "sha256:" + "0" * 64
    )
    contradicted = package._core_route_memberships(
        inventory, native, drifted
    )

    assert contradicted["route_identity_projection_status"] == "FAIL"
    assert contradicted["status"] == "FAIL"


def test_package_mechanism_drift_after_graph_build_fails_closed(
        monkeypatch: pytest.MonkeyPatch) -> None:
    opening = "sha256:" + "a" * 64
    closing = "sha256:" + "b" * 64
    observed = iter((opening, closing))
    monkeypatch.setattr(package, "mechanism_digest", lambda: next(observed))

    report = package.assess_package_self_polish(_source_coordinate())

    assert report["status"] == "FAIL"
    assert report["mechanism_digest"] == opening
    assert "PACKAGE_GATE_MECHANISM_RECAPTURE_FAILED" in report["blockers"]


@pytest.mark.parametrize("field", [
    "candidate_obligation_ledger",
    "native_facets_replay",
    "installed_native_case_replay",
    "corrigibility_research_evidence",
])
def test_embedded_assessment_sections_reject_hollow_objects(field: str) -> None:
    report = package.assess_package_self_polish(_source_coordinate())
    report[field] = {}

    with pytest.raises(ValidationError):
        Draft202012Validator(_package_schema()).validate(report)


def test_positive_unknown_is_preserved_without_becoming_a_refutation(
        monkeypatch: pytest.MonkeyPatch) -> None:
    original = package.typed_facets.recheck_typed_facets_certificate

    def preserve_positive_unknown(*args: object, **kwargs: object) -> dict:
        result = original(*args, **kwargs)
        if result["status"] == "PASS":
            result = dict(result, status="UNKNOWN")
        return result

    monkeypatch.setattr(
        package.typed_facets,
        "recheck_typed_facets_certificate",
        preserve_positive_unknown,
    )

    report = package.assess_package_self_polish(_source_coordinate())

    assert report["status"] == "UNKNOWN"
    assert report["native_facets_replay"]["status"] == "UNKNOWN"
    assert report["native_facets_replay"]["fail_count"] == 0
    assert report["native_facets_replay"]["unknown_count"] == 26
    assert report["core_route_projection"]["status"] == "UNKNOWN"
    assert "PACKAGE_NATIVE_FACETS_REPLAY_FAILED" not in report["blockers"]
    assert "CORE_ROUTE_NATIVE_PROJECTION_NOT_ESTABLISHED" \
        in report["blockers"]


def test_unavailable_native_replay_stays_unknown(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package.typed_facets,
        "typed_facets_request",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("unavailable")),
    )

    report = package.assess_package_self_polish(_source_coordinate())

    assert report["status"] == "UNKNOWN"
    assert report["native_facets_replay"]["status"] == "UNKNOWN"
    assert report["core_route_projection"]["status"] == "UNKNOWN"
    assert "CORE_ROUTE_NATIVE_PROJECTION_FAILED" not in report["blockers"]
    assert "CORE_ROUTE_NATIVE_PROJECTION_NOT_ESTABLISHED" in report["blockers"]
    assert all(row["status"] == "UNKNOWN"
               for row in report["core_route_memberships"])


@pytest.mark.parametrize("error_type", [ValueError, AttributeError])
def test_contradicted_native_replay_fails_route_projection(
        monkeypatch: pytest.MonkeyPatch, error_type: type[Exception]) -> None:
    monkeypatch.setattr(
        package.typed_facets,
        "typed_facets_request",
        lambda **_kwargs: (_ for _ in ()).throw(
            error_type("synthetic native contract contradiction")
        ),
    )

    report = package.assess_package_self_polish(_source_coordinate())

    assert report["status"] == "FAIL"
    assert report["native_facets_replay"]["status"] == "FAIL"
    assert report["core_route_projection"]["status"] == "FAIL"
    assert "CORE_ROUTE_NATIVE_PROJECTION_FAILED" in report["blockers"]
    assert all(
        row["selected_package_native_replay_status"] == "FAIL"
        and row["status"] == "FAIL"
        for row in report["core_route_memberships"]
        if row["tier"] == 1 and (
            row["coordinate"] == "OBJECT-1.1"
            or row["coordinate"].endswith("-1.1")
        )
    )


def test_contradicted_installed_replay_fails_selected_route_projection(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package,
        "_installed_native_case_replay",
        lambda *_args, **_kwargs: {
            "schema_version": "verifier-package-installed-native-case-replay-1",
            "status": "FAIL",
            "resource_status": "AVAILABLE",
            "source_coordinate_digest": core_obligation_union.value_digest(
                _source_coordinate()
            ),
            "tier_results": [],
            "memberships": [],
            "membership_count": 0,
            "case_count": 0,
            "claim_boundary": "synthetic installed replay contradiction",
            "replay_digest": "sha256:" + "0" * 64,
        },
    )

    report = package.assess_package_self_polish(_source_coordinate())

    assert report["status"] == "FAIL"
    assert report["core_route_projection"]["status"] == "UNKNOWN"
    selected = [
        row for row in report["core_route_memberships"]
        if row["tier"] in (1, 2)
    ]
    unselected = [
        row for row in report["core_route_memberships"]
        if row["tier"] not in (1, 2)
    ]
    assert len(selected) == 82
    assert all(
        row["installed_specimen_replay_status"] == "UNKNOWN"
        and row["status"] == "UNKNOWN"
        for row in selected
    )
    assert all(
        row["installed_specimen_replay_status"] == "NOT_RUN"
        for row in unselected
    )


def test_candidate_filesystem_outage_cannot_mask_source_failure(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package,
        "_source_recapture_binding",
        lambda *_args, **_kwargs: {
            "status": "FAIL",
            "matches_selected_source": False,
            "observed_source_coordinate": None,
            "observed_source_evidence": None,
            "claim_boundary": "synthetic source contradiction",
        },
    )
    monkeypatch.setattr(
        package.package_obligation_candidate,
        "load_candidate_obligation_ledger",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            PermissionError("synthetic cards outage")
        ),
    )

    report = package.assess_package_self_polish(
        _source_coordinate(),
        source_root="selected-source",
        candidate_obligation_cards_root="cards",
        candidate_obligation_manifest_path="manifest",
        expected_candidate_obligation_manifest_digest="sha256:" + "5" * 64,
    )

    assert report["status"] == "FAIL"
    assert "PACKAGE_SOURCE_RECAPTURE_FAILED" in report["blockers"]
    assert report["candidate_obligation_ledger"]["status"] == "UNKNOWN"
    assert "PACKAGE_OBLIGATION_CANDIDATE_UNAVAILABLE" in report["blockers"]


def test_closing_source_recapture_detects_assessment_time_drift(
        monkeypatch: pytest.MonkeyPatch) -> None:
    captures = iter([
        {
            "status": "UNKNOWN",
            "matches_selected_source": "UNKNOWN",
            "observed_source_coordinate": None,
            "observed_source_evidence": None,
            "claim_boundary": "synthetic opening outage",
        },
        {
            "status": "FAIL",
            "matches_selected_source": False,
            "observed_source_coordinate": None,
            "observed_source_evidence": None,
            "claim_boundary": "synthetic closing mismatch",
        },
    ])
    monkeypatch.setattr(
        package,
        "_source_recapture_binding",
        lambda *_args, **_kwargs: next(captures),
    )

    report = package.assess_package_self_polish(
        _source_coordinate(), source_root="selected-source"
    )

    assert report["status"] == "FAIL"
    assert report["source_recapture_binding"]["status"] == "FAIL"
    assert "PACKAGE_SOURCE_RECAPTURE_FAILED" in report["blockers"]


def test_resource_exhausted_native_replay_stays_unknown(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package.typed_facets,
        "typed_facets_request",
        lambda **_kwargs: (_ for _ in ()).throw(
            RecursionError("synthetic bounded recursion exhaustion")
        ),
    )

    report = package.assess_package_self_polish(_source_coordinate())

    assert report["status"] == "UNKNOWN"
    assert report["native_facets_replay"]["status"] == "UNKNOWN"
    assert "PACKAGE_NATIVE_FACETS_REPLAY_FAILED" not in report["blockers"]


def test_completed_native_failure_survives_typed_resource_outage(
        monkeypatch: pytest.MonkeyPatch) -> None:
    original = package.object_facets.recheck_object_facets_certificate

    def generic_failure(*args, **kwargs):
        result = original(*args, **kwargs)
        if result["status"] == "FAIL":
            result = {**result, "status": "PASS"}
        return result

    monkeypatch.setattr(
        package.object_facets,
        "recheck_object_facets_certificate",
        generic_failure,
    )
    monkeypatch.setattr(
        package.typed_facets,
        "build_typed_facets_certificate",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            MemoryError("synthetic typed replay outage")
        ),
    )

    report = package.assess_package_self_polish(_source_coordinate())

    assert report["status"] == report["project_gate_status"] == "FAIL"
    assert report["native_facets_replay"]["status"] == "FAIL"
    assert all(
        row["status"] == "FAIL"
        and row["generic_object_facets"]["status"] == "FAIL"
        and row["typed_facets"] is None
        and row["resource_status"] == "UNAVAILABLE"
        for row in report["native_facets_replay"]["results"]
    )
    assert "PACKAGE_NATIVE_FACETS_REPLAY_FAILED" in report["blockers"]


def test_corrigibility_cells_are_wip_selections_not_certificates() -> None:
    report = package.assess_package_self_polish(_source_coordinate())

    assert all(
        row["schema_version"]
            == "verifier-package-corrigibility-cell-selection-1"
        and row["declared_status"] == "WIP"
        and row["native_status"] == "NOT_RUN"
        and row["qualification"] == "NOT_ESTABLISHED"
        and row["status"] == "UNKNOWN"
        and row["research_surface_status"]
            == "BOUND_RESEARCH_INPUTS_NOT_QUALIFICATION"
        and row["research_evidence_digest"]
            == report["corrigibility_research_evidence"]["evidence_digest"]
        and row["code_set_status"]
            == "RESEARCH_SURFACES_BOUND_OWNER_DECISION_PENDING"
        and row["owner_decision_refs"] == []
        for row in report["corrigibility_extension_cells"]
    )
    assert report["corrigibility_extension_selection"] == {
        "schema_version": "verifier-corrigibility-extension-selection-1",
        "profile_id": "verifier-corrigibility-extension-selection-1",
        "declared_status": "WIP",
        "binding_digest": core_obligation_union.value_digest({
            "cells": report["corrigibility_extension_cells"],
            "research_evidence_digest": report[
                "corrigibility_research_evidence"
            ]["evidence_digest"],
        }),
    }
    assert report["corrigibility_research_evidence"]["module_count"] >= 1
    assert report["corrigibility_research_evidence"]["verifier_10_1"][
        "coordinate"
    ] == "VERIFIER-10.1"


def test_unavailable_source_never_fabricates_a_package_graph() -> None:
    report = package.unavailable_package_report(numeric_tier1_report={})

    assert report["status"] == report["project_gate_status"] == "UNKNOWN"
    assert report["source_coordinate"] is None
    assert report["package_graph"] is None
    assert report["denominators"] is None
    assert report["native_facets_replay"] is None
    assert report["blockers"] == ["PACKAGE_SOURCE_COORDINATE_UNAVAILABLE"]
    assert report["polished"] is report["release_authorized"] is False


def test_package_report_capacity_fallback_is_bounded_and_preserves_failure() -> None:
    attempted = package.assess_package_self_polish(_source_coordinate())
    attempted["status"] = attempted["project_gate_status"] = "FAIL"

    report = package.package_report_capacity_exhausted_report(attempted)

    assert report["status"] == report["project_gate_status"] == "FAIL"
    assert report["source_coordinate"] == _source_coordinate()
    assert report["package_graph"] is None
    assert "PACKAGE_REPORT_TRANSPORT_CAPACITY_EXHAUSTED" in report["blockers"]
    assert set(attempted["blockers"]) <= set(report["blockers"])
    assert report["self_verifier_tier1"]["status"] != "PASS"
    assert report["self_verifier_tier1"]["source_binding_status"] \
        == "NOT_ESTABLISHED"


def test_capacity_fallback_preserves_rejection_without_numeric_relabel() -> None:
    coordinate = _source_coordinate()
    other = deepcopy(coordinate)
    other["source_head"] = "f" * 40
    attempted = package.assess_package_self_polish(
        coordinate,
        self_verifier_tier1_report=_tier1_report(other),
    )

    report = package.package_report_capacity_exhausted_report(attempted)

    assert report["status"] == report["project_gate_status"] == "FAIL"
    assert report["self_verifier_tier1"]["status"] == "FAIL"
    assert report["self_verifier_tier1"]["retention_status"] == "REJECTED"
    assert report["self_verifier_tier1"]["source_binding_status"] == "FAIL"
    assert "SELF_VERIFIER_TIER1_SOURCE_DIFFERS" in report["blockers"]
    assert "NUMERIC_SELF_VERIFIER_TIER1_FAILED" not in report["blockers"]
    Draft202012Validator(_package_schema()).validate(report)


def test_later_package_outage_preserves_classified_numeric_rejection(
        monkeypatch: pytest.MonkeyPatch) -> None:
    coordinate = _source_coordinate()
    other = deepcopy(coordinate)
    other["source_head"] = "f" * 40
    monkeypatch.setattr(
        package.core_tier_progression,
        "installed_core_route_inventory",
        lambda: (_ for _ in ()).throw(MemoryError("inventory unavailable")),
    )

    report = package.assess_package_self_polish(
        coordinate,
        self_verifier_tier1_report=_tier1_report(other),
    )

    assert report["status"] == report["project_gate_status"] == "FAIL"
    assert report["self_verifier_tier1"]["status"] == "FAIL"
    assert report["self_verifier_tier1"]["retention_status"] == "REJECTED"
    assert "SELF_VERIFIER_TIER1_SOURCE_DIFFERS" in report["blockers"]
    assert "NUMERIC_SELF_VERIFIER_TIER1_FAILED" not in report["blockers"]
    Draft202012Validator(_package_schema()).validate(report)


def test_null_graph_schema_rejects_injected_bound_sections() -> None:
    report = package.unavailable_package_report(numeric_tier1_report={})
    schema = Draft202012Validator(_package_schema())

    for field, injected in (
            ("source_recapture_binding", {}),
            ("core_installed_inventory_digest", "sha256:" + "a" * 64),
            ("candidate_obligation_ledger", {}),
            ("corrigibility_research_evidence", {})):
        selected = deepcopy(report)
        selected[field] = injected
        assert not schema.is_valid(selected), field

    retained = deepcopy(report)
    retained["self_verifier_tier1"].update(
        status="PASS",
        retention_status="RETAINED",
        source_binding_status="PASS",
        represented_tiers=[1],
    )
    assert not schema.is_valid(retained)


def test_graph_present_schema_enforces_cross_section_resource_contracts() -> None:
    report = package.assess_package_self_polish(_source_coordinate())
    schema = Draft202012Validator(_package_schema())

    for field in (
            "source_coordinate", "source_coordinate_digest",
            "source_recapture_binding", "core_installed_inventory_digest",
            "candidate_obligation_ledger",
            "corrigibility_research_evidence"):
        selected = deepcopy(report)
        selected[field] = None
        assert not schema.is_valid(selected), field

    selected = deepcopy(report)
    selected["candidate_obligation_ledger"]["unexpected"] = True
    assert not schema.is_valid(selected)

    selected = deepcopy(report)
    native_row = selected["native_facets_replay"]["results"][0]
    native_row["resource_status"] = "UNAVAILABLE"
    assert not schema.is_valid(selected)

    selected = deepcopy(report)
    native_row = selected["native_facets_replay"]["results"][0]
    native_row["typed_facets"] = None
    native_row["status"] = "UNKNOWN"
    assert not schema.is_valid(selected)

    selected = deepcopy(report)
    selected["installed_native_case_replay"]["resource_status"] = "AVAILABLE"
    assert not schema.is_valid(selected)
