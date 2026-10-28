from __future__ import annotations

import ast
from copy import deepcopy
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from verifier.runtime import core_obligation_union
from verifier.runtime import package_self_polish
from verifier.runtime import package_self_polish_recheck as recheck
from verifier.runtime import public_cli


ROOT = Path(__file__).parents[1]
SCHEMA = json.loads((
    ROOT / "src/verifier/schemas/"
    "verifier-package-graph-self-polish-recheck-1.schema.json"
).read_text(encoding="utf-8"))
COORDINATE = {
    "source_head": "a" * 40,
    "source_tree": "b" * 40,
    "source_worktree_status_digest": "sha256:" + "c" * 64,
    "source_manifest_digest": "sha256:" + "d" * 64,
}


@pytest.fixture(scope="module")
def report() -> dict:
    return package_self_polish.assess_package_self_polish(COORDINATE)


@pytest.fixture(scope="module")
def installed_report() -> dict:
    selected = package_self_polish.assess_package_self_polish(
        COORDINATE, source_root=ROOT
    )
    assert selected["installed_native_case_replay"]["memberships"]
    return selected


def _selection(value: dict) -> tuple[bytes, str]:
    selected = deepcopy(value)
    body = {key: item for key, item in selected.items() if key != "report_digest"}
    selected["report_digest"] = core_obligation_union.value_digest(body)
    return core_obligation_union.canonical_bytes(selected), selected["report_digest"]


def _recheck(value: dict) -> dict:
    raw, digest = _selection(value)
    return recheck.recheck_package_self_polish_report(
        raw,
        expected_report_digest=digest,
        expected_report_bytes_digest=core_obligation_union.bytes_digest(raw),
    )


def _refresh_digest(value: dict, field: str) -> None:
    value[field] = core_obligation_union.value_digest({
        key: item for key, item in value.items() if key != field
    })


def _refresh_installed_tier_receipt(value: dict, tier: int) -> None:
    installed = value["installed_native_case_replay"]
    tier_row = next(row for row in installed["tier_results"]
                    if row["tier"] == tier)
    memberships = [
        row for row in installed["memberships"]
        if row["membership"]["tier"] == tier
    ]
    registry = recheck.self_polish_native_replay.installed_native_replay_registry()
    closure = recheck.self_polish_native_replay.installed_registry_closure()
    receipt = {
        "schema_version": recheck.self_polish_native_replay.RECEIPT_SCHEMA,
        "tier": tier,
        "status": tier_row["status"],
        "manifest_digest": tier_row["manifest_digest"],
        "source_coordinate_digest": value["source_coordinate_digest"],
        "registry_digest": registry["registry_digest"],
        "registry_closure_digest": closure["closure_digest"],
        "memberships": memberships,
        "membership_count": tier_row["membership_count"],
        "case_count": tier_row["case_count"],
        "invalidators": tier_row["invalidators"],
        "polished": False,
        "release_authority": "NONE",
        "whole_tier_conformance": "NOT_ESTABLISHED",
    }
    tier_row["receipt_digest"] = core_obligation_union.value_digest(receipt)


def _memberless_receipt(
        manifest: bytes, tier: int, source_digest: str, status: str,
        invalidators: list[str]) -> dict:
    receipt = {
        "schema_version": recheck.self_polish_native_replay.RECEIPT_SCHEMA,
        "tier": tier,
        "status": status,
        "manifest_digest": core_obligation_union.bytes_digest(manifest),
        "source_coordinate_digest": source_digest,
        "registry_digest": None,
        "registry_closure_digest": None,
        "memberships": [],
        "membership_count": 0,
        "case_count": 0,
        "invalidators": sorted(invalidators),
        "polished": False,
        "release_authority": "NONE",
        "whole_tier_conformance": "NOT_ESTABLISHED",
    }
    receipt["receipt_digest"] = core_obligation_union.value_digest(receipt)
    return receipt


def test_fresh_unknown_report_has_independent_integrity_pass(report: dict) -> None:
    result = _recheck(report)

    assert report["status"] == "UNKNOWN"
    assert result["status"] == "PASS"
    assert result["rechecked_project_status"] == "UNKNOWN"
    assert result["invalidators"] == []
    assert result["unknowns"] == []
    body = {key: value for key, value in result.items()
            if key != "recheck_digest"}
    assert result["recheck_digest"] == core_obligation_union.value_digest(body)
    Draft202012Validator(SCHEMA).validate(result)


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (
            lambda value: value["blockers"].remove(
                "CORE_FAMILY_CELL_CLOSURE_NOT_ESTABLISHED"
            ),
            "PACKAGE_RECHECK_BLOCKER_SET_DIFFERS",
        ),
        (
            lambda value: value["native_facets_replay"].update(status="FAIL"),
            "PACKAGE_RECHECK_NATIVE_REPLAY_STATUS_DIFFERS",
        ),
        (
            lambda value: value["core_route_memberships"][0].update(
                installed_specimen_replay_status="UNKNOWN"
            ),
            "PACKAGE_RECHECK_CORE_PROJECTION_STATUS_DIFFERS",
        ),
        (
            lambda value: next(
                row for row in value["package_graph"]["object_records"]
                if row["kind"] == "VERIFIER"
            )["payload"].update(
                candidate_selection_digest="sha256:" + "0" * 64
            ),
            "PACKAGE_RECHECK_CANDIDATE_GRAPH_BINDING_DIFFERS",
        ),
        (
            lambda value: next(
                row for row in value["package_graph"]["object_records"]
                if row["kind"] == "EVENT"
            )["payload"].update(
                tier_zero_execution_status="PASS"
            ),
            "PACKAGE_RECHECK_TIER_ZERO_GRAPH_BINDING_DIFFERS",
        ),
        (
            lambda value: value["tier_zero_repository_admission"].update(
                closed_coordinates=["VSTD-T0.1"]
            ),
            "PACKAGE_RECHECK_TIER_ZERO_ADMISSION_FIELDS",
        ),
        (
            lambda value: value["package_graph"]["object_records"].__setitem__(
                1, deepcopy(value["package_graph"]["object_records"][0])
            ),
            "PACKAGE_RECHECK_OBJECT_IDENTITY_DUPLICATED",
        ),
        (
            lambda value: value["core_route_memberships"][0].update(
                status="FAIL"
            ),
            "PACKAGE_RECHECK_CORE_CELL_STATUS_DIFFERS",
        ),
    ],
)
def test_schema_shaped_cross_section_tampering_fails(
        report: dict, mutation, code: str) -> None:
    selected = deepcopy(report)
    mutation(selected)

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert code in result["invalidators"]
    Draft202012Validator(SCHEMA).validate(result)


def test_internal_or_external_digest_substitution_fails(report: dict) -> None:
    raw = core_obligation_union.canonical_bytes(report)
    result = recheck.recheck_package_self_polish_report(
        raw,
        expected_report_digest="sha256:" + "0" * 64,
        expected_report_bytes_digest=core_obligation_union.bytes_digest(raw),
    )

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_REPORT_DIGEST_DIFFERS" in result["invalidators"]


def test_exact_retained_bytes_digest_is_required(report: dict) -> None:
    raw, digest = _selection(report)
    altered_bytes = raw + b"\n"
    result = recheck.recheck_package_self_polish_report(
        altered_bytes,
        expected_report_digest=digest,
        expected_report_bytes_digest=core_obligation_union.bytes_digest(raw),
    )

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_REPORT_BYTES_DIGEST_DIFFERS" in result["invalidators"]


def test_malformed_nested_records_fail_instead_of_escaping(report: dict) -> None:
    selected = deepcopy(report)
    selected["core_route_memberships"][0] = None

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_REPORT_STRUCTURE_INVALID" in result["invalidators"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(source_recapture_binding=None),
        lambda value: value.update(candidate_obligation_ledger=None),
        lambda value: value["native_facets_replay"].update(results=[None] * 26),
        lambda value: value["installed_native_case_replay"].update(
            tier_results=[None]
        ),
        lambda value: value["installed_native_case_replay"].update(
            tier_results=[{"tier": 1, "status": "UNKNOWN", "case_count": "3"}]
        ),
        lambda value: value.update(package_graph=[]),
        lambda value: value["core_route_memberships"][0].update(tier=[]),
        lambda value: value["native_facets_replay"].update(results=5),
    ],
)
def test_schema_loose_nested_shapes_never_escape(
        report: dict, mutation) -> None:
    selected = deepcopy(report)
    mutation(selected)

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    Draft202012Validator(SCHEMA).validate(result)


def test_deep_json_nesting_is_bounded_instead_of_crashing() -> None:
    raw = b'{"nested":' + b"[" * 900 + b"0" + b"]" * 900 + b"}"

    result = recheck.recheck_package_self_polish_report(
        raw,
        expected_report_digest="sha256:" + "0" * 64,
        expected_report_bytes_digest=core_obligation_union.bytes_digest(raw),
    )

    assert result["status"] == "FAIL"
    assert result["invalidators"]
    Draft202012Validator(SCHEMA).validate(result)


def test_lone_surrogate_is_a_bounded_failure() -> None:
    raw = b'{"claim_boundary":"\\ud800"}'
    result = recheck.recheck_package_self_polish_report(
        raw,
        expected_report_digest="sha256:" + "0" * 64,
        expected_report_bytes_digest=core_obligation_union.bytes_digest(raw),
    )

    assert result["status"] == "FAIL"
    assert result["invalidators"]
    Draft202012Validator(SCHEMA).validate(result)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["denominators"].update(object_kind_count=26.0),
        lambda value: value["core_route_memberships"][0].update(tier=True),
    ],
)
def test_json_numeric_type_coercions_fail(report: dict, mutation) -> None:
    selected = deepcopy(report)
    mutation(selected)

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_JSON_NUMBER_TYPE_INVALID" in result["invalidators"]


def test_schema_shaped_invalid_source_coordinate_fails(report: dict) -> None:
    selected = deepcopy(report)
    selected["source_coordinate"]["source_head"] = "not-a-git-object"
    selected["source_coordinate_digest"] = core_obligation_union.value_digest(
        selected["source_coordinate"]
    )

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_SOURCE_COORDINATE_INVALID" in result["invalidators"]


def test_coherent_native_branch_failure_cannot_be_laundered(
        report: dict) -> None:
    selected = deepcopy(report)
    branch = selected["native_facets_replay"]["results"][0][
        "generic_object_facets"
    ]
    branch["case_statuses"]["NEGATIVE"] = "PASS"
    _refresh_digest(selected["native_facets_replay"], "replay_digest")

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_NATIVE_REPLAY_ROWS_DIFFER" in result["invalidators"]


def test_native_certificate_digest_substitution_cannot_recheck_pass(
        report: dict) -> None:
    selected = deepcopy(report)
    branch = selected["native_facets_replay"]["results"][0][
        "generic_object_facets"
    ]
    branch["certificate_digests"]["POSITIVE"] = "sha256:" + "0" * 64
    _refresh_digest(selected["native_facets_replay"], "replay_digest")

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert result["unknowns"] == []
    assert "PACKAGE_RECHECK_NATIVE_REPLAY_REPRODUCTION_DIFFERS" in result[
        "invalidators"
    ]


def test_membership_failure_cannot_be_laundered_to_unknown(
        report: dict) -> None:
    selected = deepcopy(report)
    membership = selected["core_route_memberships"][0]
    membership["native_route_identity_status"] = "FAIL"
    membership["selected_package_native_replay_status"] = "FAIL"
    membership["status"] = "UNKNOWN"

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_CORE_MEMBERSHIP_BINDING_DIFFERS" in result[
        "invalidators"
    ]


def test_source_recapture_pass_requires_exact_selected_source(
        report: dict) -> None:
    selected = deepcopy(report)
    selected["source_recapture_binding"] = {
        "status": "PASS",
        "opening_binding": deepcopy(
            report["source_recapture_binding"]["opening_binding"]
        ),
        "matches_selected_source": False,
        "observed_source_coordinate": deepcopy(COORDINATE),
        "observed_source_evidence": {},
        "observed_source_coordinate_digest": core_obligation_union.value_digest(
            COORDINATE
        ),
        "claim_boundary": (
            "PASS establishes exact equality between a later recapture by the "
            "same mechanism and the selected numeric report coordinate; it is "
            "not independent evidence."
        ),
    }

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_SOURCE_RECAPTURE_STATUS_DIFFERS" in result[
        "invalidators"
    ]


def test_closing_source_outage_preserves_opening_graph_evidence(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    evidence = {
        "source_manifest_digest": COORDINATE["source_manifest_digest"],
        "candidate_source_census_digest": "sha256:" + "e" * 64,
        "candidate_source_file_count": 3,
        "candidate_source_bytes": 99,
        "tracked_file_count": 2,
        "untracked_nonignored_file_count": 1,
    }
    captures = iter((
        {
            "status": "PASS",
            "matches_selected_source": True,
            "observed_source_coordinate": deepcopy(COORDINATE),
            "observed_source_evidence": evidence,
            "observed_source_coordinate_digest": (
                core_obligation_union.value_digest(COORDINATE)
            ),
            "claim_boundary": (
                "PASS establishes exact equality between a later recapture by "
                "the same mechanism and the selected numeric report coordinate; "
                "it is not independent evidence."
            ),
        },
        {
            "status": "UNKNOWN",
            "matches_selected_source": "UNKNOWN",
            "observed_source_coordinate": None,
            "observed_source_evidence": None,
            "claim_boundary": "The later source recapture was unavailable.",
        },
    ))
    monkeypatch.setattr(
        package_self_polish,
        "_source_recapture_binding",
        lambda *_args, **_kwargs: next(captures),
    )

    selected = package_self_polish.assess_package_self_polish(
        COORDINATE, source_root=tmp_path / "missing-source-root"
    )
    monkeypatch.setattr(
        recheck,
        "_reproduce_installed_replay",
        lambda *_args: {
            "tier_results": selected["installed_native_case_replay"][
                "tier_results"
            ],
            "memberships": selected["installed_native_case_replay"][
                "memberships"
            ],
        },
    )
    result = _recheck(selected)

    opening_digest = core_obligation_union.value_digest(evidence)
    assert selected["source_recapture_binding"]["status"] == "UNKNOWN"
    opening = selected["source_recapture_binding"]["opening_binding"]
    assert opening["status"] == "PASS"
    assert opening["observed_source_coordinate"] == COORDINATE
    assert opening["observed_source_evidence"] == evidence
    assert all(
        row["payload"]["source_evidence_status"] == "BOUND"
        and row["payload"]["source_evidence_digest"] == opening_digest
        for row in selected["package_graph"]["object_records"]
    )
    assert result["status"] == "PASS"
    assert result["rechecked_project_status"] == "UNKNOWN"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: next(
            row for row in value["package_graph"]["object_records"]
            if row["kind"] == "GRAPH"
        ).update(object_id="renamed-package-graph"),
        lambda value: next(
            row for row in value["package_graph"]["object_records"]
            if row["kind"] == "VERIFIER"
        )["payload"].update(release_authorized=True),
        lambda value: next(
            row for row in value["package_graph"]["object_records"]
            if row["kind"] == "GRAPH"
        )["payload"].update(element_kind="CLAIM"),
    ],
)
def test_graph_template_identity_and_payload_are_pinned(
        report: dict, mutation) -> None:
    selected = deepcopy(report)
    mutation(selected)

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_GRAPH_TEMPLATE_DIFFERS" in result["invalidators"]


def test_retained_numeric_mechanism_digest_is_currently_pinned(
        monkeypatch: pytest.MonkeyPatch) -> None:
    tier1 = {
        "schema_version": recheck.self_polish_tiers.REPORT_SCHEMA,
        "tier": 1,
        "tier_name": "FACETS",
        "status": "PASS",
        "selected_tier_status": "PASS",
        "whole_tier_conformance": "PASS",
        "source_binding_status": "PASS",
        "source_coordinate": deepcopy(COORDINATE),
        "source_coordinate_digest": core_obligation_union.value_digest(
            COORDINATE
        ),
        "core_self_polish_attempt": {"status": "PASS"},
        "complete_self_representation": {
            "status": "PASS",
            "subject": {
                "object_id": package_self_polish.POLISH_VERIFIER_ID,
                "object_kind": "VERIFIER",
            },
            "represented_tiers": [1],
        },
        "mechanism_digest": recheck.self_polish_tiers.mechanism_digest(),
        "polished": False,
        "release_authorized": False,
        "blockers": [],
    }
    tier1["report_digest"] = core_obligation_union.value_digest(tier1)
    monkeypatch.setattr(
        package_self_polish.self_polish_tiers,
        "_retained_tier1",
        lambda *_args, **_kwargs: deepcopy(tier1),
    )
    selected = package_self_polish.assess_package_self_polish(
        COORDINATE,
        self_verifier_tier1_report=tier1,
    )
    verifier = next(
        row for row in selected["package_graph"]["object_records"]
        if row["kind"] == "VERIFIER"
    )
    verifier["payload"]["retained_numeric_mechanism_digest"] = (
        "sha256:" + "0" * 64
    )

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_GRAPH_MECHANISM_CONSTANTS_DIFFER" in (
        result["invalidators"]
    )


def test_section_extensions_and_route_projection_relabels_fail(
        report: dict) -> None:
    extended = deepcopy(report)
    extended["native_facets_replay"]["unreviewed_extension"] = "PASS"
    _refresh_digest(extended["native_facets_replay"], "replay_digest")
    relabeled = deepcopy(report)
    relabeled["core_route_projection"][
        "route_identity_projection_status"
    ] = "FAIL"

    extended_result = _recheck(extended)
    relabeled_result = _recheck(relabeled)

    assert "PACKAGE_RECHECK_SECTION_FIELDS_DIFFER" in extended_result[
        "invalidators"
    ]
    assert "PACKAGE_RECHECK_CORE_PROJECTION_STATUS_DIFFERS" in relabeled_result[
        "invalidators"
    ]


def test_corrigibility_section_and_verifier_input_extensions_fail(
        report: dict) -> None:
    selection = deepcopy(report)
    selection["corrigibility_extension_selection"]["unbound"] = "PASS"
    evidence = deepcopy(report)
    evidence["corrigibility_research_evidence"]["verifier_10_1"][
        "unbound"
    ] = "PASS"
    _refresh_digest(
        evidence["corrigibility_research_evidence"], "evidence_digest"
    )

    selection_result = _recheck(selection)
    evidence_result = _recheck(evidence)

    assert "PACKAGE_RECHECK_CORRIGIBILITY_CONSTANTS_DIFFER" in (
        selection_result["invalidators"]
    )
    assert "PACKAGE_RECHECK_CORRIGIBILITY_CONSTANTS_DIFFER" in (
        evidence_result["invalidators"]
    )


def test_corrigibility_evidence_schema_version_is_pinned(report: dict) -> None:
    selected = deepcopy(report)
    evidence = selected["corrigibility_research_evidence"]
    evidence["schema_version"] = "attacker-corrigibility-evidence"
    _refresh_digest(evidence, "evidence_digest")
    for row in selected["corrigibility_extension_cells"]:
        row["research_evidence_digest"] = evidence["evidence_digest"]
    selected["corrigibility_extension_selection"]["binding_digest"] = (
        core_obligation_union.value_digest({
            "cells": selected["corrigibility_extension_cells"],
            "research_evidence_digest": evidence["evidence_digest"],
        })
    )

    result = _recheck(selected)

    assert "PACKAGE_RECHECK_CORRIGIBILITY_CONSTANTS_DIFFER" in (
        result["invalidators"]
    )


def test_complete_native_replay_mismatch_is_not_softened_to_unknown(
        report: dict) -> None:
    selected = deepcopy(report)
    branch = selected["native_facets_replay"]["results"][0][
        "generic_object_facets"
    ]
    branch["certificate_digests"]["POSITIVE"] = "sha256:" + "0" * 64
    _refresh_digest(selected["native_facets_replay"], "replay_digest")

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_NATIVE_REPLAY_REPRODUCTION_DIFFERS" in (
        result["invalidators"]
    )


def test_unrelated_native_mismatch_is_not_hidden_by_an_outage_row(
        report: dict) -> None:
    selected = deepcopy(report)
    native = selected["native_facets_replay"]
    outage = native["results"][0]
    outage["status"] = "UNKNOWN"
    outage["generic_object_facets"] = None
    outage["typed_facets"] = None
    native["pass_count"] -= 2
    native["unknown_count"] += 2
    native["status"] = "UNKNOWN"
    other = native["results"][1]["typed_facets"]
    other["certificate_digests"]["POSITIVE"] = "sha256:" + "0" * 64
    _refresh_digest(native, "replay_digest")

    result = _recheck(selected)

    assert "PACKAGE_RECHECK_NATIVE_REPLAY_REPRODUCTION_DIFFERS" in (
        result["invalidators"]
    )


def test_installed_outage_only_explains_its_own_tier() -> None:
    retained = {
        "tier_results": [
            {"tier": 1, "invalidators": [
                "NATIVE_REPLAY_MECHANISM_UNAVAILABLE"
            ]},
            {"tier": 2, "invalidators": []},
        ],
        "memberships": [
            {"obligation_id": "A", "membership": {"tier": 1},
             "cases": [{"native_status": "UNKNOWN",
                        "native_result_digest": None}]},
            {"obligation_id": "B", "membership": {"tier": 2},
             "cases": [], "status": "PASS"},
        ],
    }
    reproduced = deepcopy(retained)
    reproduced["memberships"][0]["status"] = "UNKNOWN"
    reproduced["memberships"][1]["status"] = "FAIL"

    assert not recheck._installed_replay_mismatch_is_resource_explained(
        retained, reproduced
    )


def test_forged_tier_outage_does_not_hide_member_mismatch() -> None:
    retained = {
        "tier_results": [{
            "tier": 1,
            "manifest_digest": "sha256:" + "1" * 64,
            "invalidators": ["NATIVE_REPLAY_MECHANISM_UNAVAILABLE"],
        }],
        "memberships": [{
            "obligation_id": "A",
            "membership": {"tier": 1},
            "cases": [],
            "status": "PASS",
        }],
    }
    reproduced = deepcopy(retained)
    reproduced["memberships"][0]["status"] = "FAIL"

    assert not recheck._installed_replay_mismatch_is_resource_explained(
        retained, reproduced
    )


def test_case_outage_does_not_hide_completed_case_mismatch() -> None:
    membership = {"tier": 1, "object_kind": "OBJECT", "coordinate": "X"}
    base_case = {
        "expected_native_status": "PASS",
        "native_status": "PASS",
        "status": "PASS",
        "native_result_digest": "sha256:" + "1" * 64,
        "mechanism_source_path": "mechanism.py",
        "mechanism_source_digest": "sha256:" + "2" * 64,
    }
    retained_row = {
        "obligation_id": "OBJECT:X",
        "membership": membership,
        "cases": [
            {**base_case, "case_kind": "POSITIVE", "native_status": "UNKNOWN",
             "status": "UNKNOWN", "native_result_digest": None},
            {**base_case, "case_kind": "NEGATIVE", "native_status": "FAIL"},
        ],
        "status": "UNKNOWN",
        "native_replay_digest": "sha256:" + "3" * 64,
    }
    reproduced_row = deepcopy(retained_row)
    reproduced_row["cases"][0].update(
        native_status="PASS", status="PASS",
        native_result_digest="sha256:" + "4" * 64,
    )
    reproduced_row["cases"][1]["native_result_digest"] = "sha256:" + "5" * 64

    assert not recheck._member_mismatch_is_resource_explained(
        retained_row, reproduced_row
    )


def test_preserved_case_failure_is_not_treated_as_unknown_outage() -> None:
    retained = {
        "obligation_id": "OBJECT:X",
        "membership": {"tier": 1},
        "cases": [{
            "case_kind": "NEGATIVE",
            "expected_native_status": "FAIL",
            "native_status": "FAIL",
            "status": "PASS",
            "native_result_digest": "sha256:" + "1" * 64,
            "mechanism_source_path": "mechanism.py",
            "mechanism_source_digest": "sha256:" + "2" * 64,
        }],
        "status": "PASS",
        "native_replay_digest": "sha256:" + "3" * 64,
    }
    reproduced = deepcopy(retained)
    reproduced["cases"][0].update(
        native_status="UNKNOWN", status="FAIL", native_result_digest=None,
    )

    assert not recheck._member_mismatch_is_resource_explained(
        retained, reproduced
    )

    retained_failure = deepcopy(reproduced)
    retained_failure["cases"][0].update(
        native_status="PASS", status="FAIL", native_result_digest=None,
    )
    reproduced_failure = deepcopy(retained_failure)
    reproduced_failure["cases"][0]["native_result_digest"] = (
        "sha256:" + "4" * 64
    )
    assert recheck._member_mismatch_is_resource_explained(
        retained_failure, reproduced_failure
    )


def test_negative_case_digest_outage_preserves_fail_status() -> None:
    case = {
        "case_kind": "NEGATIVE",
        "native_status": "UNKNOWN",
        "native_result_digest": None,
    }

    assert recheck._installed_case_statuses(case) == {"FAIL", "UNKNOWN"}


def test_missing_native_branch_does_not_hide_completed_branch_mismatch() -> None:
    retained = {
        "object_id": "vstd-object",
        "object_kind": "OBJECT",
        "status": "UNKNOWN",
        "generic_object_facets": {"status": "PASS", "value": "retained"},
        "typed_facets": None,
        "resource_status": "UNAVAILABLE",
    }
    reproduced = deepcopy(retained)
    reproduced["generic_object_facets"]["value"] = "reproduced"

    assert not recheck._native_row_mismatch_is_resource_explained(
        retained, reproduced
    )
    reproduced["generic_object_facets"] = deepcopy(
        retained["generic_object_facets"]
    )
    reproduced["typed_facets"] = {"status": "PASS"}
    reproduced["resource_status"] = "AVAILABLE"
    assert recheck._native_row_mismatch_is_resource_explained(
        retained, reproduced
    )

    reproduced.update(
        status="FAIL", generic_object_facets=None, typed_facets=None,
        resource_status="UNAVAILABLE",
    )
    retained.update(
        status="PASS", typed_facets={"status": "PASS"},
        resource_status="AVAILABLE",
    )
    assert not recheck._native_row_mismatch_is_resource_explained(
        retained, reproduced
    )


def test_missing_tier_is_not_implicit_resource_evidence() -> None:
    retained = {
        "tier_results": [{
            "tier": 1,
            "manifest_digest": "sha256:" + "1" * 64,
            "invalidators": [],
        }],
        "memberships": [],
    }
    reproduced = {"tier_results": [], "memberships": []}

    assert not recheck._installed_replay_mismatch_is_resource_explained(
        retained, reproduced
    )


def test_failed_tier_outage_does_not_explain_retained_pass() -> None:
    retained = {
        "tier_results": [{"tier": 1, "status": "PASS", "invalidators": []}],
        "memberships": [],
    }
    reproduced = {
        "tier_results": [{
            "tier": 1,
            "status": "FAIL",
            "invalidators": ["NATIVE_REPLAY_MECHANISM_UNAVAILABLE"],
        }],
        "memberships": [],
    }

    assert not recheck._installed_replay_mismatch_is_resource_explained(
        retained, reproduced
    )


def test_case_outage_does_not_explain_manifest_or_missing_member(
        installed_report: dict) -> None:
    installed = installed_report["installed_native_case_replay"]
    retained = {
        "tier_results": [deepcopy(next(
            row for row in installed["tier_results"] if row["tier"] == 2
        ))],
        "memberships": [
            deepcopy(row) for row in installed["memberships"]
            if row["membership"]["tier"] == 2
        ],
    }
    reproduced = deepcopy(retained)
    target = next(
        row for row in retained["memberships"]
        if row["obligation_id"] == "SIM:SIM-2.4"
    )
    target_case = next(
        case for case in target["cases"] if case["case_kind"] == "UNKNOWN"
    )
    target_case.update(status="UNKNOWN", native_result_digest=None)
    target["status"] = "UNKNOWN"
    retained["tier_results"][0]["invalidators"].append(
        "NATIVE_REPLAY_MECHANISM_UNAVAILABLE"
    )
    retained["tier_results"][0]["manifest_digest"] = "sha256:" + "0" * 64

    assert not recheck._installed_replay_mismatch_is_resource_explained(
        retained, reproduced
    )

    retained["tier_results"][0]["manifest_digest"] = reproduced[
        "tier_results"
    ][0]["manifest_digest"]
    unrelated = next(
        row for row in retained["memberships"]
        if row["obligation_id"] != "SIM:SIM-2.4"
    )
    retained["memberships"].remove(unrelated)

    assert not recheck._installed_replay_mismatch_is_resource_explained(
        retained, reproduced
    )


def test_two_native_outages_leave_preserved_failure_uncertain() -> None:
    retained = {
        "object_id": "vstd-object",
        "object_kind": "OBJECT",
        "status": "FAIL",
        "generic_object_facets": {"status": "PASS"},
        "typed_facets": None,
        "resource_status": "UNAVAILABLE",
    }
    reproduced = {
        **retained,
        "status": "UNKNOWN",
        "generic_object_facets": deepcopy(
            retained["generic_object_facets"]
        ),
    }

    assert recheck._native_row_mismatch_is_resource_explained(
        retained, reproduced
    )


def test_two_native_outages_do_not_soften_failure_refuted_by_completed_branch(
        ) -> None:
    failed = {
        "object_id": "vstd-object",
        "object_kind": "OBJECT",
        "status": "FAIL",
        "generic_object_facets": None,
        "typed_facets": None,
        "resource_status": "UNAVAILABLE",
    }
    completed = {
        **failed,
        "status": "UNKNOWN",
        "generic_object_facets": {"status": "PASS"},
    }

    assert not recheck._native_row_mismatch_is_resource_explained(
        failed, completed
    )
    assert not recheck._native_row_mismatch_is_resource_explained(
        completed, failed
    )


def test_native_outage_row_cannot_attribute_pass_to_missing_branch(
        report: dict) -> None:
    selected = deepcopy(report)
    native = selected["native_facets_replay"]
    row = native["results"][0]
    assert row["status"] == "PASS"
    row.update(typed_facets=None, resource_status="UNAVAILABLE")
    native["pass_count"] -= 1
    native["unknown_count"] += 1
    native["status"] = (
        "FAIL" if any(
            result["status"] == "FAIL" for result in native["results"]
        ) else "UNKNOWN"
    )
    _refresh_digest(native, "replay_digest")
    invalidators: set[str] = set()
    unknowns: set[str] = set()
    objects = recheck._reconstruct_graph(selected, set(), set())

    recheck._check_replay_sections(
        selected, objects, invalidators, unknowns
    )

    assert "PACKAGE_RECHECK_NATIVE_REPLAY_ROWS_DIFFER" in invalidators


def test_reproduction_outage_on_retained_contract_failure_branch_is_unknown(
        ) -> None:
    retained = {
        "object_id": "vstd-object",
        "object_kind": "OBJECT",
        "status": "FAIL",
        "generic_object_facets": {"status": "PASS"},
        "typed_facets": None,
        "resource_status": "AVAILABLE",
    }
    reproduced = {
        **retained,
        "status": "UNKNOWN",
        "generic_object_facets": deepcopy(
            retained["generic_object_facets"]
        ),
        "resource_status": "UNAVAILABLE",
    }

    assert recheck._native_row_mismatch_is_resource_explained(
        retained, reproduced
    )


def test_failed_outage_on_contract_failure_branch_is_unknown() -> None:
    contract = {
        "object_id": "vstd-object",
        "object_kind": "OBJECT",
        "status": "FAIL",
        "generic_object_facets": {"status": "PASS"},
        "typed_facets": None,
        "resource_status": "AVAILABLE",
    }
    outage = {
        **contract,
        "generic_object_facets": deepcopy(
            contract["generic_object_facets"]
        ),
        "resource_status": "UNAVAILABLE",
    }

    assert recheck._native_row_mismatch_is_resource_explained(
        contract, outage
    )
    assert recheck._native_row_mismatch_is_resource_explained(
        outage, contract
    )


def test_native_failure_is_bound_to_the_branch_that_failed() -> None:
    base = {
        "object_id": "vstd-object",
        "object_kind": "OBJECT",
        "status": "FAIL",
    }
    present_fail = {
        **base,
        "generic_object_facets": {"status": "FAIL"},
        "typed_facets": None,
        "resource_status": "UNAVAILABLE",
    }
    completed = {
        **base,
        "generic_object_facets": {"status": "FAIL"},
        "typed_facets": {"status": "PASS"},
        "resource_status": "AVAILABLE",
    }
    assert recheck._native_row_mismatch_is_resource_explained(
        present_fail, completed
    )
    missing_fail = {
        **present_fail,
        "generic_object_facets": {"status": "PASS"},
    }
    confirmed = {
        **completed,
        "generic_object_facets": {"status": "PASS"},
        "typed_facets": {"status": "FAIL"},
    }
    assert recheck._native_row_mismatch_is_resource_explained(
        missing_fail, confirmed
    )


def test_two_installed_outages_leave_preserved_failure_uncertain() -> None:
    stable_case = {
        "case_kind": "NEGATIVE",
        "expected_native_status": "FAIL",
        "native_result_digest": None,
        "mechanism_source_path": "mechanism.py",
        "mechanism_source_digest": "sha256:" + "2" * 64,
    }
    retained = {
        "tier_results": [{
            "tier": 1,
            "status": "FAIL",
            "manifest_digest": "sha256:" + "1" * 64,
            "invalidators": ["NATIVE_REPLAY_MECHANISM_UNAVAILABLE"],
        }],
        "memberships": [{
            "obligation_id": "OBJECT:X",
            "membership": {"tier": 1},
            "cases": [{
                **stable_case, "native_status": "PASS", "status": "FAIL",
            }],
            "status": "FAIL",
        }],
    }
    reproduced = deepcopy(retained)
    reproduced["tier_results"][0]["status"] = "UNKNOWN"
    reproduced["memberships"][0]["cases"][0].update(
        native_status="UNKNOWN", status="UNKNOWN"
    )
    reproduced["memberships"][0]["status"] = "UNKNOWN"

    assert recheck._installed_replay_mismatch_is_resource_explained(
        retained, reproduced
    )


def test_case_outage_does_not_explain_unrelated_tier_invalidator(
        installed_report: dict) -> None:
    installed = installed_report["installed_native_case_replay"]
    retained = {
        "tier_results": [deepcopy(next(
            row for row in installed["tier_results"] if row["tier"] == 2
        ))],
        "memberships": [
            deepcopy(row) for row in installed["memberships"]
            if row["membership"]["tier"] == 2
        ],
    }
    reproduced = deepcopy(retained)
    target = next(
        row for row in retained["memberships"]
        if row["obligation_id"] == "SIM:SIM-2.4"
    )
    next(
        case for case in target["cases"] if case["case_kind"] == "UNKNOWN"
    ).update(status="UNKNOWN", native_result_digest=None)
    retained["tier_results"][0]["invalidators"] = sorted(
        retained["tier_results"][0]["invalidators"] + [
            "NATIVE_REPLAY_MECHANISM_UNAVAILABLE",
            "NATIVE_REPLAY_CERTIFICATE_REFUSED",
        ]
    )

    assert not recheck._installed_replay_mismatch_is_resource_explained(
        retained, reproduced
    )


def test_case_outage_masking_does_not_depend_on_unrelated_marker() -> None:
    manifest = "sha256:" + "1" * 64
    retained = {
        "tier_results": [{
            "tier": 2,
            "status": "FAIL",
            "manifest_digest": manifest,
            "membership_count": 0,
            "case_count": 0,
            "invalidators": sorted([
                "NATIVE_REPLAY_CERTIFICATE_REFUSED",
                "SIM_RESOURCE_ACTUAL_CONSUMPTION_"
                "CORRESPONDENCE_NOT_ESTABLISHED",
                "SIM_RESOURCE_COLLECTOR_HONESTY_NOT_ESTABLISHED",
            ]),
        }],
        "memberships": [],
    }
    reproduced = {
        "tier_results": [{
            "tier": 2,
            "status": "UNKNOWN",
            "manifest_digest": manifest,
            "membership_count": 1,
            "case_count": 3,
            "invalidators": ["NATIVE_REPLAY_MECHANISM_UNAVAILABLE"],
        }],
        "memberships": [{
            "obligation_id": "SIM:SIM-2.4",
            "membership": {"tier": 2},
            "cases": [{
                "case_kind": "POSITIVE",
                "native_status": "UNKNOWN",
                "status": "UNKNOWN",
                "native_result_digest": None,
            }],
            "status": "UNKNOWN",
        }],
    }
    marked = deepcopy(retained)
    marked["tier_results"][0]["invalidators"].append(
        "NATIVE_REPLAY_MECHANISM_UNAVAILABLE"
    )

    assert recheck._installed_replay_mismatch_is_resource_explained(
        marked, reproduced
    )
    assert recheck._installed_replay_mismatch_is_resource_explained(
        retained, reproduced
    )
    assert recheck._installed_replay_mismatch_is_resource_explained(
        reproduced, retained
    )


@pytest.mark.parametrize("native_status", ["PASS", "FAIL"])
def test_memberless_sim_evidence_does_not_mask_completed_contradiction(
        native_status: str) -> None:
    manifest = "sha256:" + "1" * 64
    sim_codes = sorted(recheck._SIM_TIER_INVALIDATORS)
    completed = {
        "tier_results": [{
            "tier": 2,
            "status": native_status,
            "manifest_digest": manifest,
            "membership_count": 1,
            "case_count": 3,
            "invalidators": [],
        }],
        "memberships": [{
            "obligation_id": "SIM:SIM-2.4",
            "membership": {"tier": 2},
            "cases": [{
                "case_kind": "POSITIVE",
                "native_status": native_status,
                "status": native_status,
                "native_result_digest": "sha256:" + "4" * 64,
            }],
            "status": native_status,
        }],
    }
    memberless = {
        "tier_results": [{
            "tier": 2,
            "status": "UNKNOWN",
            "manifest_digest": manifest,
            "membership_count": 0,
            "case_count": 0,
            "invalidators": sorted([
                "NATIVE_REPLAY_MECHANISM_UNAVAILABLE", *sim_codes,
            ]),
        }],
        "memberships": [],
    }

    assert not recheck._installed_replay_mismatch_is_resource_explained(
        completed, memberless
    )
    assert not recheck._installed_replay_mismatch_is_resource_explained(
        memberless, completed
    )

    legitimate = deepcopy(completed)
    legitimate["tier_results"][0].update(
        status="UNKNOWN", invalidators=sim_codes
    )
    legitimate_case = legitimate["memberships"][0]["cases"][0]
    legitimate_case.update(native_status="UNKNOWN", status="UNKNOWN")
    legitimate["memberships"][0]["status"] = "UNKNOWN"
    assert recheck._installed_replay_mismatch_is_resource_explained(
        legitimate, memberless
    )


def test_installed_tier_results_must_be_a_producible_prefix(
        installed_report: dict) -> None:
    selected = deepcopy(installed_report)
    installed = selected["installed_native_case_replay"]
    installed["tier_results"] = [
        row for row in installed["tier_results"] if row["tier"] == 2
    ]
    installed["memberships"] = [
        row for row in installed["memberships"]
        if row["membership"]["tier"] == 2
    ]
    installed["membership_count"] = len(installed["memberships"])
    installed["case_count"] = sum(
        row["case_count"] for row in installed["tier_results"]
    )
    installed["status"] = installed["tier_results"][0]["status"]
    installed["resource_status"] = "UNAVAILABLE"
    _refresh_digest(installed, "replay_digest")

    result = _recheck(selected)

    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_STATUS_DIFFERS" in result[
        "invalidators"
    ]


def test_reproduced_contract_failure_matches_retained_fail(
        monkeypatch: pytest.MonkeyPatch) -> None:
    def refused(*_args, **_kwargs):
        raise recheck.self_polish_native_replay.NativeReplayError(
            "SYNTHETIC_MANIFEST_CONTRACT_FAILURE"
        )

    monkeypatch.setattr(
        recheck.self_polish_native_replay,
        "build_installed_replay_manifest",
        refused,
    )
    report = package_self_polish.assess_package_self_polish(
        COORDINATE, source_root=ROOT
    )

    result = _recheck(report)

    assert report["installed_native_case_replay"]["status"] == "FAIL"
    assert result["status"] == "PASS"
    assert result["rechecked_project_status"] == "FAIL"


def test_contract_failure_after_resource_outage_rechecks_unknown(
        monkeypatch: pytest.MonkeyPatch) -> None:
    def manifest(tier, *_args, **_kwargs):
        if tier == 2:
            raise recheck.self_polish_native_replay.NativeReplayError(
                "SYNTHETIC_TIER_TWO_CONTRACT_FAILURE"
            )
        return b"{}"

    def replay(selected_manifest, _root, *, tier,
               expected_source_coordinate_digest, **_kwargs):
        receipt = {
            "schema_version": recheck.self_polish_native_replay.RECEIPT_SCHEMA,
            "tier": tier,
            "status": "UNKNOWN",
            "manifest_digest": core_obligation_union.bytes_digest(
                selected_manifest
            ),
            "source_coordinate_digest": expected_source_coordinate_digest,
            "registry_digest": None,
            "registry_closure_digest": None,
            "memberships": [],
            "membership_count": 0,
            "case_count": 0,
            "invalidators": ["NATIVE_REPLAY_MECHANISM_UNAVAILABLE"],
            "polished": False,
            "release_authority": "NONE",
            "whole_tier_conformance": "NOT_ESTABLISHED",
        }
        receipt["receipt_digest"] = core_obligation_union.value_digest(receipt)
        return receipt

    monkeypatch.setattr(
        recheck.self_polish_native_replay,
        "build_installed_replay_manifest",
        manifest,
    )
    monkeypatch.setattr(
        recheck.self_polish_native_replay,
        "replay_native_obligations",
        replay,
    )
    report = package_self_polish.assess_package_self_polish(
        COORDINATE, source_root=ROOT
    )

    result = _recheck(report)

    assert report["installed_native_case_replay"]["status"] == "FAIL"
    assert report["installed_native_case_replay"]["resource_status"] \
        == "UNAVAILABLE"
    assert result["status"] == "UNKNOWN"
    assert result["invalidators"] == []
    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_REPRODUCTION_DIFFERS" in (
        result["unknowns"]
    )


@pytest.mark.parametrize("mutation", [
    lambda installed: installed["memberships"][0]["cases"][0].update(
        status="UNKNOWN"
    ),
    lambda installed: installed["memberships"][0].update(
        cases=installed["memberships"][0]["cases"][:2]
    ),
    lambda installed: installed["tier_results"][0].update(
        receipt_digest="sha256:" + "0" * 64
    ),
])
def test_installed_replay_case_and_tier_contradictions_fail(
        installed_report: dict, mutation) -> None:
    selected = deepcopy(installed_report)
    installed = selected["installed_native_case_replay"]
    mutation(installed)
    _refresh_digest(installed, "replay_digest")

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_STATUS_DIFFERS" in result[
        "invalidators"
    ]


def test_fresh_installed_replay_report_rechecks_cleanly(
        installed_report: dict) -> None:
    result = _recheck(installed_report)

    assert installed_report["installed_native_case_replay"]["status"] \
        == "UNKNOWN"
    assert result["status"] == "PASS"
    assert result["rechecked_project_status"] == installed_report["status"]
    assert result["invalidators"] == []
    assert result["unknowns"] == []
    candidate = installed_report["full_native_candidate"]
    assert candidate["membership_count"] == 408
    assert candidate["case_count"] == 1224
    assert candidate["route_status_counts"] == {"PASS": 407, "UNKNOWN": 1}
    assert candidate["prepared_membership_count"] == 326
    assert candidate["extension_installation_status"] == "PREPARED_NOT_INSTALLED"
    package_schema = json.loads((ROOT / "src/verifier/schemas/"
        "verifier-package-graph-self-polish-assessment-1.schema.json"
    ).read_text(encoding="utf-8"))
    Draft202012Validator(package_schema).validate(installed_report)


@pytest.mark.parametrize("mutation,invalidator", [
    (lambda item: item["routes"][-1].update(lifecycle="INSTALLED"),
     "PACKAGE_RECHECK_FULL_NATIVE_CANDIDATE_ROUTES_DIFFER"),
    (lambda item: item["routes"][-1]["cases"][1].update(native_status="PASS"),
     "PACKAGE_RECHECK_FULL_NATIVE_CANDIDATE_ROUTES_DIFFER"),
    (lambda item: item.update(prepared_membership_count=0),
     "PACKAGE_RECHECK_FULL_NATIVE_CANDIDATE_AGGREGATES_DIFFER"),
    (lambda item: item["installed_tier_replays"][1].update(status="PASS"),
     "PACKAGE_RECHECK_FULL_NATIVE_CANDIDATE_AGGREGATES_DIFFER"),
])
def test_full_candidate_cannot_promote_lifecycle_or_mask_case_failure(
        installed_report: dict, mutation, invalidator: str) -> None:
    selected = deepcopy(installed_report)
    candidate = selected["full_native_candidate"]
    mutation(candidate)
    _refresh_digest(candidate, "candidate_digest")
    invalidators: set[str] = set()
    recheck._check_full_native_candidate(
        selected, recheck.core_tier_progression.installed_core_route_inventory(),
        invalidators,
    )
    assert invalidator in invalidators


def test_unknown_case_digest_outage_is_recheck_unknown_not_fail(
        installed_report: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    selected = deepcopy(installed_report)
    installed = selected["installed_native_case_replay"]
    reproduced = {
        "tier_results": deepcopy(installed["tier_results"]),
        "memberships": deepcopy(installed["memberships"]),
        "tier_outages": {},
        "tier_failures": {},
    }
    membership = next(
        row for row in installed["memberships"]
        if row["obligation_id"] == "SIM:SIM-2.4"
    )
    unknown_case = next(
        case for case in membership["cases"]
        if case["case_kind"] == "UNKNOWN"
    )
    unknown_case["native_result_digest"] = None
    unknown_case["status"] = "UNKNOWN"
    installed["resource_status"] = "UNAVAILABLE"
    tier_row = next(
        row for row in installed["tier_results"] if row["tier"] == 2
    )
    tier_row["invalidators"] = sorted(
        tier_row["invalidators"] + [
            "NATIVE_REPLAY_MECHANISM_UNAVAILABLE"
        ]
    )
    _refresh_digest(membership, "native_replay_digest")
    _refresh_installed_tier_receipt(selected, 2)
    _refresh_digest(installed, "replay_digest")
    projected = next(
        row for row in selected["core_route_memberships"]
        if row["object_kind"] == membership["membership"]["object_kind"]
        and row["coordinate"] == membership["membership"]["coordinate"]
    )
    projected["installed_specimen_replay_digest"] = membership[
        "native_replay_digest"
    ]
    monkeypatch.setattr(
        recheck,
        "_reproduce_installed_replay",
        lambda *_args: reproduced,
    )

    result = _recheck(selected)

    assert result["invalidators"] == [], result["invalidators"]
    assert result["status"] == "UNKNOWN", result
    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_REPRODUCTION_DIFFERS" in (
        result["unknowns"]
    )


def test_null_case_digest_without_resource_marker_fails(
        installed_report: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    selected = deepcopy(installed_report)
    installed = selected["installed_native_case_replay"]
    membership = next(
        row for row in installed["memberships"]
        if row["obligation_id"] == "SIM:SIM-2.4"
    )
    unknown_case = next(
        case for case in membership["cases"]
        if case["case_kind"] == "UNKNOWN"
    )
    unknown_case["native_result_digest"] = None
    unknown_case["status"] = "UNKNOWN"
    _refresh_digest(membership, "native_replay_digest")
    _refresh_installed_tier_receipt(selected, 2)
    _refresh_digest(installed, "replay_digest")
    projected = next(
        row for row in selected["core_route_memberships"]
        if row["object_kind"] == membership["membership"]["object_kind"]
        and row["coordinate"] == membership["membership"]["coordinate"]
    )
    projected["installed_specimen_replay_digest"] = membership[
        "native_replay_digest"
    ]
    monkeypatch.setattr(
        recheck,
        "_reproduce_installed_replay",
        lambda *_args: {
            "tier_results": deepcopy(installed["tier_results"]),
            "memberships": deepcopy(installed["memberships"]),
            "tier_outages": {},
            "tier_failures": {},
        },
    )

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_STATUS_DIFFERS" in (
        result["invalidators"]
    )


def test_reproduction_outage_before_retained_contract_failure_is_unknown(
        installed_report: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    def refused(*_args, **_kwargs):
        raise recheck.self_polish_native_replay.NativeReplayError(
            "SYNTHETIC_RETAINED_TIER_ONE_CONTRACT_FAILURE"
        )

    monkeypatch.setattr(
        recheck.self_polish_native_replay,
        "build_installed_replay_manifest",
        refused,
    )
    retained = package_self_polish.assess_package_self_polish(
        COORDINATE, source_root=ROOT
    )
    clean = installed_report["installed_native_case_replay"]
    reproduction = {
        "tier_results": [deepcopy(next(
            row for row in clean["tier_results"] if row["tier"] == 2
        ))],
        "memberships": [
            deepcopy(row) for row in clean["memberships"]
            if row["membership"]["tier"] == 2
        ],
        "tier_outages": {1: False},
        "tier_failures": {},
    }
    monkeypatch.setattr(
        recheck,
        "_reproduce_installed_replay",
        lambda *_args: reproduction,
    )

    result = _recheck(retained)

    assert retained["installed_native_case_replay"]["status"] == "FAIL"
    assert retained["installed_native_case_replay"]["tier_results"] == []
    assert result["status"] == "UNKNOWN"
    assert result["invalidators"] == []
    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_UNAVAILABLE" in result["unknowns"]


def test_tier_one_reproduction_outage_ignores_later_clean_tier(
        installed_report: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    installed = installed_report["installed_native_case_replay"]
    reproduction = {
        "tier_results": [deepcopy(next(
            row for row in installed["tier_results"] if row["tier"] == 2
        ))],
        "memberships": [
            deepcopy(row) for row in installed["memberships"]
            if row["membership"]["tier"] == 2
        ],
        "tier_outages": {1: False},
        "tier_failures": {},
    }
    monkeypatch.setattr(
        recheck,
        "_reproduce_installed_replay",
        lambda *_args: reproduction,
    )

    result = _recheck(installed_report)

    assert result["status"] == "UNKNOWN"
    assert result["invalidators"] == []
    assert result["unknowns"] == [
        "PACKAGE_RECHECK_INSTALLED_REPLAY_UNAVAILABLE"
    ]


def test_matching_whole_tier_failure_outage_rechecks_unknown() -> None:
    native = recheck.self_polish_native_replay

    def failed_outage(*_args, **_kwargs):
        raise native.NativeReplayResourceError(failure_observed=True)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(native, "replay_native_obligations", failed_outage)
        retained = package_self_polish.assess_package_self_polish(
            COORDINATE, source_root=ROOT
        )
        result = _recheck(retained)
    installed = retained["installed_native_case_replay"]
    assert (
        installed["status"],
        installed["resource_status"],
        installed["tier_results"],
    ) == ("FAIL", "UNAVAILABLE", [])

    assert result["status"] == "UNKNOWN"
    assert result["rechecked_project_status"] is None
    assert result["invalidators"] == []
    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_UNAVAILABLE" in result["unknowns"]

    clean_result = _recheck(retained)
    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_REPRODUCTION_DIFFERS" in (
        clean_result["invalidators"]
    )


def test_rechecker_failure_outage_does_not_refute_retained_outage() -> None:
    native = recheck.self_polish_native_replay

    def outage(*_args, **_kwargs):
        raise native.NativeReplayResourceError(failure_observed=False)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(native, "replay_native_obligations", outage)
        retained = package_self_polish.assess_package_self_polish(
            COORDINATE, source_root=ROOT
        )
    assert retained["installed_native_case_replay"]["status"] == "UNKNOWN"

    def failure_outage(*_args, **_kwargs):
        raise native.NativeReplayResourceError(failure_observed=True)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(native, "replay_native_obligations", failure_outage)
        result = _recheck(retained)

    assert result["status"] == "UNKNOWN"
    assert result["invalidators"] == []
    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_UNAVAILABLE" in result["unknowns"]


def test_memberless_tier_two_outage_preserves_sim_invalidators() -> None:
    native = recheck.self_polish_native_replay
    original_digest = native._digest

    def tier_two_membership_outage(value):
        if (type(value) is dict and type(value.get("membership")) is dict
                and value["membership"].get("tier") == 2
                and "cases" in value):
            raise MemoryError("synthetic tier-two membership digest outage")
        return original_digest(value)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(native, "_digest", tier_two_membership_outage)
        retained = package_self_polish.assess_package_self_polish(
            COORDINATE, source_root=ROOT
        )
        result = _recheck(retained)

    tier_two = next(
        row for row in retained["installed_native_case_replay"]["tier_results"]
        if row["tier"] == 2
    )
    assert tier_two["status"] == "UNKNOWN"
    assert tier_two["membership_count"] == 0
    assert tier_two["invalidators"] == sorted([
        "NATIVE_REPLAY_MECHANISM_UNAVAILABLE",
        "SIM_RESOURCE_ACTUAL_CONSUMPTION_CORRESPONDENCE_NOT_ESTABLISHED",
        "SIM_RESOURCE_COLLECTOR_HONESTY_NOT_ESTABLISHED",
    ])
    assert result["status"] == "PASS"
    assert result["invalidators"] == []


def test_memberless_tier_two_refusal_preserves_sim_invalidators() -> None:
    native = recheck.self_polish_native_replay
    original_resolve = native._resolve_mechanism
    sim_mechanism = (
        "verifier.domains.contracts.sim_resource."
        "recheck_sim_resource_certificate"
    )

    def refuse_sim_negative(root, checking_mechanism, **kwargs):
        function, source_path, source_digest = original_resolve(
            root, checking_mechanism, **kwargs
        )
        if checking_mechanism != sim_mechanism:
            return function, source_path, source_digest
        calls = 0

        def wrapped(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ValueError("synthetic SIM negative refusal")
            return function(*args, **kwargs)

        return wrapped, source_path, source_digest

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(native, "_resolve_mechanism", refuse_sim_negative)
        retained = package_self_polish.assess_package_self_polish(
            COORDINATE, source_root=ROOT
        )
        result = _recheck(retained)

    tier_two = next(
        row for row in retained["installed_native_case_replay"]["tier_results"]
        if row["tier"] == 2
    )
    assert tier_two["status"] == "FAIL"
    assert tier_two["membership_count"] == 0
    assert tier_two["invalidators"] == sorted([
        "NATIVE_REPLAY_CERTIFICATE_REFUSED",
        "SIM_RESOURCE_ACTUAL_CONSUMPTION_CORRESPONDENCE_NOT_ESTABLISHED",
        "SIM_RESOURCE_COLLECTOR_HONESTY_NOT_ESTABLISHED",
    ])
    assert result["status"] == "PASS", result
    assert result["rechecked_project_status"] == "FAIL"
    assert result["invalidators"] == []


def test_outer_failure_tier_not_refuted_by_reproduced_tier_outage(
        monkeypatch: pytest.MonkeyPatch) -> None:
    native = recheck.self_polish_native_replay
    original = native.replay_native_obligations

    def observed_failure(*args, tier, **kwargs):
        if tier == 2:
            raise native.NativeReplayResourceError(failure_observed=True)
        return original(*args, tier=tier, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(native, "replay_native_obligations", observed_failure)
        retained = package_self_polish.assess_package_self_polish(
            COORDINATE, source_root=ROOT
        )
    installed = retained["installed_native_case_replay"]
    assert (
        installed["status"], installed["resource_status"]
    ) == ("FAIL", "UNAVAILABLE")
    [tier_one] = installed["tier_results"]
    assert tier_one["tier"] == 1 and tier_one["status"] != "FAIL"

    def tier_two_outage(
            manifest, root, *, tier, expected_source_coordinate_digest,
            **kwargs):
        if tier == 1:
            return original(
                manifest,
                root,
                tier=tier,
                expected_source_coordinate_digest=(
                    expected_source_coordinate_digest
                ),
                **kwargs,
            )
        return _memberless_receipt(
            manifest,
            2,
            expected_source_coordinate_digest,
            "UNKNOWN",
            ["NATIVE_REPLAY_MECHANISM_UNAVAILABLE"],
        )

    monkeypatch.setattr(
        native, "replay_native_obligations", tier_two_outage
    )
    result = _recheck(retained)

    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_REPRODUCTION_DIFFERS" not in (
        result["invalidators"]
    )
    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_REPRODUCTION_DIFFERS" in (
        result["unknowns"]
    )


def test_memberless_unknown_tier_cannot_carry_failure_invalidator() -> None:
    native = recheck.self_polish_native_replay
    original = native.replay_native_obligations

    def smuggled(
            manifest, root, *, tier, expected_source_coordinate_digest,
            **kwargs):
        if tier == 2:
            return original(
                manifest,
                root,
                tier=tier,
                expected_source_coordinate_digest=(
                    expected_source_coordinate_digest
                ),
                **kwargs,
            )
        return _memberless_receipt(
            manifest,
            1,
            expected_source_coordinate_digest,
            "UNKNOWN",
            [
                "NATIVE_REPLAY_CERTIFICATE_REFUSED",
                "NATIVE_REPLAY_MECHANISM_UNAVAILABLE",
            ],
        )

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(native, "replay_native_obligations", smuggled)
        retained = package_self_polish.assess_package_self_polish(
            COORDINATE, source_root=ROOT
        )
    assert retained["installed_native_case_replay"]["status"] == "UNKNOWN"

    result = _recheck(retained)

    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_STATUS_DIFFERS" in (
        result["invalidators"]
    )


def test_unknown_tier_cannot_drop_registry_member_under_reproduction_outage(
        monkeypatch: pytest.MonkeyPatch) -> None:
    native = recheck.self_polish_native_replay
    original = native.replay_native_obligations

    def drop_member(*args, tier, **kwargs):
        receipt = original(*args, tier=tier, **kwargs)
        if tier == 2:
            receipt["memberships"].remove(next(
                row for row in receipt["memberships"]
                if row["obligation_id"] != "SIM:SIM-2.4"
            ))
            receipt["membership_count"] -= 1
            receipt["case_count"] -= 3
            receipt["receipt_digest"] = core_obligation_union.value_digest({
                key: value for key, value in receipt.items()
                if key != "receipt_digest"
            })
        return receipt

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(native, "replay_native_obligations", drop_member)
        retained = package_self_polish.assess_package_self_polish(
            COORDINATE, source_root=ROOT
        )
    installed = retained["installed_native_case_replay"]
    assert next(
        row for row in installed["tier_results"] if row["tier"] == 2
    )["status"] == "UNKNOWN"
    monkeypatch.setattr(
        recheck,
        "_reproduce_installed_replay",
        lambda *_args: {
            "tier_results": [
                deepcopy(row) for row in installed["tier_results"]
                if row["tier"] == 1
            ],
            "memberships": [
                deepcopy(row) for row in installed["memberships"]
                if row["membership"]["tier"] == 1
            ],
            "tier_outages": {2: False},
            "tier_failures": {},
        },
    )

    result = _recheck(retained)

    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_STATUS_DIFFERS" in (
        result["invalidators"]
    )


def test_sim_boundary_invalidators_are_bound_to_positive_unknown(
        installed_report: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    selected = deepcopy(installed_report)
    installed = selected["installed_native_case_replay"]
    tier_row = next(
        row for row in installed["tier_results"] if row["tier"] == 2
    )
    assert "SIM_RESOURCE_COLLECTOR_HONESTY_NOT_ESTABLISHED" in (
        tier_row["invalidators"]
    )
    tier_row["invalidators"] = [
        code for code in tier_row["invalidators"]
        if not code.startswith("SIM_RESOURCE_")
    ]
    _refresh_installed_tier_receipt(selected, 2)
    _refresh_digest(installed, "replay_digest")
    monkeypatch.setattr(
        recheck,
        "_reproduce_installed_replay",
        lambda *_args: {
            "tier_results": [
                deepcopy(row) for row in installed["tier_results"]
                if row["tier"] == 1
            ],
            "memberships": [
                deepcopy(row) for row in installed["memberships"]
                if row["membership"]["tier"] == 1
            ],
            "tier_outages": {2: False},
            "tier_failures": {},
        },
    )

    result = _recheck(selected)

    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_STATUS_DIFFERS" in (
        result["invalidators"]
    )


@pytest.mark.parametrize(
    ("exception", "result_field"),
    [
        (OSError("synthetic tier-one outage"), "tier_outages"),
        (
            recheck.self_polish_native_replay.NativeReplayError(
                "SYNTHETIC_TIER_ONE_CONTRACT_FAILURE"
            ),
            "tier_failures",
        ),
    ],
)
def test_installed_reproduction_stops_at_first_unobservable_tier(
        monkeypatch: pytest.MonkeyPatch, exception: Exception,
        result_field: str) -> None:
    observed_tiers: list[int] = []

    def unavailable(tier, *_args, **_kwargs):
        observed_tiers.append(tier)
        raise exception

    monkeypatch.setattr(
        recheck.self_polish_native_replay,
        "build_installed_replay_manifest",
        unavailable,
    )

    result = recheck._reproduce_installed_replay("sha256:" + "1" * 64)

    assert observed_tiers == [1]
    assert set(result[result_field]) == {1}
    assert result["tier_results"] == []
    assert result["memberships"] == []


def test_reproduced_late_request_digest_outage_preserves_observed_failure(
        monkeypatch: pytest.MonkeyPatch) -> None:
    objects = package_self_polish.build_package_graph(COORDINATE)
    source_digest = core_obligation_union.value_digest(COORDINATE)
    selected_request: dict[str, object] = {}
    original_request = recheck.object_facets.object_facets_request
    original_recheck = recheck.object_facets.recheck_object_facets_certificate
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
        recheck.object_facets, "object_facets_request", capture_request
    )
    monkeypatch.setattr(
        recheck.object_facets,
        "recheck_object_facets_certificate",
        refute_negative_case,
    )
    monkeypatch.setattr(
        recheck.core_obligation_union, "value_digest", fail_after_cases
    )

    replay = recheck._reproduce_native_results(objects, source_digest)

    assert replay[0]["status"] == "FAIL"
    assert replay[0]["resource_status"] == "UNAVAILABLE"


def test_outage_in_one_tier_does_not_hide_other_tier_mismatch(
        installed_report: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    installed = installed_report["installed_native_case_replay"]
    reproduced = {
        "tier_results": [deepcopy(next(
            row for row in installed["tier_results"] if row["tier"] == 1
        ))],
        "memberships": [deepcopy(row) for row in installed["memberships"]
                        if row["membership"]["tier"] == 1],
        "tier_outages": {2: False},
        "tier_failures": {},
    }
    reproduced["memberships"][0]["status"] = "FAIL"
    monkeypatch.setattr(
        recheck,
        "_reproduce_installed_replay",
        lambda *_args: reproduced,
    )

    result = _recheck(installed_report)

    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_REPRODUCTION_DIFFERS" in (
        result["invalidators"]
    )
    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_UNAVAILABLE" in result["unknowns"]


def test_installed_replay_is_independently_rerun(
        installed_report: dict) -> None:
    selected = deepcopy(installed_report)
    installed = selected["installed_native_case_replay"]
    membership = installed["memberships"][0]
    membership["cases"][0]["native_result_digest"] = "sha256:" + "0" * 64
    _refresh_digest(membership, "native_replay_digest")
    tier = membership["membership"]["tier"]
    _refresh_installed_tier_receipt(selected, tier)
    _refresh_digest(installed, "replay_digest")
    projected = next(
        row for row in selected["core_route_memberships"]
        if row["object_kind"] == membership["membership"]["object_kind"]
        and row["coordinate"] == membership["membership"]["coordinate"]
    )
    projected["installed_specimen_replay_digest"] = membership[
        "native_replay_digest"
    ]

    result = _recheck(selected)

    assert result["status"] == "FAIL", result
    assert "PACKAGE_RECHECK_INSTALLED_REPLAY_REPRODUCTION_DIFFERS" in (
        result["invalidators"]
    )


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (
            lambda value: value.update(
                claim_boundary="Package polished; release authorized."
            ),
            "PACKAGE_RECHECK_PINNED_CONSTANTS_DIFFER",
        ),
        (
            lambda value: value["core_route_memberships"][0].update(
                normative_full_family_closure="ESTABLISHED"
            ),
            "PACKAGE_RECHECK_CORE_MEMBERSHIP_BINDING_DIFFERS",
        ),
        (
            lambda value: value["corrigibility_extension_cells"][0].update(
                qualification="ESTABLISHED"
            ),
            "PACKAGE_RECHECK_CORRIGIBILITY_CELL_STATUS_DIFFERS",
        ),
    ],
)
def test_semantic_overclaims_fail_even_with_fresh_report_digest(
        report: dict, mutation, code: str) -> None:
    selected = deepcopy(report)
    mutation(selected)
    if code == "PACKAGE_RECHECK_CORRIGIBILITY_CELL_STATUS_DIFFERS":
        selected["corrigibility_extension_selection"]["binding_digest"] = (
            core_obligation_union.value_digest({
                "cells": selected["corrigibility_extension_cells"],
                "research_evidence_digest": selected[
                    "corrigibility_research_evidence"
                ]["evidence_digest"],
            })
        )

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert code in result["invalidators"]


def test_current_mechanism_drift_is_unknown_not_package_failure(
        report: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        recheck, "_current_package_mechanism_digest",
        lambda: "sha256:" + "0" * 64,
    )

    result = _recheck(report)

    assert result["status"] == "UNKNOWN"
    assert result["rechecked_project_status"] is None
    assert result["invalidators"] == []
    assert result["unknowns"] == ["PACKAGE_RECHECK_STALE_MECHANISM"]
    Draft202012Validator(SCHEMA).validate(result)


def test_stale_mechanism_skips_current_inventory_comparison(
        report: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        recheck, "_current_package_mechanism_digest",
        lambda: "sha256:" + "0" * 64,
    )
    monkeypatch.setattr(
        recheck.core_tier_progression,
        "installed_core_route_inventory",
        lambda: (_ for _ in ()).throw(AssertionError("must not compare stale")),
    )

    result = _recheck(report)

    assert result["status"] == "UNKNOWN"
    assert result["invalidators"] == []
    assert result["unknowns"] == ["PACKAGE_RECHECK_STALE_MECHANISM"]


def test_stale_mechanism_does_not_soften_retained_contradiction(
        report: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    selected = deepcopy(report)
    selected["polished"] = True
    monkeypatch.setattr(
        recheck, "_current_package_mechanism_digest",
        lambda: "sha256:" + "0" * 64,
    )

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert result["rechecked_project_status"] is None
    assert "PACKAGE_RECHECK_STABLE_PROJECT_ENVELOPE_DIFFERS" in result[
        "invalidators"
    ]
    assert "PACKAGE_RECHECK_STALE_MECHANISM" in result["unknowns"]


def test_stale_mechanism_preserves_nested_retained_failure(
        report: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    selected = deepcopy(report)
    selected["core_route_memberships"][0]["status"] = "FAIL"
    monkeypatch.setattr(
        recheck, "_current_package_mechanism_digest",
        lambda: "sha256:" + "0" * 64,
    )

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert result["rechecked_project_status"] is None
    assert "PACKAGE_RECHECK_STABLE_PROJECT_ENVELOPE_DIFFERS" in result[
        "invalidators"
    ]


def test_recheck_mechanism_unavailable_returns_bounded_unknown(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        recheck, "mechanism_digest",
        lambda: (_ for _ in ()).throw(OSError("unavailable")),
    )

    result = recheck.unavailable_package_self_polish_recheck()

    assert result["status"] == "UNKNOWN"
    assert result["mechanism_digest"] is None
    assert result["unknowns"] == [
        "PACKAGE_RECHECK_INPUT_UNAVAILABLE",
        "PACKAGE_RECHECK_MECHANISM_UNAVAILABLE",
    ]
    Draft202012Validator(SCHEMA).validate(result)


def test_null_reported_mechanism_does_not_disable_fallback_contract() -> None:
    report = package_self_polish.package_assessment_contradiction_report(
        numeric_tier1_report={"status": "UNKNOWN"},
        source_coordinate=COORDINATE,
        blocker="PACKAGE_CORE_ROUTE_INVENTORY_CONTRADICTION",
    )
    report["mechanism_digest"] = None
    report["status"] = report["project_gate_status"] = "UNKNOWN"

    result = _recheck(report)

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_PROJECT_STATUS_DIFFERS" in result["invalidators"]
    assert "PACKAGE_RECHECK_REPORTED_MECHANISM_UNAVAILABLE" in result[
        "unknowns"
    ]


def test_capacity_fallback_cannot_embed_unverified_numeric_pass() -> None:
    attempted = package_self_polish.assess_package_self_polish(COORDINATE)
    report = package_self_polish.package_report_capacity_exhausted_report(
        attempted
    )
    report["self_verifier_tier1"].update(
        status="PASS",
        retention_status="RETAINED",
        report_digest="sha256:" + "a" * 64,
        source_binding_status="PASS",
        represented_tiers=[1],
    )

    result = _recheck(report)

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_FALLBACK_CONSTANTS_DIFFER" in result[
        "invalidators"
    ]


def test_rejected_capacity_fallback_rechecks_without_numeric_relabel() -> None:
    other = deepcopy(COORDINATE)
    other["source_head"] = "f" * 40
    attempted = package_self_polish.assess_package_self_polish(
        COORDINATE,
        self_verifier_tier1_report={
            "status": "FAIL",
            "source_coordinate": other,
            "report_digest": "sha256:" + "9" * 64,
        },
    )
    report = package_self_polish.package_report_capacity_exhausted_report(
        attempted
    )

    result = _recheck(report)

    assert result["status"] == "PASS"
    assert result["rechecked_project_status"] == "FAIL"
    assert result["invalidators"] == []
    assert result["unknowns"] == []


def test_namespaced_numeric_fallback_blocker_rechecks() -> None:
    report = package_self_polish.package_assessment_unavailable_report(
        numeric_tier1_report={"status": "UNKNOWN"},
        prior_blockers=(
            "NUMERIC_TIER1_BLOCKER:SELF_POLISH_TIER_MECHANISM_UNAVAILABLE",
        ),
    )

    result = _recheck(report)

    assert result["status"] == "PASS"
    assert result["rechecked_project_status"] == "UNKNOWN"


def test_namespaced_numeric_failure_suffix_does_not_promote_package_fail() -> None:
    report = package_self_polish.package_assessment_unavailable_report(
        numeric_tier1_report={"status": "UNKNOWN"},
        prior_blockers=("NUMERIC_TIER1_BLOCKER:SYNTHETIC_DIFFERS",),
    )

    result = _recheck(report)

    assert report["status"] == "UNKNOWN"
    assert result["status"] == "PASS"
    assert result["rechecked_project_status"] == "UNKNOWN"


def test_graph_report_rejects_unjustified_numeric_failure_blocker(
        report: dict) -> None:
    selected = deepcopy(report)
    selected["blockers"] = sorted(set(selected["blockers"]) | {
        "NUMERIC_SELF_VERIFIER_TIER1_FAILED",
    })
    selected["status"] = selected["project_gate_status"] = "FAIL"

    result = _recheck(selected)

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_BLOCKER_SET_DIFFERS" in result["invalidators"]


def test_strict_json_memory_exhaustion_is_bounded_unknown(
        report: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        recheck,
        "strict_json_loads",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(MemoryError()),
    )

    result = _recheck(report)

    assert result["status"] == "UNKNOWN"
    assert result["invalidators"] == []
    assert result["unknowns"] == [
        "PACKAGE_RECHECK_REPORT_VALIDATION_UNAVAILABLE"
    ]


def test_legitimate_incomplete_installed_replay_unknown_rechecks(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        package_self_polish,
        "_source_recapture_binding",
        lambda *_: {
            "status": "UNKNOWN",
            "matches_selected_source": "UNKNOWN",
            "observed_source_coordinate": None,
            "observed_source_evidence": None,
            "claim_boundary": "The later source recapture was unavailable.",
        },
    )

    def unavailable_installed(_root, source_digest):
        body = {
            "schema_version": "verifier-package-installed-native-case-replay-1",
            "status": "UNKNOWN",
            "resource_status": "UNAVAILABLE",
            "source_coordinate_digest": source_digest,
            "tier_results": [],
            "memberships": [],
            "membership_count": 0,
            "case_count": 0,
            "claim_boundary": (
                "PASS establishes installed specimen discrimination for all 82 "
                "registered tier-1 and tier-2 routes. It does not establish that "
                "the selected package graph is a passing instance of those routes."
            ),
        }
        _refresh_digest(body, "replay_digest")
        return body

    monkeypatch.setattr(
        package_self_polish,
        "_installed_native_case_replay",
        unavailable_installed,
    )
    report = package_self_polish.assess_package_self_polish(
        COORDINATE, source_root=tmp_path
    )

    result = _recheck(report)

    assert report["installed_native_case_replay"]["status"] == "UNKNOWN"
    assert result["status"] == "UNKNOWN"
    assert result["rechecked_project_status"] is None
    assert result["invalidators"] == []
    assert result["unknowns"] == [
        "PACKAGE_RECHECK_INSTALLED_REPLAY_REPRODUCTION_DIFFERS"
    ]


@pytest.mark.parametrize(
    ("variant", "numeric_status"),
    [
        ("source-unavailable", "PASS"),
        ("source-unavailable", "UNKNOWN"),
        ("source-unavailable", "FAIL"),
        ("assessment-unavailable", "PASS"),
        ("assessment-unavailable", "UNKNOWN"),
        ("assessment-unavailable", "FAIL"),
        ("contradiction", "UNKNOWN"),
        ("capacity", "UNKNOWN"),
        ("capacity", "FAIL"),
    ],
)
def test_bounded_fallback_reports_recheck_without_promotion(
        variant: str, numeric_status: str) -> None:
    numeric = {"status": numeric_status, "source_coordinate": COORDINATE}
    if variant == "source-unavailable":
        report = package_self_polish.unavailable_package_report(
            numeric_tier1_report=numeric
        )
    elif variant == "assessment-unavailable":
        report = package_self_polish.package_assessment_unavailable_report(
            numeric_tier1_report=numeric
        )
    elif variant == "contradiction":
        report = package_self_polish.package_assessment_contradiction_report(
            numeric_tier1_report=numeric,
            source_coordinate=COORDINATE,
            blocker="PACKAGE_CORE_ROUTE_INVENTORY_CONTRADICTION",
        )
    else:
        attempted = package_self_polish.assess_package_self_polish(COORDINATE)
        if numeric_status == "FAIL":
            attempted["status"] = attempted["project_gate_status"] = "FAIL"
            attempted["blockers"].append("PACKAGE_NATIVE_FACETS_REPLAY_FAILED")
        report = package_self_polish.package_report_capacity_exhausted_report(
            attempted
        )
    result = _recheck(report)

    assert result["status"] == "PASS"
    assert result["rechecked_project_status"] == report["status"]

    if report["status"] == "FAIL":
        report["status"] = report["project_gate_status"] = "UNKNOWN"
        demoted = _recheck(report)
        assert demoted["status"] == "FAIL"
        assert "PACKAGE_RECHECK_PROJECT_STATUS_DIFFERS" in demoted["invalidators"]


def test_unclassified_empty_fallback_rechecks_as_not_selected() -> None:
    report = package_self_polish.package_assessment_unavailable_report(
        numeric_tier1_report={}
    )

    result = _recheck(report)

    assert report["self_verifier_tier1"]["retention_status"] == "NOT_SELECTED"
    assert result["status"] == "PASS"
    assert result["rechecked_project_status"] == "UNKNOWN"


def test_classified_retained_unknown_fallback_is_schema_and_recheck_valid() -> None:
    report = package_self_polish.package_assessment_unavailable_report(
        numeric_tier1_report={"status": "UNKNOWN"},
        classified_self_verifier={
            "status": "UNKNOWN",
            "retention_status": "RETAINED",
            "report_digest": "sha256:" + "7" * 64,
            "source_binding_status": "NOT_ESTABLISHED",
            "subject": None,
            "represented_tiers": [],
            "claim_boundary": recheck._SELF_VERIFIER_CLAIM_BOUNDARY,
        },
        prior_blockers=("SELF_VERIFIER_TIER1_NOT_PASS",),
    )

    Draft202012Validator(json.loads((
        ROOT / "src/verifier/schemas/"
        "verifier-package-graph-self-polish-assessment-1.schema.json"
    ).read_text(encoding="utf-8"))).validate(report)
    result = _recheck(report)

    assert result["status"] == "PASS"
    assert result["rechecked_project_status"] == "UNKNOWN"


def test_fallback_without_a_producer_blocker_fails() -> None:
    report = package_self_polish.unavailable_package_report(
        numeric_tier1_report={"status": "UNKNOWN"}
    )
    report["blockers"] = []

    result = _recheck(report)

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_BLOCKER_SET_DIFFERS" in result["invalidators"]


def test_fallback_cannot_claim_polish_or_release() -> None:
    report = package_self_polish.unavailable_package_report(
        numeric_tier1_report={"status": "UNKNOWN"}
    )
    report["polished"] = True
    report["release_authorized"] = True

    result = _recheck(report)

    assert result["status"] == "FAIL"
    assert "PACKAGE_RECHECK_PROJECT_STATUS_DIFFERS" in result["invalidators"]


def test_graph_resource_exhaustion_is_unknown_not_contradiction(
        report: dict) -> None:
    selected = deepcopy(report)
    graph = selected["package_graph"]
    graph["status"] = "UNKNOWN"
    graph["collection_digest"] = None
    graph["canonical_round_trip_status"] = "UNKNOWN"
    graph["reason"] = "canonical graph record round trip was unavailable"
    graph["object_count"] = 0
    for row in selected["tier_zero_representation_cells"]:
        row["structural_representation_status"] = "UNKNOWN"
        row["status"] = "UNKNOWN"
    selected["blockers"] = sorted(set(selected["blockers"]) | {
        "PACKAGE_GRAPH_COMPOSITION_NOT_PASS",
        "TIER_ZERO_REPRESENTATION_NOT_PASS",
    })

    result = _recheck(selected)

    assert result["status"] == "UNKNOWN"
    assert result["invalidators"] == []
    assert result["unknowns"] == [
        "PACKAGE_RECHECK_GRAPH_RECONSTRUCTION_UNAVAILABLE"
    ]


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":1,"schema_version":2}',
        b'{"schema_version":NaN}',
        b"[]",
    ],
)
def test_non_strict_or_non_record_json_fails(raw: bytes) -> None:
    result = recheck.recheck_package_self_polish_report(
        raw,
        expected_report_digest="sha256:" + "0" * 64,
        expected_report_bytes_digest=core_obligation_union.bytes_digest(raw),
    )

    assert result["status"] == "FAIL"
    assert result["invalidators"]


def test_transport_capacity_exhaustion_remains_unknown() -> None:
    raw = b" " * (recheck.MAX_PACKAGE_REPORT_BYTES + 1)
    result = recheck.recheck_package_self_polish_report(
        raw,
        expected_report_digest="sha256:" + "0" * 64,
        expected_report_bytes_digest=core_obligation_union.bytes_digest(raw),
    )

    assert result["status"] == "UNKNOWN"
    assert result["invalidators"] == []
    assert result["unknowns"] == ["PACKAGE_RECHECK_REPORT_CAPACITY_EXHAUSTED"]
    Draft202012Validator(SCHEMA).validate(result)


def test_rechecker_does_not_import_the_report_producer() -> None:
    source = (
        ROOT / "src/verifier/runtime/package_self_polish_recheck.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }

    assert "package_self_polish" not in imported
    assert "verifier.runtime.package_self_polish" not in imported
    assert "verifier.runtime.package_self_polish" not in imported_modules


def test_public_cli_exposes_recheck_without_promoting_project(
        report: dict, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    raw, digest = _selection(report)
    selected = tmp_path / "package-report.json"
    selected.write_bytes(raw)

    code = public_cli.main([
        "polish", "recheck-package", str(selected),
        "--report-digest", digest,
        "--report-bytes-digest", core_obligation_union.bytes_digest(raw),
        "--json",
    ])

    output = json.loads(capsys.readouterr().out)
    assert code == 0
    assert output["status"] == "PASS"
    assert output["rechecked_project_status"] == "UNKNOWN"


def test_public_cli_returns_bounded_unknown_for_missing_report(
        tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    missing = tmp_path / "missing.json"

    code = public_cli.main([
        "polish", "recheck-package", str(missing),
        "--report-digest", "sha256:" + "0" * 64,
        "--report-bytes-digest", "sha256:" + "0" * 64,
        "--json",
    ])

    output = json.loads(capsys.readouterr().out)
    assert code == 2
    assert output["status"] == "UNKNOWN"
    assert output["unknowns"] == ["PACKAGE_RECHECK_INPUT_UNAVAILABLE"]


def test_public_cli_checks_capacity_before_selected_digests(
        tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    selected = tmp_path / "oversized-package-report.json"
    selected.write_bytes(b" " * (recheck.MAX_PACKAGE_REPORT_BYTES + 1))

    code = public_cli.main([
        "polish", "recheck-package", str(selected),
        "--report-digest", "sha256:" + "0" * 64,
        "--report-bytes-digest", "sha256:" + "0" * 64,
        "--json",
    ])

    output = json.loads(capsys.readouterr().out)
    assert code == 2
    assert output["status"] == "UNKNOWN"
    assert output["invalidators"] == []
    assert output["unknowns"] == ["PACKAGE_RECHECK_REPORT_CAPACITY_EXHAUSTED"]


def test_public_cli_returns_fail_for_tampered_selected_bytes(
        report: dict, tmp_path: Path,
        capsys: pytest.CaptureFixture[str]) -> None:
    raw, digest = _selection(report)
    tampered = raw + b"\n"
    selected = tmp_path / "tampered-package-report.json"
    selected.write_bytes(tampered)

    code = public_cli.main([
        "polish", "recheck-package", str(selected),
        "--report-digest", digest,
        "--report-bytes-digest", core_obligation_union.bytes_digest(raw),
        "--json",
    ])

    output = json.loads(capsys.readouterr().out)
    assert code == 1
    assert output["status"] == "FAIL"
    assert "PACKAGE_RECHECK_REPORT_BYTES_DIGEST_DIFFERS" in output["invalidators"]
