"""Independent cross-coordinate commitments for published package PASS reports."""
from __future__ import annotations

import pytest

from test_package_polish_cumulative_schema import _pass_report, _reseal
from verifier.runtime import package_polish_schema_validation as validation
from verifier.runtime.core_obligation_union import value_digest


ALTERNATE_DIGEST = "sha256:" + "b" * 64


def _coordinate_bound_pass_report() -> dict:
    report = _pass_report(3)
    source_digest = value_digest(report["source_coordinate"])
    report["source_coordinate_digest"] = source_digest
    for tier in ("1", "2"):
        report["native_diagnostics"]["prerequisites"][tier][
            "source_coordinate_digest"
        ] = source_digest
    return _reseal(report)


def _mutate(report: dict, case: str) -> None:
    if case == "top_source_coordinate":
        report["source_coordinate"]["source_head"] = "3" * 40
    elif case == "native_source_coordinate":
        report["native_diagnostics"]["prerequisites"]["1"][
            "source_coordinate_digest"
        ] = ALTERNATE_DIGEST
    elif case == "native_manifest":
        report["native_diagnostics"]["prerequisites"]["0"][
            "manifest_digest"
        ] = ALTERNATE_DIGEST
    elif case == "collection":
        report["package_graph"]["collection_digest"] = ALTERNATE_DIGEST
    elif case == "native_report":
        report["verifier_execution"][
            "native_diagnostic_report_digest"
        ] = ALTERNATE_DIGEST
    else:  # pragma: no cover - test authoring guard
        raise AssertionError(case)


CASES = (
    (
        "top_source_coordinate",
        "PACKAGE_PASS_SOURCE_COORDINATE_DIGEST_DIFFERS",
    ),
    (
        "native_source_coordinate",
        "PACKAGE_PASS_NATIVE_SOURCE_COORDINATE_DIFFERS",
    ),
    (
        "native_manifest",
        "PACKAGE_PASS_MANIFEST_COORDINATE_DIFFERS",
    ),
    (
        "collection",
        "PACKAGE_PASS_COLLECTION_COORDINATE_DIFFERS",
    ),
    (
        "native_report",
        "PACKAGE_PASS_NATIVE_DIAGNOSTIC_DIGEST_DIFFERS",
    ),
)


def test_exact_package_pass_coordinate_control_validates() -> None:
    result = validation.validate_package_polish_report(
        _coordinate_bound_pass_report()
    )

    assert result.valid, result.errors


@pytest.mark.parametrize(("case", "issue_code"), CASES)
def test_resealed_one_field_package_pass_substitution_is_rejected(
    case: str,
    issue_code: str,
) -> None:
    report = _coordinate_bound_pass_report()
    _mutate(report, case)

    result = validation.validate_package_polish_report(_reseal(report))

    assert not result.valid
    coordinate_errors = [
        error
        for error in result.errors
        if ": passCoordinateCommitment: " in error
    ]
    assert len(coordinate_errors) == 1, result.errors
    assert all(
        error.startswith("/")
        and ": passCoordinateCommitment: " + issue_code + ":" in error
        for error in coordinate_errors
    ), result.errors


@pytest.mark.parametrize("status", ("UNKNOWN", "FAIL"))
@pytest.mark.parametrize(("case", "_issue_code"), CASES)
def test_nonpass_report_does_not_claim_or_require_pass_coordinate_commitments(
    status: str,
    case: str,
    _issue_code: str,
) -> None:
    report = _coordinate_bound_pass_report()
    report.update(
        status=status,
        blockers=["SYNTHETIC_NONPASS_BOUNDARY"],
        findings=[],
        whole_package_conformance="NOT_ESTABLISHED",
        polished=False,
    )
    _mutate(report, case)

    result = validation.validate_package_polish_report(_reseal(report))

    assert result.valid, result.errors
