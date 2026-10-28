"""Refresh receipts remain bound to the exact package assessment snapshot."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from test_package_polish_cumulative_schema import _pass_report, _reseal
from verifier.runtime import core_obligation_union as binding
from verifier.runtime import package_manifest_migration
from verifier.runtime import package_manifest_refresh
from verifier.runtime import package_polish
from verifier.runtime import package_polish_schema_validation as validation
from verifier.runtime import self_polish_tiers


DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64
DIGEST_E = "sha256:" + "e" * 64
REFRESH_BINDING_SCHEMA = "verifier-package-polish-refresh-binding-1"
REFRESH_REFERENCE_SCHEMA = "verifier-package-manifest-refresh-reference-1"


def _receipt(report: dict, *, status: str = "REMIGRATED") -> dict:
    manifest_digest = report["manifest"]["digest"]
    common = {
        "schema_version": package_manifest_refresh.RECEIPT_SCHEMA,
        "status": status,
        "before_digest": DIGEST_B,
        "after_digest": manifest_digest,
        "backup_digest": DIGEST_B if status == "REMIGRATED" else None,
        "source_census_digest": (
            DIGEST_C if status != "NOT_APPLICABLE" else None
        ),
        "migration_mechanism_digest": DIGEST_D,
        "refresh_is_admission": False,
        "refresh_is_polish": False,
    }
    if status == "REMIGRATED":
        separator = chr(92)
        common.update(
            backup_locator=(
                "C:" + separator + "private" + separator + "recovery"
                + separator + "before.vstd"
            ),
            prepared_receipt_digest=DIGEST_E,
            directory_durability="NOT_ESTABLISHED",
        )
    else:
        common["before_digest"] = manifest_digest
    return common


def _reference(receipt: dict) -> dict:
    body = {
        "schema_version": REFRESH_REFERENCE_SCHEMA,
        "receipt_schema_version": receipt["schema_version"],
        "status": receipt["status"],
        "before_digest": receipt["before_digest"],
        "after_digest": receipt["after_digest"],
        "backup_digest": receipt["backup_digest"],
        "source_census_digest": receipt["source_census_digest"],
        "migration_mechanism_digest": receipt["migration_mechanism_digest"],
        "prepared_receipt_digest": receipt.get("prepared_receipt_digest"),
        "directory_durability": receipt.get("directory_durability"),
        "refresh_is_admission": False,
        "refresh_is_polish": False,
    }
    return {**body, "reference_digest": binding.value_digest(body)}


def _bound_report(*, disposition: str = "REMIGRATED") -> dict:
    report = _pass_report(3)
    receipt = _receipt(report, status=disposition)
    report["manifest_refresh"] = {
        "schema_version": REFRESH_BINDING_SCHEMA,
        "status": "PASS",
        "disposition": disposition,
        "receipt_reference": _reference(receipt),
        "assessed_manifest_digest": report["manifest"]["digest"],
        "assessed_source_census_digest": receipt["source_census_digest"],
        "assessed_source_coordinate_digest": report[
            "source_coordinate_digest"
        ],
        "failure_code": None,
        "claim_boundary": (
            "The path-free receipt reference is matched to the package "
            "assessment snapshot; refresh is neither admission nor polish."
        ),
    }
    return _reseal(report)


def _no_refresh_report() -> dict:
    report = _pass_report(3)
    report["manifest_refresh"] = {
        "schema_version": REFRESH_BINDING_SCHEMA,
        "status": "PASS",
        "disposition": "NOT_REQUESTED",
        "receipt_reference": None,
        "assessed_manifest_digest": report["manifest"]["digest"],
        "assessed_source_census_digest": None,
        "assessed_source_coordinate_digest": report[
            "source_coordinate_digest"
        ],
        "failure_code": None,
        "claim_boundary": (
            "No refresh receipt was supplied; this binds the assessed manifest "
            "and source coordinate without claiming refresh execution."
        ),
    }
    return _reseal(report)


def _refresh_errors(report: dict) -> tuple[str, ...]:
    return tuple(
        error
        for error in validation.validate_package_polish_report(report).errors
        if ": refreshBindingCommitment: " in error
    )


def _producer_report(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict:
    report = _no_refresh_report()
    raw = b"selected manifest bytes\n"
    manifest_digest = binding.bytes_digest(raw)
    report["manifest"]["digest"] = manifest_digest
    report["package_graph"]["manifest_digest"] = manifest_digest
    report["verifier_execution"]["manifest_digest"] = manifest_digest
    report["native_diagnostics"]["prerequisites"]["0"][
        "manifest_digest"
    ] = manifest_digest
    report = _reseal(report)
    (root / "objects.vstd").write_bytes(raw)
    monkeypatch.setattr(
        package_polish.self_polish_statics,
        "_capture_coordinate",
        lambda _root: deepcopy(report["source_coordinate"]),
    )
    monkeypatch.setattr(
        package_manifest_migration,
        "source_refresh_coordinate",
        lambda _root: (DIGEST_C, {}),
    )
    return report


def test_no_refresh_path_is_explicit_and_does_not_fabricate_a_receipt() -> None:
    report = _no_refresh_report()

    result = validation.validate_package_polish_report(report)

    assert result.valid, result.errors
    assert report["manifest_refresh"]["disposition"] == "NOT_REQUESTED"
    assert report["manifest_refresh"]["receipt_reference"] is None


def test_schema_v2_report_cannot_omit_refresh_disposition() -> None:
    report = _bound_report()
    del report["manifest_refresh"]

    result = validation.validate_package_polish_report(_reseal(report))

    assert not result.valid
    assert any(
        "PACKAGE_REFRESH_BINDING_MISSING" in error
        for error in result.errors
    ), result.errors


@pytest.mark.parametrize("disposition", ("CURRENT", "REMIGRATED"))
def test_valid_refresh_reference_is_path_free_and_validates(
    disposition: str,
) -> None:
    report = _bound_report(disposition=disposition)

    result = validation.validate_package_polish_report(report)

    assert result.valid, result.errors
    reference = report["manifest_refresh"]["receipt_reference"]
    assert "backup_locator" not in reference
    assert "C:" + chr(92) + "private" not in repr(reference)


@pytest.mark.parametrize(
    ("case", "issue_code"),
    (
        ("after_digest", "PACKAGE_REFRESH_AFTER_DIGEST_DIFFERS"),
        ("source_census", "PACKAGE_REFRESH_SOURCE_CENSUS_DIFFERS"),
        (
            "source_coordinate",
            "PACKAGE_REFRESH_SOURCE_COORDINATE_DIFFERS",
        ),
        ("manifest", "PACKAGE_REFRESH_MANIFEST_DIGEST_DIFFERS"),
        ("reference_digest", "PACKAGE_REFRESH_REFERENCE_DIGEST_DIFFERS"),
    ),
)
def test_independently_resealed_refresh_substitution_is_rejected(
    case: str,
    issue_code: str,
) -> None:
    report = _bound_report()
    selected = report["manifest_refresh"]
    reference = selected["receipt_reference"]
    if case == "after_digest":
        reference["after_digest"] = DIGEST_B
    elif case == "source_census":
        reference["source_census_digest"] = DIGEST_B
    elif case == "source_coordinate":
        selected["assessed_source_coordinate_digest"] = DIGEST_B
    elif case == "manifest":
        selected["assessed_manifest_digest"] = DIGEST_B
    elif case == "reference_digest":
        reference["reference_digest"] = DIGEST_B
    else:  # pragma: no cover - test authoring guard
        raise AssertionError(case)
    if case in {"after_digest", "source_census"}:
        reference["reference_digest"] = binding.value_digest(
            {
                key: value
                for key, value in reference.items()
                if key != "reference_digest"
            }
        )

    result = validation.validate_package_polish_report(_reseal(report))

    assert not result.valid
    errors = _refresh_errors(_reseal(report))
    assert len(errors) == 1, errors
    assert (": " + issue_code + ":") in errors[0]


@pytest.mark.parametrize("disposition", ("CURRENT", "REMIGRATED"))
def test_report_binder_attaches_exact_refresh_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    disposition: str,
) -> None:
    report = _producer_report(tmp_path, monkeypatch)

    rebound = package_polish.bind_manifest_refresh_report(
        report, tmp_path, _receipt(report, status=disposition)
    )

    selected = rebound["manifest_refresh"]
    assert selected["status"] == "PASS"
    assert selected["disposition"] == disposition
    assert selected["assessed_manifest_digest"] == report["manifest"]["digest"]
    assert selected["assessed_source_census_digest"] == DIGEST_C
    assert "backup_locator" not in selected["receipt_reference"]
    result = validation.validate_package_polish_report(rebound)
    assert result.valid, result.errors


def test_report_binder_never_reseals_an_altered_source_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _producer_report(tmp_path, monkeypatch)
    retained_digest = report["report_digest"]
    report["claim_boundary"] += " altered"

    rebound = package_polish.bind_manifest_refresh_report(
        report, tmp_path, _receipt(report)
    )

    assert rebound["report_digest"] == retained_digest
    assert rebound["manifest_refresh"]["disposition"] == "NOT_REQUESTED"
    result = validation.validate_package_polish_report(rebound)
    assert not result.valid
    assert any("report body" in error for error in result.errors)


def test_report_binder_rejects_mismatched_receipt_after_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _producer_report(tmp_path, monkeypatch)
    receipt = _receipt(report)
    receipt["after_digest"] = DIGEST_E

    rebound = package_polish.bind_manifest_refresh_report(
        report, tmp_path, receipt
    )

    assert rebound["status"] == "FAIL"
    assert "PACKAGE_REFRESH_AFTER_DIGEST_DIFFERS" in rebound["blockers"]
    assert rebound["manifest_refresh"]["status"] == "FAIL"
    assert validation.validate_package_polish_report(rebound).valid


def _refresh_required_outcome() -> dict:
    return {
        "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
        "status": "REFRESH_REQUIRED",
        "before_digest": DIGEST_B,
        "after_digest": DIGEST_C,
        "backup_digest": None,
        "source_census_digest": DIGEST_D,
        "migration_mechanism_digest": DIGEST_E,
        "blockers": ["MANIFEST_REFRESH_REQUIRED_READ_ONLY"],
        "refresh_is_admission": False,
        "refresh_is_polish": False,
    }


def _record_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[tuple[str, dict]], list[str]]:
    """Stand in for the refresh controller and forbid any stale assessor."""

    calls: list[tuple[str, dict]] = []
    assessed: list[str] = []

    def preflight(root: str, **kwargs: object) -> dict:
        calls.append((root, dict(kwargs)))
        return _refresh_required_outcome()

    monkeypatch.setattr(package_manifest_refresh, "ensure_current_manifest", preflight)
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *args, **kwargs: assessed.append("package") or pytest.fail(
            "stale package assessor must not run before refresh"
        ),
    )
    return calls, assessed


@pytest.mark.parametrize("tier", [0, 1, 2, 3])
def test_each_root_numeric_polish_runs_refresh_preflight_before_assessment(
    tier: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls, assessed = _record_preflight(monkeypatch)

    code = self_polish_tiers.handle_self_polish_tier_argv(
        [str(tier), "--source-root", str(tmp_path), "--json"]
    )

    assert code == 2
    assert calls == [(str(tmp_path), {
        "mode": "auto", "journal_root": None, "review_policy": "record",
    })]
    assert assessed == []
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == self_polish_tiers.POLISH_REFRESH_BLOCKED_SCHEMA


@pytest.mark.parametrize("tier", [0, 1, 2, 3])
def test_check_mode_and_journal_selection_reach_the_preflight_unchanged(
    tier: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls, assessed = _record_preflight(monkeypatch)
    journal = tmp_path / "external-journal"

    code = self_polish_tiers.handle_self_polish_tier_argv([
        str(tier), "--source-root", str(tmp_path), "--json",
        "--manifest-refresh", "check",
        "--manifest-refresh-journal", str(journal),
    ])

    assert code == 2
    assert calls == [(str(tmp_path), {
        "mode": "check", "journal_root": str(journal), "review_policy": "record",
    })]
    assert assessed == []
    report = json.loads(capsys.readouterr().out)
    assert report["polished"] is False


@pytest.mark.parametrize("tier", [1, 2, 3])
def test_refresh_block_retains_every_cumulative_tier_as_not_run(
    tier: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _record_preflight(monkeypatch)

    self_polish_tiers.handle_self_polish_tier_argv(
        [str(tier), "--source-root", str(tmp_path), "--json"]
    )

    report = json.loads(capsys.readouterr().out)
    assert report["assessment_execution_status"] == "NOT_RUN"
    assert [row["tier"] for row in report["tier_results"]] == list(range(1, tier + 1))
    assert {row["execution_status"] for row in report["tier_results"]} == {"NOT_RUN"}


def test_polish_surface_has_no_separate_remigrate_command() -> None:
    parser = self_polish_tiers.build_self_polish_tier_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["remigrate"])
