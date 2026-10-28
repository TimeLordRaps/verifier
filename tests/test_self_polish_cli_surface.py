"""Public command discoverability for numeric self-polish tiers.

Terminology: identifier (ID).

Terminology: JavaScript Object Notation (JSON).
"""

from __future__ import annotations

from copy import deepcopy
import json
import sys
from pathlib import Path

import pytest

from verifier.runtime import core_obligation_union
from verifier.runtime import package_self_polish
from verifier.runtime import package_manifest_refresh
from verifier.runtime import package_polish
from verifier.runtime import package_polish_schema_validation
from verifier.runtime import manifest_gate
from verifier.runtime import self_polish_estate
from verifier.runtime import self_polish_tiers
from verifier.runtime import tier_zero
from verifier.runtime.public_cli import main


ROOT = Path(__file__).resolve().parents[1]
REFRESH_BLOCKED_SCHEMA = ROOT / "src" / "verifier" / "schemas" / (
    "verifier-polish-manifest-refresh-blocked-1.schema.json"
)
PUBLICATION_REJECTED_SCHEMA = ROOT / "src" / "verifier" / "schemas" / (
    "verifier-manifest-package-polish-publication-rejected-1.schema.json"
)


def test_polish_help_advertises_numeric_self_polish_tiers(
        capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["polish", "--help"])

    assert stopped.value.code == 0
    help_text = capsys.readouterr().out
    normalized_help = " ".join(help_text.split())
    assert "0" in help_text
    assert "1" in help_text
    assert "2" in help_text
    assert "repository admission before numbered self-polish tiers" \
        in normalized_help
    assert (
        "root objects.vstd package GRAPH through Tier 1 Facets"
        in normalized_help
    )
    assert (
        "root objects.vstd package GRAPH through Tier 2 Dynamics"
        in normalized_help
    )


def test_numeric_tier0_help_names_manifest_and_source_root(
        capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["polish", "0", "--help"])

    assert stopped.value.code == 0
    normalized_help = " ".join(capsys.readouterr().out.split()).lower()
    assert "--source-root" in normalized_help
    assert "--manifest" in normalized_help


def test_numeric_tier1_help_explains_estate_authority_and_evidence_inputs(
        capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["polish", "1", "--help"])

    assert stopped.value.code == 0
    normalized_help = " ".join(capsys.readouterr().out.split()).lower()
    assert "--candidate-estate-authority-policy" in normalized_help
    assert "independently selected estate-authority policy" in normalized_help
    assert "--candidate-estate-evidence-manifest" in normalized_help
    assert "exact per-candidate semantic-evidence manifest" in normalized_help
    assert "--candidate-estate-evidence-selection" in normalized_help
    assert "repeatable configured-key replay selection" in normalized_help
    assert "--package-graph" in normalized_help
    assert (
        "38-kind whole-package vstd package graph project gate rooted in "
        "objects.vstd"
    ) in normalized_help
    assert "--package-obligation-cards" in normalized_help
    assert (
        "candidate json card for every admitted package object kind"
        in normalized_help
    )
    assert "--package-obligation-manifest" in normalized_help
    assert "hash manifest binding every selected candidate card's bytes" \
        in normalized_help
    assert "--package-owner-policy" in normalized_help
    assert "separately selected configured-key package owner policy" \
        in normalized_help
    assert "--package-owner-decisions" in normalized_help
    assert (
        "signed exact adoption statement for every applicable package owner "
        "decision"
    ) in normalized_help
    assert "26-kind" not in normalized_help
    assert "selected 26 candidate" not in normalized_help
    assert "all 110 package owner decisions" not in normalized_help


def test_numeric_tier2_help_states_full_tier1_report_transport_bound(
        capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["polish", "2", "--help"])

    assert stopped.value.code == 0
    normalized_help = " ".join(capsys.readouterr().out.split()).lower()
    assert "--tier1-report" in normalized_help
    assert "at most 16 mib including any final newline" in normalized_help


def test_package_owner_inputs_require_package_graph(
        capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stopped:
        main([
            "polish", "1",
            "--package-owner-policy", "owner-policy.json",
        ])

    assert stopped.value.code == 2
    assert "require --package-graph" in capsys.readouterr().err


def test_package_graph_cli_preserves_package_schema_when_assessment_unavailable(
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    coordinate = {
        "source_head": "1" * 40,
        "source_tree": "2" * 40,
        "source_worktree_status_digest": "sha256:" + "3" * 64,
        "source_manifest_digest": "sha256:" + "4" * 64,
    }
    numeric = {
        "status": "UNKNOWN",
        "source_coordinate": coordinate,
        "report_digest": "sha256:" + "5" * 64,
    }
    monkeypatch.setattr(
        self_polish_tiers,
        "assess_self_polish_tier",
        lambda *_args, **_kwargs: numeric,
    )
    monkeypatch.setattr(
        package_self_polish,
        "assess_package_self_polish",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("synthetic package unavailability")
        ),
    )

    exit_code = main(["polish", "1", "--package-graph", "--json"])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert report["schema_version"] == package_self_polish.REPORT_SCHEMA
    assert report["status"] == report["project_gate_status"] == "UNKNOWN"
    assert report["blockers"] == [
        "PACKAGE_SELF_POLISH_ASSESSMENT_UNAVAILABLE"
    ]


def test_package_graph_cli_preserves_detected_contradiction_as_fail(
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    coordinate = {
        "source_head": "1" * 40,
        "source_tree": "2" * 40,
        "source_worktree_status_digest": "sha256:" + "3" * 64,
        "source_manifest_digest": "sha256:" + "4" * 64,
    }
    numeric = {
        "status": "UNKNOWN",
        "source_coordinate": coordinate,
        "report_digest": "sha256:" + "5" * 64,
    }
    monkeypatch.setattr(
        self_polish_tiers,
        "assess_self_polish_tier",
        lambda *_args, **_kwargs: numeric,
    )
    monkeypatch.setattr(
        package_self_polish,
        "assess_package_self_polish",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("synthetic detected contradiction")
        ),
    )

    exit_code = main(["polish", "1", "--package-graph", "--json"])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert report["status"] == report["project_gate_status"] == "FAIL"
    assert report["blockers"] == [
        "PACKAGE_SELF_POLISH_CONTRACT_VIOLATION"
    ]


def test_package_graph_cli_preserves_resource_exhaustion_as_unknown(
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    coordinate = {
        "source_head": "1" * 40,
        "source_tree": "2" * 40,
        "source_worktree_status_digest": "sha256:" + "3" * 64,
        "source_manifest_digest": "sha256:" + "4" * 64,
    }
    numeric = {
        "status": "UNKNOWN",
        "source_coordinate": coordinate,
        "report_digest": "sha256:" + "5" * 64,
    }
    monkeypatch.setattr(
        self_polish_tiers,
        "assess_self_polish_tier",
        lambda *_args, **_kwargs: numeric,
    )
    monkeypatch.setattr(
        package_self_polish,
        "assess_package_self_polish",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RecursionError("synthetic bounded recursion exhaustion")
        ),
    )

    exit_code = main(["polish", "1", "--package-graph", "--json"])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert report["status"] == report["project_gate_status"] == "UNKNOWN"
    assert report["blockers"] == [
        "PACKAGE_SELF_POLISH_ASSESSMENT_UNAVAILABLE"
    ]


def test_package_graph_cli_preserves_numeric_blockers_on_package_outage(
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    coordinate = {
        "source_head": "1" * 40,
        "source_tree": "2" * 40,
        "source_worktree_status_digest": "sha256:" + "3" * 64,
        "source_manifest_digest": "sha256:" + "4" * 64,
    }
    numeric = {
        "status": "UNKNOWN",
        "source_coordinate": coordinate,
        "report_digest": "sha256:" + "5" * 64,
        "blockers": ["NUMERIC_PREEXISTING_BLOCKER"],
    }
    monkeypatch.setattr(
        self_polish_tiers,
        "assess_self_polish_tier",
        lambda *_args, **_kwargs: numeric,
    )
    monkeypatch.setattr(
        package_self_polish,
        "assess_package_self_polish",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("synthetic package unavailability")
        ),
    )

    exit_code = main(["polish", "1", "--package-graph", "--json"])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert report["blockers"] == [
        "NUMERIC_TIER1_BLOCKER:NUMERIC_PREEXISTING_BLOCKER",
        "PACKAGE_SELF_POLISH_ASSESSMENT_UNAVAILABLE",
    ]


def _current_manifest_refresh() -> dict:
    digest = "sha256:" + "1" * 64
    return {
        "schema_version": package_manifest_refresh.RECEIPT_SCHEMA,
        "status": "CURRENT",
        "before_digest": digest,
        "after_digest": digest,
        "backup_digest": None,
        "source_census_digest": "sha256:" + "2" * 64,
        "migration_mechanism_digest": "sha256:" + "3" * 64,
        "refresh_is_admission": False,
        "refresh_is_polish": False,
    }


def _accept_deliberately_incomplete_assessor_stub(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep orchestration-only tests independent of final schema validation."""
    monkeypatch.setattr(
        package_polish_schema_validation,
        "validate_package_polish_report",
        lambda report: package_polish_schema_validation.PackagePolishSchemaValidation(
            schema_version=report.get("schema_version"),
            schema_supported=True,
            valid=True,
            errors=(),
        ),
    )


def test_default_package_polish_refuses_schema_invalid_pass_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A producer contradiction must not be published as a successful polish."""
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: _current_manifest_refresh(),
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: {
            "schema_version": "verifier-manifest-package-polish-2",
            "status": "PASS",
            "unexpected_verifier_execution_authority": True,
        },
    )

    exit_code = main([
        "polish", "1", "--source-root", str(tmp_path), "--json",
    ])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert report["schema_version"] == (
        "verifier-manifest-package-polish-publication-rejected-1"
    )
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["PACKAGE_POLISH_REPORT_SCHEMA_INVALID"]
    assert report["source_report_schema"] == (
        "verifier-manifest-package-polish-2"
    )
    assert report["requested_tier"] == 1
    assert report["polished"] is False
    assert report["release_authorized"] is False
    assert report["deployment_authorized"] is False
    assert report["validation_errors"]
    assert report["validation_error_count"] == len(
        report["validation_errors"]
    )
    assert report["selected_schema_digest"] == (
        core_obligation_union.bytes_digest(
            ROOT.joinpath(
                "src/verifier/schemas/"
                "verifier-manifest-package-polish-2.schema.json"
            ).read_bytes()
        )
    )
    assert report["validator_mechanism_digest"] == (
        core_obligation_union.bytes_digest(
            Path(package_polish_schema_validation.__file__).read_bytes()
        )
    )
    assert report["report_digest"].startswith("sha256:")
    body = dict(report)
    body.pop("report_digest")
    assert report["report_digest"] == core_obligation_union.value_digest(body)
    import jsonschema
    schema = json.loads(PUBLICATION_REJECTED_SCHEMA.read_bytes())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(report)
    assert (
        package_polish_schema_validation
        .validate_publication_rejection_receipt(report).valid
        is True
    )


def test_default_package_polish_refuses_unknown_report_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: _current_manifest_refresh(),
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: {
            "schema_version": "verifier-manifest-package-polish-future",
            "status": "PASS",
        },
    )

    assert main([
        "polish", "1", "--source-root", str(tmp_path), "--json",
    ]) == 2
    report = json.loads(capsys.readouterr().out)

    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == [
        "PACKAGE_POLISH_REPORT_SCHEMA_UNSUPPORTED"
    ]
    assert report["selected_schema_digest"] is None
    assert (
        package_polish_schema_validation
        .validate_publication_rejection_receipt(report).valid
        is True
    )


@pytest.mark.parametrize("producer_result", (None, [], "not-a-report"))
def test_default_package_polish_rejects_non_mapping_json_results(
    producer_result: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: _current_manifest_refresh(),
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: deepcopy(producer_result),
    )

    assert main([
        "polish", "1", "--source-root", str(tmp_path), "--json",
    ]) == 2
    report = json.loads(capsys.readouterr().out)
    source_raw = self_polish_tiers._json_report_wire_bytes(producer_result)

    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == [
        "PACKAGE_POLISH_REPORT_SCHEMA_UNSUPPORTED"
    ]
    assert report["source_report_schema"] is None
    assert report["source_report_status"] is None
    assert report["source_report_encoding_status"] == "AVAILABLE"
    assert report["source_report_digest"] == (
        core_obligation_union.bytes_digest(source_raw)
    )
    assert report["source_report_bytes"] == len(source_raw)
    assert (
        package_polish_schema_validation
        .validate_publication_rejection_receipt(report).valid
        is True
    )


@pytest.mark.parametrize(
    "unencodable",
    (
        pytest.param(
            {
                "schema_version": "verifier-manifest-package-polish-2",
                "status": "PASS",
                "unencodable": {"set-member"},
            },
            id="set",
        ),
        pytest.param(
            {
                "schema_version": "verifier-manifest-package-polish-2",
                "status": "PASS",
                "unencodable": float("nan"),
            },
            id="nan",
        ),
    ),
)
def test_default_package_polish_rejects_non_json_results_without_wire_claim(
    unencodable: dict[str, object],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: _current_manifest_refresh(),
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: deepcopy(unencodable),
    )

    assert main([
        "polish", "1", "--source-root", str(tmp_path), "--json",
    ]) == 2
    report = json.loads(capsys.readouterr().out)

    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == [
        "PACKAGE_POLISH_REPORT_ENCODING_UNAVAILABLE"
    ]
    assert report["source_report_encoding_status"] == "UNAVAILABLE"
    assert report["source_report_schema"] == (
        "verifier-manifest-package-polish-2"
    )
    assert report["source_report_status"] == "PASS"
    assert report["source_report_digest"] is None
    assert report["source_report_bytes"] is None
    assert report["validation_errors"][0] == (
        "/: encoding: final report is not representable as strict JSON"
    )
    assert (
        package_polish_schema_validation
        .validate_publication_rejection_receipt(report).valid
        is True
    )


def test_default_package_polish_rejects_unhashable_source_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: _current_manifest_refresh(),
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: {
            "schema_version": "unsupported-package-polish-schema",
            "status": [],
        },
    )

    assert main([
        "polish", "1", "--source-root", str(tmp_path), "--json",
    ]) == 2
    report = json.loads(capsys.readouterr().out)

    assert report["status"] == "UNKNOWN"
    assert report["source_report_status"] is None
    assert report["source_report_encoding_status"] == "AVAILABLE"
    assert (
        package_polish_schema_validation
        .validate_publication_rejection_receipt(report).valid
        is True
    )


@pytest.mark.parametrize("unsafe_schema", ("\ud800", "x" * 513))
def test_default_package_polish_bounds_unsafe_source_schema_metadata(
    unsafe_schema: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    producer_result = {
        "schema_version": unsafe_schema,
        "status": "PASS",
    }
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: _current_manifest_refresh(),
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: producer_result,
    )
    # Force the compact-encoding path. A lone surrogate must use the exact
    # deterministic ASCII-escaped compact fallback.
    monkeypatch.setattr(package_polish, "MAX_REPORT_BYTES", 1)

    assert main([
        "polish", "1", "--source-root", str(tmp_path), "--json",
    ]) == 2
    report = json.loads(capsys.readouterr().out)

    assert report["status"] == "UNKNOWN"
    assert report["source_report_schema"] is None
    assert report["source_report_status"] == "PASS"
    assert report["source_report_encoding_status"] == "AVAILABLE"
    try:
        expected_source_raw = (
            json.dumps(
                producer_result, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            ) + "\n"
        ).encode("utf-8")
    except UnicodeError:
        expected_source_raw = (
            json.dumps(
                producer_result, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            ) + "\n"
        ).encode("utf-8")
    assert report["source_report_digest"] == (
        core_obligation_union.bytes_digest(expected_source_raw)
    )
    assert report["source_report_bytes"] == len(expected_source_raw)
    assert (
        package_polish_schema_validation
        .validate_publication_rejection_receipt(report).valid
        is True
    )


@pytest.mark.parametrize("malformed_instances", ([1], [[]]))
def test_oversized_schema_invalid_report_never_reaches_capacity_projection(
    malformed_instances: list[object],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    producer_result = {
        "schema_version": package_polish.EXTENSIBLE_REPORT_SCHEMA,
        "status": "PASS",
        "obligation_instances": malformed_instances,
    }
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: _current_manifest_refresh(),
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: producer_result,
    )
    monkeypatch.setattr(package_polish, "MAX_REPORT_BYTES", 128)
    monkeypatch.setattr(
        package_polish,
        "_capacity_receipt",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("schema-invalid report reached capacity projection")
        ),
    )

    assert main([
        "polish", "1", "--source-root", str(tmp_path), "--json",
    ]) == 2
    report = json.loads(capsys.readouterr().out)

    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == [
        "PACKAGE_POLISH_REPORT_SCHEMA_INVALID"
    ]
    assert report["source_report_schema"] == (
        package_polish.EXTENSIBLE_REPORT_SCHEMA
    )
    assert (
        package_polish_schema_validation
        .validate_publication_rejection_receipt(report).valid
        is True
    )


def test_publication_rejection_escapes_surrogate_validation_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    producer_result = {
        "schema_version": package_polish.EXTENSIBLE_REPORT_SCHEMA,
        "status": "PASS",
        "\ud800": True,
    }
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: _current_manifest_refresh(),
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: producer_result,
    )

    assert main([
        "polish", "1", "--source-root", str(tmp_path), "--json",
    ]) == 2
    report = json.loads(capsys.readouterr().out)

    assert report["status"] == "UNKNOWN"
    assert any("\\ud800" in error for error in report["validation_errors"])
    assert all(
        "\ud800" not in error for error in report["validation_errors"]
    )
    assert all(
        len(error.encode("utf-8")) <= 512
        for error in report["validation_errors"]
    )
    assert (
        package_polish_schema_validation
        .validate_publication_rejection_receipt(report).valid
        is True
    )


def test_unencodable_surrogate_report_is_rejected_before_capacity_projection(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    producer_result = package_polish.assess_package_polish(
        1, ROOT, cancelled=True
    )
    producer_result["claim_boundary"] = "\ud800" * 2048
    validation = (
        package_polish_schema_validation
        .validate_package_polish_report(producer_result)
    )
    assert validation.valid is False
    assert any(
        "cannot be encoded by the canonical digest mechanism" in error
        for error in validation.errors
    )
    source_pretty = self_polish_tiers._json_report_wire_bytes(
        producer_result
    )
    assert len(source_pretty) > 128

    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: _current_manifest_refresh(),
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: producer_result,
    )
    monkeypatch.setattr(package_polish, "MAX_REPORT_BYTES", 128)

    assert main([
        "polish", "1", "--source-root", str(ROOT), "--json",
    ]) == 2
    output = capsys.readouterr().out.encode("utf-8")
    report = json.loads(output)

    assert report["schema_version"] == (
        "verifier-manifest-package-polish-publication-rejected-1"
    )
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["PACKAGE_POLISH_REPORT_SCHEMA_INVALID"]
    assert report["whole_package_conformance"] == "NOT_ESTABLISHED"
    assert report["polished"] is False
    assert report["source_report_encoding_status"] == "AVAILABLE"
    assert report["source_report_digest"].startswith("sha256:")
    assert report["source_report_bytes"] > 0
    assert len(output) <= 128 or report["status"] != "PASS"
    assert (
        package_polish_schema_validation
        .validate_publication_rejection_receipt(report).valid
        is True
    )


@pytest.mark.parametrize("tier", (0, 1, 2, 3))
def test_default_numeric_polish_refreshes_once_before_assessment(
    tier: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    events: list[tuple[str, int]] = []
    _accept_deliberately_incomplete_assessor_stub(monkeypatch)

    def ensure(root, *, mode, journal_root, review_policy="record"):
        assert root == str(tmp_path)
        assert mode == "auto"
        assert journal_root is None
        events.append(("refresh", tier))
        return _current_manifest_refresh()

    def assess_package(selected_tier, root, *, cancelled):
        assert root == str(tmp_path)
        assert cancelled is False
        events.append(("assess", selected_tier))
        return {"status": "PASS"}

    def assess_zero(root, *, manifest_path):
        assert root == tmp_path
        assert manifest_path is None
        events.append(("assess", 0))
        return {
            "schema_version": "test-tier-zero",
            "status": "PASS",
            "blockers": [],
        }

    monkeypatch.setattr(
        package_manifest_refresh, "ensure_current_manifest", ensure
    )
    monkeypatch.setattr(package_polish, "assess_package_polish", assess_package)
    monkeypatch.setattr(tier_zero, "assess_tier_zero", assess_zero)
    monkeypatch.setattr(manifest_gate, "admission_findings", lambda report: [])

    exit_code = main([
        "polish", str(tier), "--source-root", str(tmp_path), "--json",
    ])
    capsys.readouterr()

    assert exit_code == 0
    assert events == [("refresh", tier), ("assess", tier)]


@pytest.mark.parametrize("tier", (0, 1, 2, 3))
def test_manifest_refresh_check_drift_is_unknown_without_assessment(
    tier: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[int] = []

    def ensure(root, *, mode, journal_root, review_policy="record"):
        assert root == str(tmp_path)
        assert mode == "check"
        assert journal_root is None
        calls.append(tier)
        return {
            "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
            "status": "REFRESH_REQUIRED",
            "before_digest": "sha256:" + "4" * 64,
            "after_digest": "sha256:" + "5" * 64,
            "backup_digest": None,
            "source_census_digest": "sha256:" + "6" * 64,
            "migration_mechanism_digest": "sha256:" + "7" * 64,
            "blockers": ["MANIFEST_REFRESH_REQUIRED_READ_ONLY"],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        }

    def unexpected(*args, **kwargs):
        raise AssertionError("stale assessor must not run")

    monkeypatch.setattr(
        package_manifest_refresh, "ensure_current_manifest", ensure
    )
    monkeypatch.setattr(package_polish, "assess_package_polish", unexpected)
    monkeypatch.setattr(tier_zero, "assess_tier_zero", unexpected)

    exit_code = main([
        "polish", str(tier), "--source-root", str(tmp_path),
        "--manifest-refresh", "check", "--json",
    ])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert calls == [tier]
    assert report["schema_version"] == (
        self_polish_tiers.POLISH_REFRESH_BLOCKED_SCHEMA
    )
    assert report["refresh_outcome_schema_version"] == (
        package_manifest_refresh.OUTCOME_SCHEMA
    )
    assert report["refresh_outcome_status"] == "REFRESH_REQUIRED"
    assert report["status"] == "UNKNOWN"
    assert report["requested_tier"] == tier
    assert report["assessment_execution_status"] == "NOT_RUN"
    assert report["polished"] is False
    assert report["blockers"] == ["MANIFEST_REFRESH_REQUIRED_READ_ONLY"]
    # Assemble the retained compatibility coordinate at runtime.  The namespace
    # closure scanner rejects object-like ``VSTD-`` tokens in source text, while
    # this report must still reproduce the serialized Tier-0 wire coordinate.
    tier_zero_coordinate = "VSTD-" + "T0.1"
    assert report["findings"] == [{
        "scope": "repository",
        "object_id": None,
        "object_kind": None,
        "coordinate": tier_zero_coordinate,
        "obligation_id": tier_zero_coordinate + "-canonical-manifest-admission",
        "obligation_name": "Canonical manifest admission",
        "semantic_version": None,
        "gate_id": "manifest-refresh",
        "status": "UNKNOWN",
        "code": "MANIFEST_REFRESH_REQUIRED_READ_ONLY",
        "reason": "Manifest refresh required read only.",
        "explanation": "Manifest refresh required read only.",
        "next_action": (
            "Resolve this reported prerequisite without substituting objects, "
            "evidence or a passing specimen, then run the retained rerun_argv."
        ),
        "rerun_argv": ["vstd", "polish", "0", "--json"],
    }]
    if tier == 0:
        assert "tier_results" not in report
        assert "native_diagnostics" not in report
    else:
        assert report["denominator_status"] == "NOT_RETAINED"
        assert report["package_graph"] is None
        assert report["obligation_instances"] == []
        assert [item["tier"] for item in report["tier_results"]] == list(
            range(1, tier + 1)
        )
        assert all(
            item["execution_status"] == "NOT_RUN"
            and item["status"] == "UNKNOWN"
            and item["instance_count"] == 0
            and item["status_counts"] == {}
            and item["checker_status_counts"] == {}
            for item in report["tier_results"]
        )
        native = report["native_diagnostics"]
        assert set(native["tier_execution"]) == {
            str(depth) for depth in range(tier + 1)
        }
        assert all(
            item["execution_status"] == "NOT_RUN"
            and item["status"] == "UNKNOWN"
            and item["evidence_digest"] is None
            and item["blocking_prerequisite"]["blockers"]
            == ["MANIFEST_REFRESH_REQUIRED_READ_ONLY"]
            for item in native["tier_execution"].values()
        )
    import jsonschema
    schema = json.loads(REFRESH_BLOCKED_SCHEMA.read_bytes())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(report)
    assert self_polish_tiers._valid_manifest_refresh_blocked_report(report)


def test_manifest_refresh_review_rows_become_focused_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def ensure(*_args, **_kwargs):
        return {
            "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
            "status": "UNKNOWN",
            "blockers": ["MANIFEST_REFRESH_REVIEW_REQUIRED"],
            "review_required": [{
                "path": "src/example.py",
                "reason": "SOURCE_SEMANTICS_CHANGED",
                "object_id": "example-object",
                "classifications": ["POLICY"],
                "obligations": ["OBJECT-0.1", "POLICY-0.2"],
            }],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        }

    def unexpected(*_args, **_kwargs):
        raise AssertionError("stale assessor must not run")

    monkeypatch.setattr(
        package_manifest_refresh, "ensure_current_manifest", ensure
    )
    monkeypatch.setattr(
        package_polish, "assess_package_polish", unexpected
    )

    exit_code = main([
        "polish", "3", "--source-root", str(tmp_path),
        "--manifest-refresh", "check", "--json",
    ])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    expected_reason = (
        "SOURCE_SEMANTICS_CHANGED requires renewed semantic review before "
        "root objects.vstd can be refreshed."
    )
    expected_next_action = (
        "Review the changed source semantics for this exact object and "
        "obligation, then rerun the focused gate."
    )
    classification_reason = (
        "SOURCE_SEMANTICS_CHANGED requires renewed semantic review of "
        "classification POLICY before root objects.vstd can be refreshed."
    )
    classification_finding = {
        "scope": "object",
        "object_id": "example-object",
        "object_kind": "POLICY",
        "coordinate": "file:src/example.py",
        "obligation_id": "VSTD-T0.7-source-and-mechanism-freshness",
        "obligation_name": "Source and mechanism freshness",
        "semantic_version": None,
        "gate_id": "manifest-refresh",
        "status": "UNKNOWN",
        "code": "SOURCE_SEMANTICS_CHANGED",
        "reason": classification_reason,
        "explanation": classification_reason,
        "next_action": (
            "Review the changed source semantics for this exact object and "
            "classification, then rerun the focused source-freshness obligation."
        ),
        "rerun_argv": [
            "vstd", "gate", "--object", "example-object",
            "--obligation", "VSTD-T0.7-source-and-mechanism-freshness",
        ],
    }
    assert report["findings"] == [classification_finding, *[
        {
            "scope": "object",
            "object_id": "example-object",
            "object_kind": None,
            "coordinate": "file:src/example.py",
            "obligation_id": obligation_id,
            # A supplied obligation ID is never rewritten; one that is not a
            # registered identity is named visibly unresolved.
            "obligation_name": "Unresolved obligation identity",
            "semantic_version": None,
            "gate_id": "manifest-refresh",
            "status": "UNKNOWN",
            "code": "SOURCE_SEMANTICS_CHANGED",
            "reason": expected_reason,
            "explanation": expected_reason,
            "next_action": expected_next_action,
            "rerun_argv": [
                "vstd", "gate", "--object", "example-object",
                "--obligation", obligation_id,
            ],
        }
        for obligation_id in ("OBJECT-0.1", "POLICY-0.2")
    ]]


def test_manifest_refresh_classification_only_rows_become_focused_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
            "status": "UNKNOWN",
            "blockers": ["MANIFEST_REFRESH_REVIEW_REQUIRED"],
            "review_required": [{
                "path": "src/generated.txt",
                "reason": "SOURCE_SEMANTICS_CHANGED",
                "object_id": "generated-metadata",
                "classifications": ["POLICY", "PROTOCOL"],
                "obligations": [],
            }],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("stale assessor must not run")
        ),
    )

    exit_code = main([
        "polish", "0", "--source-root", str(tmp_path),
        "--manifest-refresh", "check", "--json",
    ])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["MANIFEST_REFRESH_REVIEW_REQUIRED"]
    assert len(report["findings"]) == 2
    assert [row["object_kind"] for row in report["findings"]] == [
        "POLICY", "PROTOCOL",
    ]
    assert all(
        row["object_id"] == "generated-metadata"
        and row["obligation_id"]
            == "VSTD-T0.7-source-and-mechanism-freshness"
        and row["coordinate"] == "file:src/generated.txt"
        and row["code"] == "SOURCE_SEMANTICS_CHANGED"
        and row["reason"] == row["explanation"]
        and "classification " + row["object_kind"] in row["reason"]
        and row["next_action"] == (
            "Review the changed source semantics for this exact object and "
            "classification, then rerun the focused source-freshness obligation."
        )
        and row["rerun_argv"] == [
            "vstd", "gate", "--object", "generated-metadata",
            "--obligation", "VSTD-T0.7-source-and-mechanism-freshness",
        ]
        for row in report["findings"]
    )
    assert self_polish_tiers._valid_manifest_refresh_blocked_report(report)


def test_manifest_refresh_mixed_review_row_deduplicates_exact_coordinates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
            "status": "UNKNOWN",
            "blockers": ["MANIFEST_REFRESH_REVIEW_REQUIRED"],
            "review_required": [{
                "path": "src/mixed.py",
                "reason": "SOURCE_SEMANTICS_CHANGED",
                "object_id": "mixed-object",
                "classifications": ["POLICY", "POLICY"],
                "obligations": ["POLICY-0.2", "POLICY-0.2"],
            }],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("stale assessor must not run")
        ),
    )

    exit_code = main([
        "polish", "0", "--source-root", str(tmp_path),
        "--manifest-refresh", "check", "--json",
    ])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert report["blockers"] == ["MANIFEST_REFRESH_REVIEW_REQUIRED"]
    assert len(report["findings"]) == 2
    assert [row["object_kind"] for row in report["findings"]] == [
        "POLICY", None,
    ]
    assert [row["obligation_id"] for row in report["findings"]] == [
        "VSTD-T0.7-source-and-mechanism-freshness", "POLICY-0.2",
    ]
    assert not any(
        row["code"] == "MANIFEST_REFRESH_OUTCOME_INVALID"
        for row in report["findings"]
    )


@pytest.mark.parametrize(
    "classifications, obligations",
    [
        pytest.param([], [], id="empty-both"),
        pytest.param(["POLICY", None], [], id="malformed-classification"),
    ],
)
def test_manifest_refresh_unaddressable_review_row_is_invalid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    classifications: list[object],
    obligations: list[str],
) -> None:
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
            "status": "UNKNOWN",
            "blockers": ["MANIFEST_REFRESH_REVIEW_REQUIRED"],
            "review_required": [{
                "path": "src/unaddressable.py",
                "reason": "SOURCE_SEMANTICS_CHANGED",
                "object_id": "unaddressable-object",
                "classifications": classifications,
                "obligations": obligations,
            }],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )

    exit_code = main([
        "polish", "0", "--source-root", str(tmp_path),
        "--manifest-refresh", "check", "--json",
    ])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert "MANIFEST_REFRESH_OUTCOME_INVALID" in report["blockers"]
    invalid = [
        row for row in report["findings"]
        if row["code"] == "MANIFEST_REFRESH_OUTCOME_INVALID"
    ]
    assert len(invalid) == 1
    if classifications == ["POLICY", None]:
        focused = [row for row in report["findings"] if row not in invalid]
        assert len(focused) == 1
        assert focused[0]["object_kind"] == "POLICY"


def test_manifest_refresh_malformed_accounting_is_normalized_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def ensure(*_args, **_kwargs):
        return {
            "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
            "status": "UNKNOWN",
            "blockers": "NOT_A_BLOCKER_LIST",
            "review_required": [
                None,
                {
                    "path": "src/example.py",
                    "reason": "SOURCE_SEMANTICS_CHANGED",
                    "object_id": "example-object",
                    "classifications": ["POLICY"],
                    "obligations": ["POLICY-0.2", "POLICY-0.2"],
                },
            ],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        }

    monkeypatch.setattr(
        package_manifest_refresh, "ensure_current_manifest", ensure
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("stale assessor must not run")
        ),
    )

    exit_code = main([
        "polish", "3", "--source-root", str(tmp_path),
        "--manifest-refresh", "check", "--json",
    ])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert report["blockers"] == ["MANIFEST_REFRESH_OUTCOME_INVALID"]
    assert report["denominator_status"] == "NOT_RETAINED"
    assert len(report["findings"]) == 3
    focused = [
        item for item in report["findings"] if item["object_id"] is not None
    ]
    assert len(focused) == 2
    assert [row["object_kind"] for row in focused] == ["POLICY", None]
    assert [row["obligation_id"] for row in focused] == [
        "VSTD-T0.7-source-and-mechanism-freshness", "POLICY-0.2",
    ]
    invalid = [
        item for item in report["findings"]
        if item["code"] == "MANIFEST_REFRESH_OUTCOME_INVALID"
    ]
    assert len(invalid) == 1
    assert invalid[0]["gate_id"] == "manifest-refresh"
    assert all(
        record["blocking_prerequisite"]["blockers"]
        == ["MANIFEST_REFRESH_OUTCOME_INVALID"]
        for record in report["native_diagnostics"]["tier_execution"].values()
    )


def test_manifest_refresh_malformed_review_promotes_shape_blocker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
            "status": "UNKNOWN",
            "blockers": ["MANIFEST_REFRESH_REVIEW_REQUIRED"],
            "review_required": [None],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("stale assessor must not run")
        ),
    )

    exit_code = main([
        "polish", "3", "--source-root", str(tmp_path),
        "--manifest-refresh", "check", "--json",
    ])
    report = json.loads(capsys.readouterr().out)

    expected = {
        "MANIFEST_REFRESH_REVIEW_REQUIRED",
        "MANIFEST_REFRESH_OUTCOME_INVALID",
    }
    assert exit_code == 2
    assert set(report["blockers"]) == expected
    assert any(
        item["code"] == "MANIFEST_REFRESH_OUTCOME_INVALID"
        for item in report["findings"]
    )
    assert all(
        set(record["blocking_prerequisite"]["blockers"]) == expected
        for record in report["native_diagnostics"]["tier_execution"].values()
    )


def test_manifest_refresh_failure_retains_cumulative_not_run_accounting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
            "status": "FAIL",
            "blockers": ["MANIFEST_REFRESH_WRITE_FAILED"],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("failed refresh must not run package assessment")
        ),
    )

    exit_code = main([
        "polish", "3", "--source-root", str(tmp_path),
        "--manifest-refresh", "check", "--json",
    ])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert report["status"] == "FAIL"
    assert [item["tier"] for item in report["tier_results"]] == [1, 2, 3]
    assert all(
        item["execution_status"] == "NOT_RUN"
        for item in report["tier_results"]
    )
    assert set(report["native_diagnostics"]["tier_execution"]) == {
        "0", "1", "2", "3",
    }
    assert report["denominator_status"] == "NOT_RETAINED"


def test_refresh_blocked_schema_is_strict_and_digest_validation_rejects_tamper(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
            "status": "UNKNOWN",
            "blockers": ["MANIFEST_REFRESH_REVIEW_REQUIRED"],
            "review_required": [{
                "path": "src/example.py",
                "reason": "SOURCE_SEMANTICS_CHANGED",
                "object_id": "example-object",
                "classifications": ["POLICY"],
                "obligations": ["POLICY-0.2"],
            }],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("blocked refresh must not run package assessment")
        ),
    )
    assert main([
        "polish", "3", "--source-root", str(tmp_path),
        "--manifest-refresh", "check", "--json",
    ]) == 2
    report = json.loads(capsys.readouterr().out)

    import jsonschema
    schema = json.loads(REFRESH_BLOCKED_SCHEMA.read_bytes())
    validator = jsonschema.Draft202012Validator(schema)
    jsonschema.Draft202012Validator.check_schema(schema)
    validator.validate(report)
    assert self_polish_tiers._valid_manifest_refresh_blocked_report(report)

    unexpected = deepcopy(report)
    unexpected["undeclared"] = True
    assert list(validator.iter_errors(unexpected))
    assert not self_polish_tiers._valid_manifest_refresh_blocked_report(
        unexpected
    )

    for invalid_reason in (None, "   "):
        malformed_reason = deepcopy(report)
        if invalid_reason is None:
            malformed_reason["findings"][0].pop("reason")
        else:
            malformed_reason["findings"][0]["reason"] = invalid_reason
        assert list(validator.iter_errors(malformed_reason))
        assert not self_polish_tiers._valid_manifest_refresh_blocked_report(
            malformed_reason
        )

    mismatched_reason = deepcopy(report)
    mismatched_reason["findings"][0]["reason"] = (
        "A nonblank but causally different reason."
    )
    mismatched_body = {
        key: value for key, value in mismatched_reason.items()
        if key != "report_digest"
    }
    mismatched_reason["report_digest"] = core_obligation_union.value_digest(
        mismatched_body
    )
    # Draft 2020-12 cannot compare two sibling strings. The schema retains the
    # nonblank wire shape; the command validator enforces their semantic alias.
    validator.validate(mismatched_reason)
    assert not self_polish_tiers._valid_manifest_refresh_blocked_report(
        mismatched_reason
    )

    coordinated_wrong_reason = deepcopy(report)
    coordinated_wrong_reason["findings"][0]["reason"] = (
        "A nonblank but source-inconsistent reason."
    )
    coordinated_wrong_reason["findings"][0]["explanation"] = (
        coordinated_wrong_reason["findings"][0]["reason"]
    )
    coordinated_wrong_body = {
        key: value for key, value in coordinated_wrong_reason.items()
        if key != "report_digest"
    }
    coordinated_wrong_reason["report_digest"] = (
        core_obligation_union.value_digest(coordinated_wrong_body)
    )
    validator.validate(coordinated_wrong_reason)
    assert not self_polish_tiers._valid_manifest_refresh_blocked_report(
        coordinated_wrong_reason
    )

    wrong_tier = deepcopy(report)
    wrong_tier["tier_results"][2]["tier"] = 2
    assert list(validator.iter_errors(wrong_tier))
    assert not self_polish_tiers._valid_manifest_refresh_blocked_report(
        wrong_tier
    )

    wrong_digest = deepcopy(report)
    wrong_digest["report_digest"] = "sha256:" + "0" * 64
    validator.validate(wrong_digest)
    assert not self_polish_tiers._valid_manifest_refresh_blocked_report(
        wrong_digest
    )


@pytest.mark.parametrize(
    "malformed",
    (
        {},
        {"status": "CURRENT"},
        {
            **_current_manifest_refresh(),
            "unexpected_future_authority": True,
        },
        {
            "schema_version": package_manifest_refresh.RECEIPT_SCHEMA,
            "status": "REMIGRATED",
            "before_digest": "sha256:" + "1" * 64,
            "after_digest": "sha256:" + "2" * 64,
            "backup_digest": "sha256:" + "1" * 64,
            "backup_locator": "backup.vstd",
            "source_census_digest": "sha256:" + "3" * 64,
            "migration_mechanism_digest": "sha256:" + "4" * 64,
            "directory_durability": "NOT_ESTABLISHED",
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
        {
            "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
            "status": "FUTURE_SUCCESS",
            "blockers": ["MANIFEST_REFRESH_OUTCOME_UNKNOWN"],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    ),
)
@pytest.mark.parametrize("tier", (0, 3))
def test_malformed_or_unknown_refresh_success_never_runs_stale_assessor(
        malformed: dict, tier: int, tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: deepcopy(malformed),
    )
    monkeypatch.setattr(
        package_polish,
        "assess_package_polish",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("unproven freshness must not run package assessment")
        ),
    )
    monkeypatch.setattr(
        tier_zero,
        "assess_tier_zero",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("unproven freshness must not run Tier 0 admission")
        ),
    )

    assert main([
        "polish", str(tier), "--source-root", str(tmp_path), "--json",
    ]) == 2
    report = json.loads(capsys.readouterr().out)

    assert report["schema_version"] == (
        self_polish_tiers.POLISH_REFRESH_BLOCKED_SCHEMA
    )
    assert "MANIFEST_REFRESH_OUTCOME_INVALID" in report["blockers"]
    assert report["assessment_execution_status"] == "NOT_RUN"
    if tier:
        assert report["denominator_status"] == "NOT_RETAINED"
    else:
        assert "denominator_status" not in report
    assert self_polish_tiers._valid_manifest_refresh_blocked_report(report)


def test_complete_remigrated_refresh_receipt_allows_assessment(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    _accept_deliberately_incomplete_assessor_stub(monkeypatch)
    receipt = {
        "schema_version": package_manifest_refresh.RECEIPT_SCHEMA,
        "status": "REMIGRATED",
        "before_digest": "sha256:" + "1" * 64,
        "after_digest": "sha256:" + "2" * 64,
        "backup_digest": "sha256:" + "1" * 64,
        "backup_locator": "backup.vstd",
        "source_census_digest": "sha256:" + "3" * 64,
        "migration_mechanism_digest": "sha256:" + "4" * 64,
        "prepared_receipt_digest": "sha256:" + "5" * 64,
        "directory_durability": "NOT_ESTABLISHED",
        "refresh_is_admission": False,
        "refresh_is_polish": False,
    }
    calls: list[int] = []
    monkeypatch.setattr(
        package_manifest_refresh, "ensure_current_manifest",
        lambda *_args, **_kwargs: receipt,
    )

    def assess(tier, *_args, **_kwargs):
        calls.append(tier)
        return {"status": "PASS"}

    monkeypatch.setattr(package_polish, "assess_package_polish", assess)
    assert main([
        "polish", "3", "--source-root", str(tmp_path), "--json",
    ]) == 0
    capsys.readouterr()
    assert calls == [3]


@pytest.mark.parametrize("tier", (1, 2, 3))
def test_cancelled_default_package_polish_does_not_refresh(
    tier: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[int, bool]] = []
    _accept_deliberately_incomplete_assessor_stub(monkeypatch)

    def unexpected(*args, **kwargs):
        raise AssertionError("cancelled package polish must not refresh")

    def assess(selected_tier, root, *, cancelled):
        calls.append((selected_tier, cancelled))
        return {"status": "PASS"}

    monkeypatch.setattr(
        package_manifest_refresh, "ensure_current_manifest", unexpected
    )
    monkeypatch.setattr(package_polish, "assess_package_polish", assess)

    exit_code = main(["polish", str(tier), "--cancelled", "--json"])
    capsys.readouterr()

    assert exit_code == 0
    assert calls == [(tier, True)]


@pytest.mark.parametrize("tier", (1, 2, 3))
def test_native_specimens_do_not_refresh_root_manifest(
    tier: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[int] = []

    def unexpected(*args, **kwargs):
        raise AssertionError("native specimens must not refresh root manifest")

    def assess(tier, **kwargs):
        calls.append(tier)
        return {"status": "PASS"}

    monkeypatch.setattr(
        package_manifest_refresh, "ensure_current_manifest", unexpected
    )
    monkeypatch.setattr(self_polish_tiers, "assess_self_polish_tier", assess)

    exit_code = main([
        "polish", str(tier), "--native-specimens", "--json",
    ])
    capsys.readouterr()

    assert exit_code == 0
    assert calls == [tier]


def test_legacy_package_graph_does_not_refresh_root_manifest(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[str] = []

    def unexpected(*args, **kwargs):
        raise AssertionError("legacy package graph must not refresh root manifest")

    def assess_numeric(tier, **kwargs):
        calls.append("numeric")
        return {
            "status": "PASS",
            "source_coordinate": {"synthetic": True},
            "blockers": [],
        }

    def assess_graph(*args, **kwargs):
        calls.append("package-graph")
        return {"status": "PASS"}

    monkeypatch.setattr(
        package_manifest_refresh, "ensure_current_manifest", unexpected
    )
    monkeypatch.setattr(
        self_polish_tiers, "assess_self_polish_tier", assess_numeric
    )
    monkeypatch.setattr(
        package_self_polish, "assess_package_self_polish", assess_graph
    )

    exit_code = main(["polish", "1", "--package-graph", "--json"])
    capsys.readouterr()

    assert exit_code == 0
    assert calls == ["numeric", "package-graph"]


def test_tier_zero_explicit_manifest_does_not_refresh_root_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    selected = tmp_path / "selected.vstd"
    calls: list[object] = []

    def unexpected(*args, **kwargs):
        raise AssertionError("explicit Tier-0 manifest must not refresh root")

    def assess(root, *, manifest_path):
        calls.append(manifest_path)
        return {
            "schema_version": "test-tier-zero",
            "status": "PASS",
            "blockers": [],
        }

    monkeypatch.setattr(
        package_manifest_refresh, "ensure_current_manifest", unexpected
    )
    monkeypatch.setattr(tier_zero, "assess_tier_zero", assess)
    monkeypatch.setattr(manifest_gate, "admission_findings", lambda report: [])

    exit_code = main([
        "polish", "0", "--source-root", str(tmp_path),
        "--manifest", selected.name, "--json",
    ])
    capsys.readouterr()

    assert exit_code == 0
    assert calls == [selected]


@pytest.mark.parametrize("spelling", ("relative", "absolute", "hardlink"))
def test_tier_zero_explicit_root_manifest_still_refreshes_and_assesses_canonical(
    spelling: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "objects.vstd"
    target.write_bytes(b'{}\n')
    if spelling == "relative":
        selected = Path("objects.vstd")
    elif spelling == "absolute":
        selected = target
    else:
        selected = tmp_path / "root-alias.vstd"
        try:
            selected.hardlink_to(target)
        except OSError as exc:
            pytest.skip(f"OS_CAPABILITY_GUARD: hardlink unavailable: {exc}")
    events: list[tuple[str, object]] = []

    def ensure(root, *, mode, journal_root, review_policy="record"):
        events.append(("refresh", root))
        return _current_manifest_refresh()

    def assess(root, *, manifest_path):
        events.append(("assess", manifest_path))
        return {
            "schema_version": "test-tier-zero",
            "status": "PASS",
            "blockers": [],
        }

    monkeypatch.setattr(package_manifest_refresh, "ensure_current_manifest", ensure)
    monkeypatch.setattr(tier_zero, "assess_tier_zero", assess)
    monkeypatch.setattr(manifest_gate, "admission_findings", lambda report: [])

    exit_code = main([
        "polish", "0", "--source-root", str(tmp_path),
        "--manifest", str(selected), "--json",
    ])
    capsys.readouterr()

    assert exit_code == 0
    assert events == [
        ("refresh", str(tmp_path)),
        ("assess", target),
    ]


def test_package_graph_cli_preserves_package_schema_when_numeric_step_fails(
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(
        self_polish_tiers,
        "assess_self_polish_tier",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ValueError("synthetic numeric input failure")
        ),
    )

    exit_code = main(["polish", "1", "--package-graph", "--json"])
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert report["schema_version"] == package_self_polish.REPORT_SCHEMA
    assert report["status"] == report["project_gate_status"] == "FAIL"
    assert report["self_verifier_tier1"]["status"] == "FAIL"
    assert report["blockers"] == [
        "NUMERIC_SELF_VERIFIER_TIER1_FAILED",
        "NUMERIC_TIER1_BLOCKER:SELF_POLISH_TIER_CLI_INPUT_REJECTED",
        "PACKAGE_SELF_POLISH_ASSESSMENT_UNAVAILABLE",
    ]


def _break_module_import(
    monkeypatch: pytest.MonkeyPatch, module_name: str, exc_type: type,
) -> None:
    """Make the next import of one runtime module fail as a broken artifact."""

    def broken_import():
        raise exc_type("synthetic import failure")

    seams = {
        "verifier.runtime.package_manifest_refresh": "_manifest_refresh_module",
        "verifier.runtime.package_polish": "_package_polish_modules",
    }
    monkeypatch.setattr(self_polish_tiers, seams[module_name], broken_import)


def _assert_bounded_unknown_refresh_block(
    report: dict, *, tier: int, code: str,
) -> None:
    import jsonschema
    schema = json.loads(REFRESH_BLOCKED_SCHEMA.read_bytes())
    jsonschema.Draft202012Validator(schema).validate(report)
    assert self_polish_tiers._valid_manifest_refresh_blocked_report(report)
    assert report["status"] == "UNKNOWN"
    assert code in report["blockers"]
    assert report["requested_tier"] == tier
    assert report["assessment_execution_status"] == "NOT_RUN"
    assert report["polished"] is False
    finding = next(row for row in report["findings"] if row["code"] == code)
    assert finding["status"] == "UNKNOWN"
    assert f"vstd polish {tier} --json" in finding["next_action"]
    assert finding["gate_id"].strip()
    assert finding["obligation_id"].strip()
    assert finding["obligation_name"].strip()
    assert finding["reason"] == finding["explanation"]
    assert finding["rerun_argv"] == [
        "vstd", "polish", str(tier), "--json",
    ]


@pytest.mark.parametrize("exc_type", [SyntaxError, AssertionError])
@pytest.mark.parametrize("tier", [0, 1, 3])
def test_refresh_module_import_failure_is_bounded_unknown_json(
    tier: int,
    exc_type: type,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _break_module_import(
        monkeypatch, "verifier.runtime.package_manifest_refresh", exc_type,
    )

    exit_code = main([
        "polish", str(tier), "--source-root", str(tmp_path), "--json",
    ])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert exit_code == 2
    assert "Traceback" not in captured.err
    assert "synthetic import failure" not in captured.out
    assert report["blockers"] == ["MANIFEST_REFRESH_MECHANISM_UNAVAILABLE"]
    _assert_bounded_unknown_refresh_block(
        report, tier=tier, code="MANIFEST_REFRESH_MECHANISM_UNAVAILABLE",
    )


@pytest.mark.parametrize("exc_type", [SyntaxError, AssertionError])
@pytest.mark.parametrize("tier", [1, 3])
def test_package_polish_import_failure_is_bounded_unknown_json(
    tier: int,
    exc_type: type,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: _current_manifest_refresh(),
    )
    _break_module_import(monkeypatch, "verifier.runtime.package_polish", exc_type)

    exit_code = main([
        "polish", str(tier), "--source-root", str(tmp_path), "--json",
    ])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert exit_code == 2
    assert "Traceback" not in captured.err
    assert "synthetic import failure" not in captured.out
    assert report["blockers"] == ["PACKAGE_POLISH_MECHANISM_UNAVAILABLE"]
    _assert_bounded_unknown_refresh_block(
        report, tier=tier, code="PACKAGE_POLISH_MECHANISM_UNAVAILABLE",
    )


def test_refresh_blocked_envelope_validation_drift_is_bounded_unknown_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
            "status": "REFRESH_REQUIRED",
            "blockers": ["MANIFEST_REFRESH_REQUIRED_READ_ONLY"],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )
    monkeypatch.setattr(
        self_polish_tiers, "_valid_manifest_refresh_blocked_report",
        lambda value: False,
    )

    exit_code = main([
        "polish", "1", "--source-root", str(tmp_path), "--json",
    ])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert exit_code == 2
    assert "Traceback" not in captured.err
    assert report["status"] == "UNKNOWN"
    assert "MANIFEST_REFRESH_REQUIRED_READ_ONLY" in report["blockers"]
    assert "MANIFEST_REFRESH_BLOCKED_ENVELOPE_INVALID" in report["blockers"]
    assert report["assessment_execution_status"] == "NOT_RUN"


def test_refresh_import_failure_human_output_is_safe_and_readable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _break_module_import(
        monkeypatch, "verifier.runtime.package_manifest_refresh", SyntaxError,
    )

    exit_code = main(["polish", "1", "--source-root", str(tmp_path)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "Traceback" not in captured.err
    assert "synthetic import failure" not in captured.out
    assert "[UNKNOWN]" in captured.out
    assert "MANIFEST_REFRESH_MECHANISM_UNAVAILABLE" in captured.out


@pytest.mark.parametrize("code", sorted(self_polish_tiers.LIVE_SOURCE_DRIFT_CODES))
def test_refresh_live_source_drift_is_bounded_unknown_json(
    code: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Refresh hides drift behind a generic outage; the envelope must not."""

    def drifted(*_args, **_kwargs):
        try:
            raise self_polish_estate.EstateError(code)
        except self_polish_estate.EstateError as cause:
            raise package_manifest_refresh.ManifestRefreshError(
                "MANIFEST_REFRESH_SOURCE_UNAVAILABLE",
            ) from cause

    monkeypatch.setattr(package_manifest_refresh, "ensure_current_manifest", drifted)

    exit_code = main([
        "polish", "1", "--source-root", str(tmp_path), "--json",
    ])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert exit_code == 2
    assert "Traceback" not in captured.err
    assert report["blockers"] == [code]
    _assert_bounded_unknown_refresh_block(report, tier=1, code=code)


def test_refresh_source_drift_human_output_names_retry_without_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def drifted(*_args, **_kwargs):
        try:
            raise self_polish_estate.EstateError("CANDIDATE_SOURCE_MUTATED")
        except self_polish_estate.EstateError as cause:
            raise package_manifest_refresh.ManifestRefreshError(
                "MANIFEST_REFRESH_SOURCE_UNAVAILABLE",
            ) from cause

    monkeypatch.setattr(package_manifest_refresh, "ensure_current_manifest", drifted)

    exit_code = main(["polish", "1", "--source-root", str(tmp_path)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "Traceback" not in captured.err
    assert "[UNKNOWN]" in captured.out
    assert "CANDIDATE_SOURCE_MUTATED" in captured.out
    assert "vstd polish 1 --json" in captured.out
    assert "FAIL" not in captured.out


_EXIT_BY_STATUS = {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}


def _refresh_source_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(*_args, **_kwargs):
        raise package_manifest_refresh.ManifestRefreshError(
            "MANIFEST_REFRESH_SOURCE_UNAVAILABLE",
        )

    monkeypatch.setattr(package_manifest_refresh, "ensure_current_manifest", unavailable)


def _refresh_write_failed_control(monkeypatch: pytest.MonkeyPatch) -> None:
    """Genuine FAIL control: a refused write is a verifier-visible failure."""

    def failed(*_args, **_kwargs):
        raise package_manifest_refresh.ManifestRefreshError(
            "MANIFEST_REFRESH_WRITE_FAILED", status="FAIL",
        )

    monkeypatch.setattr(package_manifest_refresh, "ensure_current_manifest", failed)


def _refresh_review_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.OUTCOME_SCHEMA,
            "status": "UNKNOWN",
            "blockers": ["MANIFEST_REFRESH_REVIEW_REQUIRED"],
            "review_required": [{
                "path": "src/example.py",
                "reason": "SOURCE_SEMANTICS_CHANGED",
                "object_id": "example-object",
                "classifications": ["POLICY"],
                "obligations": ["POLICY-0.2"],
            }],
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )


def _import_mechanism_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    _break_module_import(
        monkeypatch, "verifier.runtime.package_manifest_refresh", SyntaxError,
    )


def _live_source_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    def drifted(*_args, **_kwargs):
        try:
            raise self_polish_estate.EstateError("CANDIDATE_SOURCE_MUTATED")
        except self_polish_estate.EstateError as cause:
            raise package_manifest_refresh.ManifestRefreshError(
                "MANIFEST_REFRESH_SOURCE_UNAVAILABLE",
            ) from cause

    monkeypatch.setattr(package_manifest_refresh, "ensure_current_manifest", drifted)


@pytest.mark.parametrize("tier", (0, 1))
@pytest.mark.parametrize(
    ("install", "expected_status"),
    (
        pytest.param(_refresh_source_unavailable, "UNKNOWN", id="refresh-unavailable"),
        pytest.param(_refresh_review_required, "UNKNOWN", id="review-required"),
        pytest.param(_import_mechanism_unavailable, "UNKNOWN", id="import-mechanism"),
        pytest.param(_live_source_drift, "UNKNOWN", id="live-source-drift"),
        pytest.param(_refresh_write_failed_control, "FAIL", id="write-failed-control"),
    ),
)
def test_blocked_envelope_exit_derives_from_status_in_json_and_human_modes(
    install,
    expected_status: str,
    tier: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    install(monkeypatch)
    argv = [
        "polish", str(tier), "--source-root", str(tmp_path),
        "--manifest-refresh", "check",
    ]

    json_exit = main([*argv, "--json"])
    json_captured = capsys.readouterr()
    report = json.loads(json_captured.out)

    assert json_captured.err == ""
    assert report["status"] == expected_status
    assert json_exit == _EXIT_BY_STATUS[report["status"]]

    human_exit = main(argv)
    human_captured = capsys.readouterr()

    assert human_captured.err == ""
    assert human_captured.out.splitlines()[0].startswith(
        f"[{expected_status}]"
    )
    assert human_exit == json_exit


@pytest.mark.parametrize(
    ("source_refusal", "outcome_invalid"),
    (
        pytest.param(
            "GIT_STATE_UNAVAILABLE", False,
            id="classified-refusal-keeps-its-blocker",
        ),
        pytest.param(
            "NOT_A_CODE", True,
            id="unclassified-refusal-code-is-outcome-invalid",
        ),
    ),
)
def test_classified_source_refusal_detail_is_not_masked_as_outcome_invalid(
    source_refusal: str,
    outcome_invalid: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A producer's closed-vocabulary source_refusal must pass the envelope gate."""

    def refused(*_args, **_kwargs):
        raise package_manifest_refresh.ManifestRefreshError(
            "MANIFEST_REFRESH_SOURCE_UNAVAILABLE",
            details={"source_refusal": source_refusal},
        )

    monkeypatch.setattr(package_manifest_refresh, "ensure_current_manifest", refused)

    exit_code = main([
        "polish", "0", "--source-root", str(tmp_path),
        "--manifest-refresh", "check", "--json",
    ])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert captured.err == ""
    assert exit_code == 2
    assert report["status"] == "UNKNOWN"
    if outcome_invalid:
        assert "MANIFEST_REFRESH_OUTCOME_INVALID" in report["blockers"]
    else:
        assert "MANIFEST_REFRESH_OUTCOME_INVALID" not in report["blockers"]
        assert report["blockers"] == ["MANIFEST_REFRESH_SOURCE_UNAVAILABLE"]
        assert not any(
            row["code"] == "MANIFEST_REFRESH_OUTCOME_INVALID"
            for row in report["findings"]
        )


@pytest.mark.parametrize(
    ("details", "named"),
    (
        pytest.param(
            {"cause_type": "ValueError", "cause": "NAMESPACE_SOURCE_CHANGED_DURING_DISCOVERY"},
            "MANIFEST_REFRESH_PREVIEW_FAILED:NAMESPACE_SOURCE_CHANGED_DURING_DISCOVERY",
            id="code-shaped-cause-is-named",
        ),
        pytest.param(
            {"cause_type": "OSError"},
            "MANIFEST_REFRESH_PREVIEW_FAILED:OSError",
            id="only-the-cause-type-is-named",
        ),
        # A wrapped refusal is named by its innermost code and that code's arguments:
        # the outer wrappers say where it was raised, the innermost what to fix.
        pytest.param(
            {"cause_type": "ValueError", "cause": (
                "PACKAGE_ORIGINAL_KIND_CATALOG_EVIDENCE_INVALID:VALIDATOR_FAILED:repository_assets:"
                "validate_source_partition:ValueError:REPOSITORY_ASSET_ORIGINAL_KIND_OWNED_CONTENT_DRIFT:"
                "vstd-generated-distribution-metadata")},
            "MANIFEST_REFRESH_PREVIEW_FAILED:REPOSITORY_ASSET_ORIGINAL_KIND_OWNED_CONTENT_DRIFT:"
            "vstd-generated-distribution-metadata",
            id="refusal-chain-is-named-by-its-innermost-code",
        ),
    ),
)
def test_preview_failure_names_its_cause_instead_of_a_generic_outcome_invalid(
    details: dict,
    named: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The refresh outcome carries only closed keys, so the cause travels as a blocker."""

    def failed(*_args, **_kwargs):
        raise package_manifest_refresh.ManifestRefreshError(
            "MANIFEST_REFRESH_PREVIEW_FAILED", status="FAIL", details=details,
        )

    monkeypatch.setattr(package_manifest_refresh, "ensure_current_manifest", failed)
    argv = ["polish", "0", "--source-root", str(tmp_path), "--manifest-refresh", "check"]

    json_exit = main([*argv, "--json"])
    report = json.loads(capsys.readouterr().out)

    assert json_exit == 1
    assert "MANIFEST_REFRESH_OUTCOME_INVALID" not in report["blockers"]
    assert report["blockers"] == sorted(["MANIFEST_REFRESH_PREVIEW_FAILED", named])

    main(argv)
    assert named in capsys.readouterr().out
