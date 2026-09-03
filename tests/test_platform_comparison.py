"""Terminology: command-line interface (CLI); JavaScript Object Notation (JSON);
Verifier Standard (VSTD).

Adversarial tests for bounded operating-system result comparison.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable

import pytest

from verifier.core.platform_comparison import (
    PlatformComparisonStatus,
    compare_platform_run_receipts,
)
from verifier.core.receipt import compute_canonical_digest
from verifier.core.run import capture_run
from verifier.core.run_validation import _rebuild_stable_payload_from_dict
from verifier.runtime.public_cli import main


PLATFORMS = ("Darwin", "Linux", "Windows")
ROOT = Path(__file__).resolve().parents[1]


def _captured_receipt(project: Path) -> dict[str, Any]:
    project.mkdir()
    (project / "data").mkdir()
    (project / "src").mkdir()
    (project / "data" / "input.txt").write_text(
        "portable input\n", encoding="utf-8"
    )
    (project / "src" / "compute.py").write_text(
        "from pathlib import Path\n"
        "Path('output.txt').write_bytes(Path('data/input.txt').read_bytes().upper())\n",
        encoding="utf-8",
    )
    manifest = {
        "claim": {
            "id": "RUN-PLATFORM-TEST",
            "title": "Operating-system comparison fixture",
            "statement": "The declared command records the same output bytes.",
            "scope": "one test fixture",
            "limitations": ["supplied receipt coordinates only"],
            "falsification_condition": "a comparable declared result differs",
        },
        "command": [sys.executable, "src/compute.py"],
        "cwd": ".",
        "repo_dir": ".",
        "target_name": "platform-comparison-fixture",
        "portable_repository_id": "example.invalid/verifier-fixture",
        "inputs": [
            {"path": "data/input.txt", "role": "primary_input"},
            {"path": "src/compute.py", "role": "entrypoint_source"},
        ],
        "outputs": [{"path": "output.txt", "role": "primary_output"}],
        "determinism_declared": "DETERMINISTIC",
        "evaluator_claims": [
            {
                "evaluator_name": "fixture_byte_counter",
                "metric_name": "output_bytes",
                "value": 15,
            }
        ],
        "refutation_surface": {
            "admissible_refutations": ["a declared result differs"],
            "excluded_claims": ["UNIVERSAL_PORTABILITY"],
            "falsification_condition": "a comparable declared result differs",
            "platform_comparability": {
                "mechanism_id": "PLATFORM-COMPARISON-TEST-SUBJECT-1",
                "compatible_platforms": list(PLATFORMS),
                "result_surfaces": [
                    "execution",
                    "declared_outputs",
                    "evaluator_claims",
                    "stdio",
                ],
            },
        },
    }
    return capture_run(manifest, manifest_dir=project).to_dict()


def _write_variant(
    root: Path,
    base: dict[str, Any],
    platform: str,
    *,
    mutate: Callable[[dict[str, Any]], None] | None = None,
    execution_platform: str | None = None,
) -> Path:
    receipt = copy.deepcopy(base)
    receipt["source_state"]["runtime"]["platform_system"] = platform
    receipt["execution"]["platform_system"] = execution_platform or platform
    if mutate is not None:
        mutate(receipt)
    receipt["canonical_digest"] = compute_canonical_digest(
        _rebuild_stable_payload_from_dict(receipt)
    )
    root.mkdir()
    (root / "receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8"
    )
    return root


def _three_receipts(tmp_path: Path) -> tuple[dict[str, Any], list[Path]]:
    base = _captured_receipt(tmp_path / "project")
    receipts = [
        _write_variant(tmp_path / platform.lower(), base, platform)
        for platform in PLATFORMS
    ]
    return base, receipts


def test_identical_declared_results_across_all_platforms_pass(tmp_path: Path) -> None:
    _base, receipts = _three_receipts(tmp_path)

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.PASS
    assert result.exit_code == 0
    assert result.required_platforms == PLATFORMS
    assert result.observed_platforms == PLATFORMS
    assert result.comparison_binding_digest is not None
    assert {item["platform"] for item in result.observations} == set(PLATFORMS)
    assert len({item["result_digest"] for item in result.observations}) == 1


def test_capture_uses_platform_neutral_nested_source_paths(tmp_path: Path) -> None:
    receipt = _captured_receipt(tmp_path / "project")

    assert set(receipt["source_state"]["source_file_hashes"]) == {
        "data/input.txt",
        "src/compute.py",
    }


def test_missing_declared_platform_is_not_established(tmp_path: Path) -> None:
    _base, receipts = _three_receipts(tmp_path)

    result = compare_platform_run_receipts(receipts[:-1])

    assert result.status is PlatformComparisonStatus.NOT_ESTABLISHED
    assert result.exit_code == 2
    assert result.errors == ("missing declared platforms: Windows",)


def test_comparable_output_disagreement_is_conflicted(tmp_path: Path) -> None:
    base = _captured_receipt(tmp_path / "project")
    receipts = [
        _write_variant(tmp_path / "darwin", base, "Darwin"),
        _write_variant(tmp_path / "linux", base, "Linux"),
        _write_variant(
            tmp_path / "windows",
            base,
            "Windows",
            mutate=lambda receipt: receipt["outputs"][0].__setitem__(
                "sha256", "0" * 64
            ),
        ),
    ]

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.CONFLICTED
    assert result.exit_code == 1
    assert result.comparison_binding_digest is not None
    assert any(
        difference["path"] == "declared_outputs[0].sha256"
        and difference["observed_platform"] == "Windows"
        for difference in result.differences
    )


def test_comparable_evaluator_value_disagreement_is_conflicted(
    tmp_path: Path,
) -> None:
    base = _captured_receipt(tmp_path / "project")
    receipts = [
        _write_variant(tmp_path / "darwin", base, "Darwin"),
        _write_variant(tmp_path / "linux", base, "Linux"),
        _write_variant(
            tmp_path / "windows",
            base,
            "Windows",
            mutate=lambda receipt: receipt["claims"]["evaluator_claims"][
                0
            ].__setitem__("value", 16),
        ),
    ]

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.CONFLICTED
    assert any(
        difference["path"] == "evaluator_claims[0].value"
        for difference in result.differences
    )


@pytest.mark.parametrize(
    ("reference_value", "observed_value"),
    ((15, 15.0), (0.0, -0.0), (True, 1)),
)
def test_canonical_json_value_representation_drift_is_conflicted(
    tmp_path: Path,
    reference_value: object,
    observed_value: object,
) -> None:
    base = _captured_receipt(tmp_path / "project")
    base["claims"]["evaluator_claims"][0]["value"] = reference_value
    receipts = [
        _write_variant(tmp_path / "darwin", base, "Darwin"),
        _write_variant(tmp_path / "linux", base, "Linux"),
        _write_variant(
            tmp_path / "windows",
            base,
            "Windows",
            mutate=lambda receipt: receipt["claims"]["evaluator_claims"][
                0
            ].__setitem__("value", observed_value),
        ),
    ]

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.CONFLICTED
    assert any(
        difference["path"] == "evaluator_claims[0].value"
        for difference in result.differences
    )


def test_output_identity_drift_is_not_established(tmp_path: Path) -> None:
    base = _captured_receipt(tmp_path / "project")
    receipts = [
        _write_variant(tmp_path / "darwin", base, "Darwin"),
        _write_variant(tmp_path / "linux", base, "Linux"),
        _write_variant(
            tmp_path / "windows",
            base,
            "Windows",
            mutate=lambda receipt: receipt["outputs"][0].__setitem__(
                "path", "different-output.txt"
            ),
        ),
    ]

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.NOT_ESTABLISHED
    assert any(
        difference["kind"] == "comparison_binding"
        and difference["path"] == "outputs[0].path"
        for difference in result.differences
    )


def test_evaluator_identity_drift_is_not_established(tmp_path: Path) -> None:
    base = _captured_receipt(tmp_path / "project")
    receipts = [
        _write_variant(tmp_path / "darwin", base, "Darwin"),
        _write_variant(tmp_path / "linux", base, "Linux"),
        _write_variant(
            tmp_path / "windows",
            base,
            "Windows",
            mutate=lambda receipt: receipt["claims"]["evaluator_claims"][
                0
            ].__setitem__("metric_name", "different_metric"),
        ),
    ]

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.NOT_ESTABLISHED
    assert any(
        difference["kind"] == "comparison_binding"
        and difference["path"]
        == "claims.evaluator_claims[0].metric_name"
        for difference in result.differences
    )


def test_non_platform_binding_drift_is_not_mislabeled_conflict(
    tmp_path: Path,
) -> None:
    base = _captured_receipt(tmp_path / "project")
    receipts = [
        _write_variant(tmp_path / "darwin", base, "Darwin"),
        _write_variant(
            tmp_path / "linux",
            base,
            "Linux",
            mutate=lambda receipt: receipt.__setitem__(
                "claim_scope", "different claim coordinate"
            ),
        ),
        _write_variant(tmp_path / "windows", base, "Windows"),
    ]

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.NOT_ESTABLISHED
    assert result.comparison_binding_digest is None
    assert any(
        difference["kind"] == "comparison_binding"
        and difference["path"] == "claim_scope"
        for difference in result.differences
    )


def test_machine_family_drift_is_not_mislabeled_operating_system_conflict(
    tmp_path: Path,
) -> None:
    base = _captured_receipt(tmp_path / "project")

    def change_machine_family(receipt: dict[str, Any]) -> None:
        receipt["source_state"]["runtime"]["platform_machine"] = "arm64"

    receipts = [
        _write_variant(tmp_path / "darwin", base, "Darwin"),
        _write_variant(tmp_path / "linux", base, "Linux"),
        _write_variant(
            tmp_path / "windows",
            base,
            "Windows",
            mutate=change_machine_family,
        ),
    ]

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.NOT_ESTABLISHED
    assert any(
        difference["path"] == "platform_comparison_environment.machine_family"
        for difference in result.differences
    )


def test_missing_machine_coordinate_is_not_established(tmp_path: Path) -> None:
    base = _captured_receipt(tmp_path / "project")

    def remove_machine(receipt: dict[str, Any]) -> None:
        del receipt["source_state"]["runtime"]["platform_machine"]

    receipts = [
        _write_variant(tmp_path / "darwin", base, "Darwin"),
        _write_variant(tmp_path / "linux", base, "Linux", mutate=remove_machine),
        _write_variant(tmp_path / "windows", base, "Windows"),
    ]

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.NOT_ESTABLISHED
    assert any("comparison environment is missing" in error for error in result.errors)


def test_canonical_digest_tampering_is_invalid(tmp_path: Path) -> None:
    _base, receipts = _three_receipts(tmp_path)
    receipt_path = receipts[1] / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["claim_scope"] = "tampered without digest update"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.INVALID
    assert any("canonical digest mismatch" in error for error in result.errors)


@pytest.mark.parametrize(
    ("payload", "error_fragment"),
    (
        ('{"value": NaN}', "non-finite number"),
        ('{"value": Infinity}', "non-finite number"),
        ('{"value": -Infinity}', "non-finite number"),
        ('{"value": 1e999}', "outside the finite float range"),
        ('{"value": 1, "value": 2}', "duplicate object key"),
    ),
)
def test_comparator_rejects_nonstandard_or_ambiguous_json(
    tmp_path: Path,
    payload: str,
    error_fragment: str,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(payload, encoding="utf-8")

    result = compare_platform_run_receipts([receipt_path])

    assert result.status is PlatformComparisonStatus.INVALID
    assert any(error_fragment in error for error in result.errors)


def test_absent_declaration_is_not_established(tmp_path: Path) -> None:
    base = _captured_receipt(tmp_path / "project")

    def remove_declaration(receipt: dict[str, Any]) -> None:
        del receipt["assessment_context"]["refutation_surface"][
            "platform_comparability"
        ]

    receipts = [
        _write_variant(
            tmp_path / platform.lower(),
            base,
            platform,
            mutate=remove_declaration,
        )
        for platform in PLATFORMS
    ]

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.NOT_ESTABLISHED
    assert result.exit_code == 2
    assert len(result.errors) == 3


def test_malformed_declaration_is_invalid(tmp_path: Path) -> None:
    base = _captured_receipt(tmp_path / "project")

    def corrupt_mechanism(receipt: dict[str, Any]) -> None:
        receipt["assessment_context"]["refutation_surface"][
            "platform_comparability"
        ]["mechanism_id"] = ""

    receipts = [
        _write_variant(tmp_path / "darwin", base, "Darwin"),
        _write_variant(tmp_path / "linux", base, "Linux", mutate=corrupt_mechanism),
        _write_variant(tmp_path / "windows", base, "Windows"),
    ]

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.INVALID
    assert result.exit_code == 1
    assert any("mechanism_id must identify" in error for error in result.errors)


def test_platform_identifiers_that_collide_after_normalization_are_invalid(
    tmp_path: Path,
) -> None:
    base = _captured_receipt(tmp_path / "project")
    base["assessment_context"]["refutation_surface"]["platform_comparability"][
        "compatible_platforms"
    ] = ["Linux", "Windows", "ＷＩＮＤＯＷＳ"]
    receipts = [
        _write_variant(tmp_path / platform.lower(), base, platform)
        for platform in PLATFORMS
    ]

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.INVALID
    assert any(
        "collide after Unicode normalization and casefold" in error
        for error in result.errors
    )


def test_duplicate_platform_evidence_is_not_established(tmp_path: Path) -> None:
    base = _captured_receipt(tmp_path / "project")
    receipts = [
        _write_variant(tmp_path / "darwin", base, "Darwin"),
        _write_variant(tmp_path / "linux-a", base, "Linux"),
        _write_variant(tmp_path / "linux-b", base, "Linux"),
    ]

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.NOT_ESTABLISHED
    assert any("duplicate receipt" in error for error in result.errors)
    assert any("missing declared platforms: Windows" == error for error in result.errors)


def test_contradictory_platform_fields_are_invalid(tmp_path: Path) -> None:
    base = _captured_receipt(tmp_path / "project")
    receipts = [
        _write_variant(tmp_path / "darwin", base, "Darwin"),
        _write_variant(
            tmp_path / "linux",
            base,
            "Linux",
            execution_platform="Windows",
        ),
        _write_variant(tmp_path / "windows", base, "Windows"),
    ]

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.INVALID
    assert any("does not equal" in error for error in result.errors)


def test_declaration_order_is_semantically_normalized(tmp_path: Path) -> None:
    base = _captured_receipt(tmp_path / "project")

    def reverse_declaration(receipt: dict[str, Any]) -> None:
        declaration = receipt["assessment_context"]["refutation_surface"][
            "platform_comparability"
        ]
        declaration["compatible_platforms"].reverse()
        declaration["result_surfaces"].reverse()

    receipts = [
        _write_variant(tmp_path / "darwin", base, "Darwin"),
        _write_variant(tmp_path / "linux", base, "Linux", mutate=reverse_declaration),
        _write_variant(tmp_path / "windows", base, "Windows"),
    ]

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.PASS


def test_legacy_windows_source_separators_compare_with_posix_paths(
    tmp_path: Path,
) -> None:
    base = _captured_receipt(tmp_path / "project")

    def use_legacy_windows_separators(receipt: dict[str, Any]) -> None:
        source_hashes = receipt["source_state"]["source_file_hashes"]
        receipt["source_state"]["source_file_hashes"] = {
            path.replace("/", "\\"): digest
            for path, digest in source_hashes.items()
        }

    receipts = [
        _write_variant(tmp_path / "darwin", base, "Darwin"),
        _write_variant(tmp_path / "linux", base, "Linux"),
        _write_variant(
            tmp_path / "windows",
            base,
            "Windows",
            mutate=use_legacy_windows_separators,
        ),
    ]

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.PASS


def test_colliding_legacy_windows_source_paths_are_invalid(tmp_path: Path) -> None:
    base = _captured_receipt(tmp_path / "project")

    def add_separator_collision(receipt: dict[str, Any]) -> None:
        source_hashes = receipt["source_state"]["source_file_hashes"]
        source_hashes["src\\compute.py"] = source_hashes["src/compute.py"]

    receipts = [
        _write_variant(tmp_path / "darwin", base, "Darwin"),
        _write_variant(tmp_path / "linux", base, "Linux"),
        _write_variant(
            tmp_path / "windows",
            base,
            "Windows",
            mutate=add_separator_collision,
        ),
    ]

    result = compare_platform_run_receipts(receipts)

    assert result.status is PlatformComparisonStatus.INVALID
    assert any(
        "collide after Windows separator normalization" in error
        for error in result.errors
    )


def test_compare_platforms_cli_emits_bounded_json_report(
    tmp_path: Path, capsys
) -> None:
    _base, receipts = _three_receipts(tmp_path)

    assert main(
        ["compare-platforms", *(str(path) for path in receipts), "--json"]
    ) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["status"] == "PASS"
    assert report["report_kind"] == "platform_comparison_diagnostic"
    assert report["mechanism"]["identifier"] == "VSTD-PLATFORM-COMPARISON-0.1"
    assert (
        report["declaration"]["mechanism_id"]
        == "PLATFORM-COMPARISON-TEST-SUBJECT-1"
    )
    assert "universal portability" in " ".join(report["limitations"])
    assert "record identical values" in report["claim_boundary"]


def test_generic_example_serializes_platform_neutral_output_bytes(
    tmp_path: Path,
) -> None:
    input_path = tmp_path / "input.txt"
    output_path = tmp_path / "output.json"
    metrics_path = tmp_path / "metrics.json"
    input_path.write_text("beta alpha beta\n", encoding="utf-8", newline="\n")

    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "examples" / "generic_run" / "compute.py"),
            str(input_path),
            str(output_path),
            str(metrics_path),
        ],
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0
    assert b"\r\n" not in output_path.read_bytes()
    assert b"\r\n" not in metrics_path.read_bytes()


def test_continuous_integration_aggregate_cannot_mask_comparison_failure() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    marker = "- name: Require comparable recorded results across all declared platforms"
    step = workflow.split(marker, 1)[1].split("      - uses:", 1)[0]

    assert "| tee platform-comparison.json" not in step
    assert "--json > platform-comparison.json" in step
    assert 'report.get("status") == "PASS"' in step
    assert 'report.get("exit_code") == 0' in step
