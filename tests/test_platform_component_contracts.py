"""Machine-check the bounded cross-platform component-contract surface.

Terminology: continuous integration (CI); JavaScript Object Notation (JSON);
Java unit test report format (JUnit); Secure Hash Algorithm 256-bit (SHA-256);
Verifier Standard (VSTD).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

from verifier.interoperability.reference_catalog import reference_component_registry


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs" / "platform-component-contracts.json"
REPORT_BUILDER_PATH = ROOT / "scripts" / "build_platform_component_report.py"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
MATRIX_PATH = ROOT / "docs" / "PLATFORM_INTEROPERABILITY.md"

SPEC = importlib.util.spec_from_file_location(
    "build_platform_component_report_test", REPORT_BUILDER_PATH
)
assert SPEC is not None and SPEC.loader is not None
report_builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report_builder)


def _manifest() -> dict:
    return report_builder.load_manifest(MANIFEST_PATH)


def _environment(**updates: str) -> dict[str, str]:
    value = {
        "platform_system": "Linux",
        "platform_machine": "x86_64",
        "python_implementation": "CPython",
        "python_version": "3.12.10",
        "runner_os": "Linux",
        "runner_arch": "X64",
        "image_os": "ubuntu24",
        "image_version": "20260901.1",
        "executed_git_sha": "a" * 40,
        "git_ref": "refs/pull/31/merge",
        "event_name": "pull_request",
        "run_id": "33788300817",
        "run_attempt": "1",
        "pull_request_head_sha": "b" * 40,
        "pull_request_base_sha": "c" * 40,
    }
    value.update(updates)
    return value


def _loaded_environment(**updates: str) -> dict[str, str]:
    value = _environment(**updates)
    value[report_builder.ENVIRONMENT_DOCUMENT_DIGEST_FIELD] = "sha256:" + "d" * 64
    return value


def _mapped_test_modules() -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                test_module
                for component in _manifest()["components"]
                for test_module in component["test_modules"]
            }
        )
    )


def _write_junit(
    path: Path,
    *,
    failure: bool = False,
    modules: tuple[str, ...] | None = None,
    skipped_module: str | None = None,
) -> None:
    modules = modules or _mapped_test_modules()
    cases = []
    for index, test_module in enumerate(modules):
        classname = test_module.removesuffix(".py").replace("/", ".")
        child = ""
        if failure and index == 0:
            child = '<failure message="failed" />'
        elif test_module == skipped_module:
            child = '<skipped message="not available" />'
        cases.append(
            f'<testcase classname="{classname}" name="test_contract_{index}">{child}</testcase>'
        )
    result = (
        f'<testsuites><testsuite name="platform" tests="{len(cases)}" '
        f'failures="{1 if failure else 0}">' + "".join(cases) + "</testsuite></testsuites>"
    )
    path.write_text(result, encoding="utf-8")


def test_manifest_exactly_covers_reference_catalog_and_four_coordinates() -> None:
    manifest = _manifest()
    registry = reference_component_registry()

    assert tuple(item["coordinate_id"] for item in manifest["coordinates"]) == (
        "linux-x64",
        "windows-x64",
        "macos-x64",
        "macos-arm64",
    )
    assert [item["component_id"] for item in manifest["components"]] == [
        item.component_id for item in registry.components
    ]
    assert all(
        set(item["coordinate_intent"])
        == {coordinate["coordinate_id"] for coordinate in manifest["coordinates"]}
        for item in manifest["components"]
    )
    assert {
        state
        for item in manifest["components"]
        for state in item["coordinate_intent"].values()
    } == {"CONFIGURED_UNRUN"}
    assert "PASS" not in MANIFEST_PATH.read_text(encoding="utf-8")


def test_runtime_report_rendering_is_platform_neutral() -> None:
    rendered = report_builder.render_report_bytes(
        {"schema_version": report_builder.REPORT_SCHEMA_VERSION, "value": "line\nfeed"}
    )

    assert b"\r" not in rendered
    assert rendered.endswith(b"\n")
    assert rendered == report_builder.render_report_bytes(
        {"value": "line\nfeed", "schema_version": report_builder.REPORT_SCHEMA_VERSION}
    )


def test_manifest_declares_behavior_scope_and_optional_profiles() -> None:
    components = {
        item["component_id"]: item for item in _manifest()["components"]
    }

    artifact = components["component:artifact-bundle-verifier"]
    assert artifact["coverage_kind"] == "BEHAVIOR"
    assert artifact["dependency_profiles"] == ["seal", "test"]
    assert artifact["catalog_optional_dependencies"] == [
        "cryptography for seal verification"
    ]
    assert artifact["test_modules"] == ["tests/test_artifact_control.py"]
    assert "privileged-write prevention" in artifact["test_scope"]
    assert {item["coverage_kind"] for item in components.values()} == {"BEHAVIOR"}


def test_manifest_tests_exist_and_are_in_the_four_coordinate_ci_command() -> None:
    manifest = _manifest()
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    job = workflow["jobs"]["platform-python-contracts"]
    matrix = job["strategy"]["matrix"]["include"]

    expected_coordinates = {
        (
            item["coordinate_id"],
            item["runner_label"],
            item["operating_system"],
            item["machine_family"],
            item["runner_architecture"],
            item["python_version"],
        )
        for item in manifest["coordinates"]
    }
    configured_coordinates = {
        (
            item["coordinate"],
            item["runner"],
            item["expected_platform"],
            item["expected_machine"],
            item["expected_runner_arch"],
            "3.12.10",
        )
        for item in matrix
    }
    assert configured_coordinates == expected_coordinates

    test_step = next(
        step
        for step in job["steps"]
        if step.get("name")
        == "Exercise the complete Python contract suite and optional integrations"
    )
    command = test_step["run"]
    mapped_tests = {
        test_module
        for component in manifest["components"]
        for test_module in component["test_modules"]
    }
    assert mapped_tests
    assert command.strip().startswith("python -m pytest -q")
    assert "tests/test_" not in command
    assert " ".join(command.split()) == report_builder.TEST_COMMAND
    assert 'testpaths = ["tests"]' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for test_module in mapped_tests:
        assert (ROOT / test_module).is_file()
    required_profiles = {
        profile
        for component in manifest["components"]
        for profile in component["dependency_profiles"]
    }
    assert required_profiles == {"test", "seal", "scitt"}
    install_step = next(
        step
        for step in job["steps"]
        if 'pip install ".[test,seal,scitt]"' in str(step.get("run", ""))
    )
    assert install_step


def test_workflow_builds_report_only_after_tests_and_always_uploads_raw_evidence() -> None:
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["platform-python-contracts"]["steps"]
    test_index = next(
        index
        for index, step in enumerate(steps)
        if step.get("name")
        == "Exercise the complete Python contract suite and optional integrations"
    )
    report_index = next(
        index
        for index, step in enumerate(steps)
        if step.get("name") == "Build bounded platform-component report"
    )
    uploads = [
        step for step in steps if "upload-artifact@" in str(step.get("uses", ""))
    ]
    raw_upload = next(
        step
        for step in uploads
        if step["with"]["name"].startswith("platform-python-contracts-")
    )
    report_upload = next(
        step
        for step in uploads
        if step["with"]["name"].startswith("platform-component-contract-")
    )

    assert report_index > test_index
    assert steps[report_index].get("if", "success()") == "success()"
    assert "--coordinate ${{ matrix.coordinate }}" in steps[report_index]["run"]
    assert raw_upload["if"] == "always()"
    assert "${{ github.run_id }}-${{ github.run_attempt }}" in raw_upload["with"][
        "name"
    ]
    assert raw_upload["with"]["retention-days"] == 30
    assert set(raw_upload["with"]["path"].splitlines()) == {
        "platform-environment.json",
        "platform-contracts.xml",
    }
    assert report_upload["if"] == "success()"
    assert "${{ github.run_id }}-${{ github.run_attempt }}" in report_upload[
        "with"
    ]["name"]
    assert report_upload["with"]["retention-days"] == 30
    assert report_upload["with"]["path"] == "platform-component-contract.json"


def test_documented_component_table_is_exactly_rendered_from_manifest() -> None:
    manifest = _manifest()
    document = MATRIX_PATH.read_text(encoding="utf-8")
    begin = "<!-- BEGIN GENERATED PLATFORM COMPONENT CONTRACTS -->"
    end = "<!-- END GENERATED PLATFORM COMPONENT CONTRACTS -->"

    assert document.count(begin) == document.count(end) == 1
    rendered = document.split(begin, 1)[1].split(end, 1)[0].strip() + "\n"
    assert rendered == report_builder.render_component_table(manifest)
    assert "macOS Intel x86-64" in rendered
    assert "macOS Apple ARM64" in rendered


def test_runtime_report_is_deterministic_and_binds_catalog_manifest_and_run(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    junit = tmp_path / "platform-contracts.xml"
    _write_junit(junit)
    summary = report_builder.junit_summary(junit, _mapped_test_modules())
    environment = _loaded_environment()

    first = report_builder.build_report(
        manifest,
        coordinate_id="linux-x64",
        environment=environment,
        test_summary=summary,
    )
    second = report_builder.build_report(
        manifest,
        coordinate_id="linux-x64",
        environment=environment,
        test_summary=summary,
    )

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["observed_test_status"] == "TEST_COMMAND_SUCCEEDED"
    assert first["verification_effect"] == "NONE"
    assert first["junit"]["document_digest"].startswith("sha256:")
    assert [
        item["test_module"] for item in first["junit"]["mapped_module_results"]
    ] == list(_mapped_test_modules())
    assert all(
        item["passed"] >= 1
        for item in first["junit"]["mapped_module_results"]
    )
    assert first["environment"]["executed_git_sha"] == "a" * 40
    assert first["environment"]["source_document_sha256"] == "sha256:" + "d" * 64
    assert first["catalog"]["schema_version"] == reference_component_registry().schema_version
    assert first["catalog"]["registry_version"] == reference_component_registry().registry_version
    assert first["catalog"]["canonical_digest"] == (
        "sha256:" + reference_component_registry().canonical_digest()
    )
    assert first["source_manifest"]["canonical_digest"] == report_builder.manifest_digest(
        manifest
    )
    assert first["source_workflow"] == {
        "path": ".github/workflows/ci.yml",
        "canonical_digest": report_builder._sha256(WORKFLOW_PATH.read_bytes()),
        "test_command": report_builder.TEST_COMMAND,
    }
    assert [item["component_id"] for item in first["component_test_mapping"]] == [
        item.component_id for item in reference_component_registry().components
    ]
    assert "does not establish universal platform support" in first["claim_boundary"]


def test_runtime_report_rejects_failed_tests_and_environment_substitution(
    tmp_path: Path,
) -> None:
    junit = tmp_path / "failed.xml"
    _write_junit(junit, failure=True)
    with pytest.raises(report_builder.PlatformComponentReportError, match="not successful"):
        report_builder.junit_summary(junit, _mapped_test_modules())

    contradictory = tmp_path / "contradictory.xml"
    contradictory.write_text(
        '<testsuites><testsuite tests="1" failures="1" errors="0" skipped="0">'
        '<testcase classname="tests.test_platform_comparison" name="test_claimed_pass" />'
        "</testsuite></testsuites>",
        encoding="utf-8",
    )
    with pytest.raises(
        report_builder.PlatformComponentReportError,
        match="failures count contradicts contained test evidence",
    ):
        report_builder.junit_summary(contradictory)

    contradictory_tests = tmp_path / "contradictory-tests.xml"
    contradictory_tests.write_text(
        '<testsuites><testsuite tests="2" failures="0">'
        '<testcase classname="tests.test_platform_comparison" name="test_claimed_pass" />'
        "</testsuite></testsuites>",
        encoding="utf-8",
    )
    with pytest.raises(
        report_builder.PlatformComponentReportError,
        match="tests count contradicts contained test evidence",
    ):
        report_builder.junit_summary(contradictory_tests)

    malformed_count = tmp_path / "malformed-count.xml"
    malformed_count.write_text(
        '<testsuites><testsuite tests="one">'
        '<testcase classname="tests.test_platform_comparison" name="test_claimed_pass" />'
        "</testsuite></testsuites>",
        encoding="utf-8",
    )
    with pytest.raises(
        report_builder.PlatformComponentReportError,
        match="tests count is not a nonnegative integer",
    ):
        report_builder.junit_summary(malformed_count)

    missing_module = tmp_path / "missing-module.xml"
    _write_junit(missing_module, modules=_mapped_test_modules()[:-1])
    with pytest.raises(
        report_builder.PlatformComponentReportError,
        match="no cases for mapped module",
    ):
        report_builder.junit_summary(missing_module, _mapped_test_modules())

    skipped_module = tmp_path / "skipped-module.xml"
    _write_junit(
        skipped_module,
        skipped_module=_mapped_test_modules()[0],
    )
    with pytest.raises(
        report_builder.PlatformComponentReportError,
        match="no non-skipped case for mapped module",
    ):
        report_builder.junit_summary(skipped_module, _mapped_test_modules())

    successful = tmp_path / "successful.xml"
    _write_junit(successful)
    successful_summary = report_builder.junit_summary(
        successful, _mapped_test_modules()
    )

    with pytest.raises(
        report_builder.PlatformComponentReportError,
        match="does not match the declared coordinate",
    ):
        report_builder.build_report(
            _manifest(),
            coordinate_id="linux-x64",
            environment=_loaded_environment(platform_machine="arm64"),
            test_summary=successful_summary,
        )

    missing_pull_request_coordinate = tmp_path / "missing-pull-request.json"
    missing_pull_request_coordinate.write_text(
        json.dumps(_environment(pull_request_head_sha="")), encoding="utf-8"
    )
    with pytest.raises(
        report_builder.PlatformComponentReportError,
        match="requires exact head and base object IDs",
    ):
        report_builder.load_environment(missing_pull_request_coordinate)

    unexpected_field = tmp_path / "unexpected-field.json"
    unexpected = _environment()
    unexpected["unbound_extra_field"] = "not permitted"
    unexpected_field.write_text(json.dumps(unexpected), encoding="utf-8")
    with pytest.raises(
        report_builder.PlatformComponentReportError,
        match="environment evidence keys mismatch",
    ):
        report_builder.load_environment(unexpected_field)

    duplicate_key = tmp_path / "duplicate-key.json"
    duplicate_key.write_text(
        json.dumps(_environment())[:-1] + ', "run_id": "33788300817"}',
        encoding="utf-8",
    )
    with pytest.raises(
        report_builder.PlatformComponentReportError,
        match="duplicate key 'run_id'",
    ):
        report_builder.load_environment(duplicate_key)


def test_report_builder_cli_writes_deterministic_exact_coordinate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    environment_path = tmp_path / "platform-environment.json"
    junit_path = tmp_path / "platform-contracts.xml"
    output_path = tmp_path / "platform-component-contract.json"
    environment_path.write_text(
        json.dumps(
            _environment(
                platform_system="Windows",
                platform_machine="AMD64",
                runner_os="Windows",
            )
        ),
        encoding="utf-8",
    )
    _write_junit(junit_path)
    arguments = [
        "--coordinate",
        "windows-x64",
        "--environment",
        str(environment_path),
        "--junit",
        str(junit_path),
        "--manifest",
        str(MANIFEST_PATH),
        "--output",
        str(output_path),
    ]

    assert report_builder.main(arguments) == 0
    first = output_path.read_bytes()
    assert report_builder.main(arguments) == 0
    second = output_path.read_bytes()

    assert first == second
    report = json.loads(second)
    assert report["coordinate"]["coordinate_id"] == "windows-x64"
    assert report["environment"]["platform_system"] == "Windows"
    assert "REPORT WRITTEN" in capsys.readouterr().out
