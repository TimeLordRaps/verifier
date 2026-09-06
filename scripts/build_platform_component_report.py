#!/usr/bin/env python3
"""Build bounded component-contract evidence for one exact platform test run.

Terminology: continuous integration (CI); identifier (ID);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Verifier Standard (VSTD).

The source manifest records configured intent only. This builder runs after the
mapped tests and refuses to emit a report unless the supplied JUnit document
records at least one test and no failures or errors. The report is evidence for
that exact test command and environment, not a general platform-support claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping
import xml.etree.ElementTree as ET

from verifier.interoperability.reference_catalog import reference_component_registry


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "docs" / "platform-component-contracts.json"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
MANIFEST_SCHEMA_VERSION = "VSTD-PLATFORM-COMPONENT-CONTRACTS-1"
REPORT_SCHEMA_VERSION = "VSTD-PLATFORM-COMPONENT-REPORT-1"
TEST_COMMAND = (
    "python -u -m pytest -vv -s --durations=10 --timeout=60 "
    "-p scripts.pytest_public_evidence "
    "--junitxml=platform-contracts.xml"
)
COORDINATE_IDS = ("linux-x64", "windows-x64", "macos-x64", "macos-arm64")
INTENT_STATUSES = frozenset(
    {"CONFIGURED_UNRUN", "NOT_CONFIGURED", "UNSUPPORTED"}
)
REQUIRED_ENVIRONMENT_FIELDS = (
    "platform_system",
    "platform_machine",
    "python_implementation",
    "python_version",
    "runner_os",
    "runner_arch",
    "image_os",
    "image_version",
    "executed_git_sha",
    "git_ref",
    "event_name",
    "run_id",
    "run_attempt",
    "pull_request_head_sha",
    "pull_request_base_sha",
)
ENVIRONMENT_DOCUMENT_DIGEST_FIELD = "source_document_sha256"
REPORT_CLAIM_BOUNDARY = (
    "This report establishes only that the mapped tests completed without a JUnit "
    "failure or error under the exact recorded Git, workflow, interpreter, runner, "
    "operating-system, and machine coordinate. It does not establish universal "
    "platform support, full behavioral equivalence, native dependency portability, "
    "external implementation interoperability, or correctness beyond those tests."
)


class PlatformComponentReportError(ValueError):
    """Raised when a source contract or observed run coordinate is not exact."""


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PlatformComponentReportError(f"{label} must be one nonempty trimmed string")
    return value


def _exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise PlatformComponentReportError(
            f"{label} keys mismatch; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PlatformComponentReportError(
                f"JSON document contains duplicate key {key!r}"
            )
        result[key] = value
    return result


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    """Load and validate the exact source intent manifest."""

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PlatformComponentReportError(f"cannot load source manifest: {exc}") from exc
    if not isinstance(value, dict):
        raise PlatformComponentReportError("source manifest must be one JSON object")
    validate_manifest(value, root=ROOT)
    return value


def validate_manifest(value: Mapping[str, Any], *, root: Path) -> None:
    """Require one total, deterministic mapping over the reference catalog."""

    _exact_keys(
        value,
        {
            "schema_version",
            "claim_boundary",
            "status_vocabulary",
            "coordinates",
            "components",
        },
        "source manifest",
    )
    if value.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise PlatformComponentReportError(
            f"source manifest schema_version must be {MANIFEST_SCHEMA_VERSION!r}"
        )
    _nonempty_string(value.get("claim_boundary"), "source manifest claim_boundary")

    vocabulary = value.get("status_vocabulary")
    if not isinstance(vocabulary, dict) or set(vocabulary) != INTENT_STATUSES:
        raise PlatformComponentReportError(
            "status_vocabulary must define exactly CONFIGURED_UNRUN, "
            "NOT_CONFIGURED, and UNSUPPORTED"
        )
    for status, description in vocabulary.items():
        _nonempty_string(description, f"status_vocabulary.{status}")

    coordinates = value.get("coordinates")
    if not isinstance(coordinates, list):
        raise PlatformComponentReportError("coordinates must be an array")
    coordinate_keys = {
        "coordinate_id",
        "operating_system",
        "runner_operating_system",
        "machine_family",
        "runner_architecture",
        "runner_label",
        "python_version",
    }
    coordinate_ids: list[str] = []
    for index, coordinate in enumerate(coordinates):
        if not isinstance(coordinate, dict):
            raise PlatformComponentReportError(f"coordinates[{index}] must be an object")
        _exact_keys(coordinate, coordinate_keys, f"coordinates[{index}]")
        for key in coordinate_keys:
            _nonempty_string(coordinate.get(key), f"coordinates[{index}].{key}")
        coordinate_ids.append(coordinate["coordinate_id"])
    if tuple(coordinate_ids) != COORDINATE_IDS:
        raise PlatformComponentReportError(
            f"coordinates must appear exactly as {list(COORDINATE_IDS)!r}"
        )

    registry = reference_component_registry()
    catalog = {component.component_id: component for component in registry.components}
    components = value.get("components")
    if not isinstance(components, list):
        raise PlatformComponentReportError("components must be an array")
    component_keys = {
        "component_id",
        "label",
        "dependency_profiles",
        "catalog_optional_dependencies",
        "coverage_kind",
        "test_modules",
        "test_scope",
        "coordinate_intent",
    }
    component_ids: list[str] = []
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise PlatformComponentReportError(f"components[{index}] must be an object")
        _exact_keys(component, component_keys, f"components[{index}]")
        component_id = _nonempty_string(
            component.get("component_id"), f"components[{index}].component_id"
        )
        component_ids.append(component_id)
        if component_id not in catalog:
            raise PlatformComponentReportError(
                f"source manifest has unknown component {component_id!r}"
            )
        descriptor = catalog[component_id]
        if component.get("label") != descriptor.label:
            raise PlatformComponentReportError(
                f"label mismatch for {component_id}: expected {descriptor.label!r}"
            )
        if component.get("catalog_optional_dependencies") != list(
            descriptor.optional_dependencies
        ):
            raise PlatformComponentReportError(
                f"catalog optional dependency mismatch for {component_id}"
            )
        profiles = component.get("dependency_profiles")
        if (
            not isinstance(profiles, list)
            or not profiles
            or profiles != sorted(set(profiles))
            or not set(profiles) <= {"test", "seal", "scitt"}
            or "test" not in profiles
        ):
            raise PlatformComponentReportError(
                f"{component_id} dependency_profiles must be a sorted unique subset of "
                "test, seal, and scitt that includes test"
            )
        if component.get("coverage_kind") not in {
            "BEHAVIOR",
            "ENTRYPOINT_CHARACTERIZATION",
        }:
            raise PlatformComponentReportError(
                f"{component_id} coverage_kind must be BEHAVIOR or "
                "ENTRYPOINT_CHARACTERIZATION"
            )
        tests = component.get("test_modules")
        if not isinstance(tests, list) or not tests or tests != sorted(set(tests)):
            raise PlatformComponentReportError(
                f"{component_id} test_modules must be a nonempty sorted unique array"
            )
        for test_module in tests:
            test_path = _nonempty_string(test_module, f"{component_id} test module")
            if not re.fullmatch(r"tests/test_[A-Za-z0-9_]+\.py", test_path):
                raise PlatformComponentReportError(
                    f"{component_id} has invalid test module path {test_path!r}"
                )
            if not (root / test_path).is_file():
                raise PlatformComponentReportError(
                    f"{component_id} test module does not exist: {test_path}"
                )
        _nonempty_string(component.get("test_scope"), f"{component_id} test_scope")
        intent = component.get("coordinate_intent")
        if not isinstance(intent, dict) or tuple(intent) != COORDINATE_IDS:
            raise PlatformComponentReportError(
                f"{component_id} coordinate_intent must contain the four coordinates "
                "in canonical order"
            )
        invalid = {status for status in intent.values() if status not in INTENT_STATUSES}
        if invalid:
            raise PlatformComponentReportError(
                f"{component_id} has invalid intent statuses: {sorted(invalid)}"
            )
    expected_ids = tuple(sorted(catalog))
    if tuple(component_ids) != expected_ids:
        raise PlatformComponentReportError(
            "source manifest component identifiers must exactly equal the sorted "
            "reference catalog identifiers"
        )


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    """Return the digest of the canonical source-manifest JSON object."""

    return _sha256(_canonical_json_bytes(manifest))


def _case_matches_module(case: ET.Element, test_module: str) -> bool:
    classname = case.attrib.get("classname", "")
    dotted = test_module.removesuffix(".py").replace("/", ".")
    stem = Path(test_module).stem
    return (
        classname == dotted
        or classname.startswith(dotted + ".")
        or classname == stem
        or classname.startswith(stem + ".")
    )


def junit_summary(
    path: Path, required_test_modules: tuple[str, ...] = ()
) -> dict[str, Any]:
    """Require successful, non-skipped execution for every mapped test module."""

    try:
        document = path.read_bytes()
    except OSError as exc:
        raise PlatformComponentReportError(f"cannot load JUnit evidence: {exc}") from exc
    return junit_summary_bytes(document, required_test_modules)


def junit_summary_bytes(
    document: bytes, required_test_modules: tuple[str, ...] = ()
) -> dict[str, Any]:
    """Validate one captured JUnit byte document without rereading its source."""

    try:
        root = ET.fromstring(document)
    except ET.ParseError as exc:
        raise PlatformComponentReportError(f"cannot load JUnit evidence: {exc}") from exc
    cases = root.findall(".//testcase")
    failures = root.findall(".//failure")
    errors = root.findall(".//error")
    skipped = root.findall(".//skipped")
    if not cases:
        raise PlatformComponentReportError("JUnit evidence contains no test cases")
    counted_elements = [root]
    if root.tag != "testsuite":
        counted_elements.extend(root.findall(".//testsuite"))
    for index, element in enumerate(counted_elements):
        label = f"JUnit {element.tag}[{index}]"
        descendants = {
            "tests": len(element.findall(".//testcase")),
            "failures": len(element.findall(".//failure")),
            "errors": len(element.findall(".//error")),
            "skipped": len(element.findall(".//skipped")),
        }
        for attribute, observed_count in descendants.items():
            declared = element.attrib.get(attribute)
            if declared is None:
                continue
            if re.fullmatch(r"0|[1-9][0-9]*", declared) is None:
                raise PlatformComponentReportError(
                    f"{label} {attribute} count is not a nonnegative integer"
                )
            if int(declared) != observed_count:
                raise PlatformComponentReportError(
                    f"{label} {attribute} count contradicts contained test evidence: "
                    f"declared={declared}, observed={observed_count}"
                )
    if failures or errors:
        raise PlatformComponentReportError(
            f"JUnit evidence is not successful: failures={len(failures)}, errors={len(errors)}"
        )
    module_results = []
    for test_module in sorted(set(required_test_modules)):
        module_cases = [
            case for case in cases if _case_matches_module(case, test_module)
        ]
        if not module_cases:
            raise PlatformComponentReportError(
                f"JUnit evidence contains no cases for mapped module {test_module}"
            )
        skipped_cases = [
            case for case in module_cases if case.find("skipped") is not None
        ]
        passed = len(module_cases) - len(skipped_cases)
        if passed < 1:
            raise PlatformComponentReportError(
                f"JUnit evidence has no non-skipped case for mapped module {test_module}"
            )
        module_results.append(
            {
                "test_module": test_module,
                "test_cases": len(module_cases),
                "passed": passed,
                "skipped": len(skipped_cases),
            }
        )
    return {
        "status": "TEST_COMMAND_SUCCEEDED",
        "test_cases": len(cases),
        "failures": 0,
        "errors": 0,
        "skipped": len(skipped),
        "document_digest": _sha256(document),
        "mapped_module_results": module_results,
    }


def load_environment(path: Path) -> dict[str, str]:
    """Load the exact environment record emitted before dependency installation."""

    try:
        document = path.read_bytes()
    except OSError as exc:
        raise PlatformComponentReportError(f"cannot load environment evidence: {exc}") from exc
    return load_environment_bytes(document)


def load_environment_bytes(document: bytes) -> dict[str, str]:
    """Validate one captured environment byte document without rereading its source."""

    try:
        value = json.loads(
            document.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PlatformComponentReportError(f"cannot load environment evidence: {exc}") from exc
    if not isinstance(value, dict):
        raise PlatformComponentReportError("environment evidence must be one JSON object")
    _exact_keys(
        value,
        set(REQUIRED_ENVIRONMENT_FIELDS),
        "environment evidence",
    )
    environment: dict[str, str] = {}
    for field in REQUIRED_ENVIRONMENT_FIELDS:
        item = value.get(field)
        if not isinstance(item, str):
            raise PlatformComponentReportError(f"environment {field} must be a string")
        if field not in {"pull_request_head_sha", "pull_request_base_sha"} and not item:
            raise PlatformComponentReportError(f"environment {field} must not be empty")
        environment[field] = item
    if re.fullmatch(r"[0-9a-fA-F]{40,64}", environment["executed_git_sha"]) is None:
        raise PlatformComponentReportError("executed_git_sha is not a full Git object ID")
    for field in ("pull_request_head_sha", "pull_request_base_sha"):
        value = environment[field]
        if value and re.fullmatch(r"[0-9a-fA-F]{40,64}", value) is None:
            raise PlatformComponentReportError(f"{field} is not a full Git object ID")
    if environment["event_name"] == "pull_request" and not all(
        environment[field]
        for field in ("pull_request_head_sha", "pull_request_base_sha")
    ):
        raise PlatformComponentReportError(
            "pull_request environment evidence requires exact head and base object IDs"
        )
    environment[ENVIRONMENT_DOCUMENT_DIGEST_FIELD] = _sha256(document)
    return environment


def _coordinate(manifest: Mapping[str, Any], coordinate_id: str) -> Mapping[str, str]:
    for coordinate in manifest["coordinates"]:
        if coordinate["coordinate_id"] == coordinate_id:
            return coordinate
    raise PlatformComponentReportError(f"unknown coordinate {coordinate_id!r}")


def require_matching_environment(
    coordinate: Mapping[str, str], environment: Mapping[str, str]
) -> None:
    """Reject a report when declared and observed platform coordinates differ."""

    expected = {
        "platform_system": coordinate["operating_system"],
        "platform_machine": coordinate["machine_family"],
        "runner_os": coordinate["runner_operating_system"],
        "runner_arch": coordinate["runner_architecture"],
        "python_version": coordinate["python_version"],
    }
    differences = {
        key: {"expected": expected_value, "observed": environment.get(key)}
        for key, expected_value in expected.items()
        if environment.get(key) != expected_value
    }
    if differences:
        raise PlatformComponentReportError(
            "observed environment does not match the declared coordinate: "
            + json.dumps(differences, sort_keys=True)
        )


def build_report(
    manifest: Mapping[str, Any],
    *,
    coordinate_id: str,
    environment: Mapping[str, str],
    test_summary: Mapping[str, Any],
) -> dict[str, Any]:
    """Build one deterministic, bounded report from validated inputs."""

    validate_manifest(manifest, root=ROOT)
    _exact_keys(
        environment,
        set(REQUIRED_ENVIRONMENT_FIELDS) | {ENVIRONMENT_DOCUMENT_DIGEST_FIELD},
        "loaded environment evidence",
    )
    environment_document_digest = environment.get(ENVIRONMENT_DOCUMENT_DIGEST_FIELD)
    if (
        not isinstance(environment_document_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", environment_document_digest) is None
    ):
        raise PlatformComponentReportError(
            "loaded environment evidence lacks an exact source document SHA-256 digest"
        )
    coordinate = _coordinate(manifest, coordinate_id)
    require_matching_environment(coordinate, environment)
    if (
        test_summary.get("status") != "TEST_COMMAND_SUCCEEDED"
        or not isinstance(test_summary.get("test_cases"), int)
        or int(test_summary["test_cases"]) < 1
        or test_summary.get("failures") != 0
        or test_summary.get("errors") != 0
    ):
        raise PlatformComponentReportError("test summary is not successful")
    required_test_modules = sorted(
        {
            test_module
            for component in manifest["components"]
            for test_module in component["test_modules"]
        }
    )
    module_results = test_summary.get("mapped_module_results")
    if not isinstance(module_results, list):
        raise PlatformComponentReportError(
            "test summary lacks mapped-module execution evidence"
        )
    observed_test_modules = []
    for item in module_results:
        if not isinstance(item, dict):
            raise PlatformComponentReportError(
                "mapped-module execution evidence must contain objects"
            )
        test_module = item.get("test_module")
        passed = item.get("passed")
        if not isinstance(test_module, str) or type(passed) is not int or passed < 1:
            raise PlatformComponentReportError(
                "mapped-module execution evidence must record a non-skipped pass"
            )
        observed_test_modules.append(test_module)
    if observed_test_modules != required_test_modules:
        raise PlatformComponentReportError(
            "mapped-module execution evidence does not exactly cover the source manifest"
        )
    registry = reference_component_registry()
    mappings = []
    for component in manifest["components"]:
        intent = component["coordinate_intent"][coordinate_id]
        if intent != "CONFIGURED_UNRUN":
            raise PlatformComponentReportError(
                f"cannot emit execution evidence for {component['component_id']} with "
                f"source intent {intent}"
            )
        mappings.append(
            {
                "component_id": component["component_id"],
                "label": component["label"],
                "dependency_profiles": component["dependency_profiles"],
                "catalog_optional_dependencies": component[
                    "catalog_optional_dependencies"
                ],
                "coverage_kind": component["coverage_kind"],
                "test_modules": component["test_modules"],
                "test_scope": component["test_scope"],
                "source_intent": intent,
            }
        )
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_kind": "bounded_platform_component_contract_execution",
        "verification_effect": "NONE",
        "observed_test_status": "TEST_COMMAND_SUCCEEDED",
        "claim_boundary": REPORT_CLAIM_BOUNDARY,
        "coordinate": dict(coordinate),
        "environment": dict(environment),
        "junit": dict(test_summary),
        "catalog": {
            "schema_version": registry.schema_version,
            "registry_version": registry.registry_version,
            "canonical_digest": "sha256:" + registry.canonical_digest(),
            "component_ids": [item.component_id for item in registry.components],
        },
        "source_manifest": {
            "schema_version": manifest["schema_version"],
            "canonical_digest": manifest_digest(manifest),
        },
        "source_workflow": {
            "path": ".github/workflows/ci.yml",
            "canonical_digest": _sha256(WORKFLOW_PATH.read_bytes()),
            "test_command": TEST_COMMAND,
        },
        "component_test_mapping": mappings,
    }


def render_report_bytes(report: Mapping[str, Any]) -> bytes:
    """Render one platform-neutral, deterministic report document."""

    return (
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def render_component_table(manifest: Mapping[str, Any]) -> str:
    """Render the manifest's exact component-to-coordinate intent table."""

    validate_manifest(manifest, root=ROOT)
    lines = [
        "| Reference component | Linux x86-64 | Windows x86-64 | macOS Intel x86-64 | macOS Apple ARM64 | Coverage kind | Test modules | Dependency profile | Bounded test scope |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for component in manifest["components"]:
        identifier = component["component_id"]
        label = component["label"]
        tests = "<br>".join(f"`{path}`" for path in component["test_modules"])
        profiles = ", ".join(f"`{profile}`" for profile in component["dependency_profiles"])
        intent = component["coordinate_intent"]
        lines.append(
            "| "
            + f"{label}<br>`{identifier}` | "
            + " | ".join(f"`{intent[coordinate]}`" for coordinate in COORDINATE_IDS)
            + f" | `{component['coverage_kind']}` | {tests} | {profiles} | {component['test_scope']} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--coordinate", required=True, choices=COORDINATE_IDS)
    parser.add_argument("--environment", type=Path, default=Path("platform-environment.json"))
    parser.add_argument("--junit", type=Path, default=Path("platform-contracts.xml"))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=Path("platform-component-contract.json"))
    args = parser.parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        environment = load_environment(args.environment)
        required_test_modules = tuple(
            sorted(
                {
                    test_module
                    for component in manifest["components"]
                    for test_module in component["test_modules"]
                }
            )
        )
        summary = junit_summary(args.junit, required_test_modules)
        report = build_report(
            manifest,
            coordinate_id=args.coordinate,
            environment=environment,
            test_summary=summary,
        )
        args.output.write_bytes(render_report_bytes(report))
    except (OSError, UnicodeError, PlatformComponentReportError) as exc:
        print(f"[PLATFORM COMPONENT REPORT BLOCKED] {exc}", file=sys.stderr)
        return 1
    print(f"[PLATFORM COMPONENT REPORT WRITTEN] {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
