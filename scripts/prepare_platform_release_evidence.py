#!/usr/bin/env python3
"""Prepare deterministic, release-bound platform evidence.

Terminology: continuous integration (CI); JavaScript Object Notation (JSON);
Java unit test report format (JUnit); Secure Hash Algorithm 256-bit (SHA-256);
Verifier Standard (VSTD); ZIP archive format (ZIP).

The input is the eight artifacts emitted by one exact successful hosted
repository-checks run: a component report plus raw environment and JUnit
evidence for each canonical platform coordinate. The output is observational
evidence only and has no VSTD verification effect.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any
import zipfile


ROOT = Path(__file__).resolve().parents[1]
REPORT_BUILDER_PATH = Path(__file__).with_name("build_platform_component_report.py")
_REPORT_SPEC = importlib.util.spec_from_file_location(
    "vstd_platform_component_report_builder", REPORT_BUILDER_PATH
)
assert _REPORT_SPEC is not None and _REPORT_SPEC.loader is not None
report_builder = importlib.util.module_from_spec(_REPORT_SPEC)
_REPORT_SPEC.loader.exec_module(report_builder)


BUNDLE_SCHEMA_VERSION = "VSTD-PLATFORM-RELEASE-EVIDENCE-1"
BUNDLE_CLAIM_BOUNDARY = (
    "This bundle preserves the exact raw environment records, JUnit documents, "
    "and reconstructed component reports from one successful hosted run at the "
    "named release commit. It does not establish universal platform support, full "
    "behavioral equivalence, native dependency portability, external implementation "
    "interoperability, or correctness beyond the mapped tests. Its VSTD verification "
    "effect is NONE."
)
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


class PlatformReleaseEvidenceError(ValueError):
    """Raised when hosted platform evidence is incomplete or inconsistently bound."""


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _render_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _read_json_object_bytes(document: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(document.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PlatformReleaseEvidenceError(f"cannot load {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise PlatformReleaseEvidenceError(f"{label} must be one JSON object")
    return value


def _require_exact_directory(path: Path, expected_files: set[str], label: str) -> None:
    if not path.is_dir():
        raise PlatformReleaseEvidenceError(f"missing {label} directory {path.name!r}")
    actual = {item.name for item in path.iterdir()}
    if actual != expected_files or not all(item.is_file() for item in path.iterdir()):
        raise PlatformReleaseEvidenceError(
            f"{label} directory {path.name!r} files mismatch; "
            f"missing={sorted(expected_files - actual)}, "
            f"extra={sorted(actual - expected_files)}"
        )


def _required_test_modules(manifest: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                test_module
                for component in manifest["components"]
                for test_module in component["test_modules"]
            }
        )
    )


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, _ZIP_TIMESTAMP)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = 0o100644 << 16
    return info


def prepare_release_evidence(
    *,
    evidence_root: Path,
    output: Path,
    release_tag: str,
    repository: str,
    source_commit: str,
    run_id: str,
    run_attempt: str,
    default_branch: str = "main",
) -> dict[str, Any]:
    """Validate one exact four-coordinate run and write a deterministic ZIP bundle."""

    if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", release_tag) is None:
        raise PlatformReleaseEvidenceError("release_tag must be an exact vX.Y.Z tag")
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        raise PlatformReleaseEvidenceError("repository must be an exact owner/name coordinate")
    if re.fullmatch(r"[0-9a-f]{40,64}", source_commit) is None:
        raise PlatformReleaseEvidenceError(
            "source_commit must be one lowercase full Git object identifier"
        )
    if re.fullmatch(r"[1-9][0-9]*", run_id) is None:
        raise PlatformReleaseEvidenceError("run_id must be a positive decimal identifier")
    if re.fullmatch(r"[1-9][0-9]*", run_attempt) is None:
        raise PlatformReleaseEvidenceError(
            "run_attempt must be a positive decimal identifier"
        )
    if not default_branch or default_branch != default_branch.strip():
        raise PlatformReleaseEvidenceError("default_branch must be nonempty and trimmed")
    if not evidence_root.is_dir():
        raise PlatformReleaseEvidenceError("evidence_root is not a directory")

    coordinates = report_builder.COORDINATE_IDS
    raw_names = {
        coordinate: f"platform-python-contracts-{run_id}-{run_attempt}-{coordinate}"
        for coordinate in coordinates
    }
    report_names = {
        coordinate: f"platform-component-contract-{run_id}-{run_attempt}-{coordinate}"
        for coordinate in coordinates
    }
    expected_directories = set(raw_names.values()) | set(report_names.values())
    actual_directories = {item.name for item in evidence_root.iterdir()}
    if actual_directories != expected_directories or not all(
        item.is_dir() for item in evidence_root.iterdir()
    ):
        raise PlatformReleaseEvidenceError(
            "downloaded artifact directories mismatch; "
            f"missing={sorted(expected_directories - actual_directories)}, "
            f"extra={sorted(actual_directories - expected_directories)}"
        )

    manifest = report_builder.load_manifest()
    required_modules = _required_test_modules(manifest)
    member_payloads: dict[str, bytes] = {}
    for coordinate in coordinates:
        raw_directory = evidence_root / raw_names[coordinate]
        report_directory = evidence_root / report_names[coordinate]
        _require_exact_directory(
            raw_directory,
            {"platform-environment.json", "platform-contracts.xml"},
            "raw platform evidence",
        )
        _require_exact_directory(
            report_directory,
            {"platform-component-contract.json"},
            "platform component report",
        )

        environment_path = raw_directory / "platform-environment.json"
        junit_path = raw_directory / "platform-contracts.xml"
        report_path = report_directory / "platform-component-contract.json"
        try:
            environment_bytes = environment_path.read_bytes()
            junit_bytes = junit_path.read_bytes()
            report_bytes = report_path.read_bytes()
        except OSError as exc:
            raise PlatformReleaseEvidenceError(
                f"cannot capture {coordinate} platform evidence: {exc}"
            ) from exc
        environment = report_builder.load_environment_bytes(environment_bytes)
        expected_environment = {
            "executed_git_sha": source_commit,
            "git_ref": f"refs/heads/{default_branch}",
            "event_name": "push",
            "run_id": run_id,
            "run_attempt": run_attempt,
            "pull_request_head_sha": "",
            "pull_request_base_sha": "",
        }
        differences = {
            key: {"expected": expected, "observed": environment.get(key)}
            for key, expected in expected_environment.items()
            if environment.get(key) != expected
        }
        if differences:
            raise PlatformReleaseEvidenceError(
                f"{coordinate} release coordinate mismatch: "
                + json.dumps(differences, sort_keys=True)
            )

        junit = report_builder.junit_summary_bytes(junit_bytes, required_modules)
        expected_report = report_builder.build_report(
            manifest,
            coordinate_id=coordinate,
            environment=environment,
            test_summary=junit,
        )
        observed_report = _read_json_object_bytes(
            report_bytes, f"{coordinate} component report"
        )
        expected_report_bytes = report_builder.render_report_bytes(expected_report)
        if observed_report != expected_report or report_bytes != expected_report_bytes:
            raise PlatformReleaseEvidenceError(
                f"{coordinate} component report is not the exact reconstructed report"
            )

        member_payloads[f"coordinates/{coordinate}/environment.json"] = (
            environment_bytes
        )
        member_payloads[f"coordinates/{coordinate}/junit.xml"] = junit_bytes
        member_payloads[f"coordinates/{coordinate}/report.json"] = report_bytes

    member_records = [
        {
            "path": name,
            "sha256": _sha256(payload),
            "size_bytes": len(payload),
        }
        for name, payload in sorted(member_payloads.items())
    ]
    bundle_manifest = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "report_kind": "bounded_platform_release_evidence",
        "verification_effect": "NONE",
        "release_tag": release_tag,
        "repository": repository,
        "source_commit": source_commit,
        "workflow": {
            "name": "repository-checks",
            "path": ".github/workflows/ci.yml",
            "event": "push",
            "git_ref": f"refs/heads/{default_branch}",
            "run_id": run_id,
            "run_attempt": run_attempt,
        },
        "coordinate_ids": list(coordinates),
        "members": member_records,
        "claim_boundary": BUNDLE_CLAIM_BOUNDARY,
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w") as bundle:
        bundle.writestr(
            _zip_info("PLATFORM-EVIDENCE-MANIFEST.json"),
            _render_json(bundle_manifest),
        )
        for name, payload in sorted(member_payloads.items()):
            bundle.writestr(_zip_info(name), payload)
    return bundle_manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--default-branch", default="main")
    args = parser.parse_args(argv)
    try:
        prepare_release_evidence(
            evidence_root=args.evidence_root,
            output=args.output,
            release_tag=args.release_tag,
            repository=args.repository,
            source_commit=args.source_commit,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            default_branch=args.default_branch,
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        report_builder.PlatformComponentReportError,
        PlatformReleaseEvidenceError,
    ) as exc:
        print(f"[PLATFORM RELEASE EVIDENCE BLOCKED] {exc}", file=sys.stderr)
        return 1
    print(f"[PLATFORM RELEASE EVIDENCE WRITTEN] {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
