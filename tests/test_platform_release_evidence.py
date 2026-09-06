"""Adversarial tests for release-bound platform evidence.

Terminology: Extensible Markup Language (XML); identifier (ID); Java unit test report format (JUnit);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Unicode Transformation Format, 8-bit (UTF-8); Verifier Standard (VSTD);
ZIP archive format (ZIP).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "prepare_platform_release_evidence.py"
SPEC = importlib.util.spec_from_file_location("prepare_platform_release_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release_evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_evidence)
report_builder = release_evidence.report_builder

SOURCE_COMMIT = "a" * 40
RUN_ID = "40000000001"
RUN_ATTEMPT = "2"


def _junit_bytes(modules: tuple[str, ...], *, failure: bool = False) -> bytes:
    cases = []
    for index, test_module in enumerate(modules):
        classname = test_module.removesuffix(".py").replace("/", ".")
        child = '<failure message="failed" />' if failure and index == 0 else ""
        cases.append(
            f'<testcase classname="{classname}" name="test_contract_{index}">'
            f"{child}</testcase>"
        )
    return (
        f'<testsuites><testsuite name="platform" tests="{len(cases)}" '
        f'failures="{1 if failure else 0}">'
        + "".join(cases)
        + "</testsuite></testsuites>"
    ).encode("utf-8")


def _evidence_tree(root: Path) -> Path:
    evidence_root = root / "downloaded"
    evidence_root.mkdir()
    manifest = report_builder.load_manifest()
    modules = tuple(
        sorted(
            {
                module
                for component in manifest["components"]
                for module in component["test_modules"]
            }
        )
    )
    for coordinate in manifest["coordinates"]:
        coordinate_id = coordinate["coordinate_id"]
        raw = evidence_root / (
            f"platform-python-contracts-{RUN_ID}-{RUN_ATTEMPT}-{coordinate_id}"
        )
        report_directory = evidence_root / (
            f"platform-component-contract-{RUN_ID}-{RUN_ATTEMPT}-{coordinate_id}"
        )
        raw.mkdir()
        report_directory.mkdir()
        environment = {
            "platform_system": coordinate["operating_system"],
            "platform_machine": coordinate["machine_family"],
            "python_implementation": "CPython",
            "python_version": coordinate["python_version"],
            "runner_os": coordinate["runner_operating_system"],
            "runner_arch": coordinate["runner_architecture"],
            "image_os": f"image-{coordinate_id}",
            "image_version": "20260904.1",
            "executed_git_sha": SOURCE_COMMIT,
            "git_ref": "refs/heads/main",
            "event_name": "push",
            "run_id": RUN_ID,
            "run_attempt": RUN_ATTEMPT,
            "pull_request_head_sha": "",
            "pull_request_base_sha": "",
        }
        environment_path = raw / "platform-environment.json"
        environment_path.write_text(
            json.dumps(environment, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        loaded_environment = report_builder.load_environment(environment_path)
        junit_path = raw / "platform-contracts.xml"
        junit_path.write_bytes(_junit_bytes(modules))
        summary = report_builder.junit_summary(junit_path, modules)
        report = report_builder.build_report(
            manifest,
            coordinate_id=coordinate_id,
            environment=loaded_environment,
            test_summary=summary,
        )
        (report_directory / "platform-component-contract.json").write_bytes(
            report_builder.render_report_bytes(report)
        )
    return evidence_root


def _prepare(evidence_root: Path, output: Path) -> dict:
    return release_evidence.prepare_release_evidence(
        evidence_root=evidence_root,
        output=output,
        release_tag="v1.3.0",
        repository="TimeLordRaps/verifier",
        source_commit=SOURCE_COMMIT,
        run_id=RUN_ID,
        run_attempt=RUN_ATTEMPT,
    )


def test_bundle_is_complete_deterministic_and_exactly_bound(tmp_path: Path) -> None:
    evidence_root = _evidence_tree(tmp_path)
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    manifest = _prepare(evidence_root, first)
    _prepare(evidence_root, second)

    assert first.read_bytes() == second.read_bytes()
    assert manifest["schema_version"] == "VSTD-PLATFORM-RELEASE-EVIDENCE-1"
    assert manifest["verification_effect"] == "NONE"
    assert manifest["source_commit"] == SOURCE_COMMIT
    assert manifest["workflow"]["run_id"] == RUN_ID
    assert manifest["coordinate_ids"] == list(report_builder.COORDINATE_IDS)
    assert len(manifest["members"]) == 12
    with zipfile.ZipFile(first) as bundle:
        names = bundle.namelist()
        assert names[0] == "PLATFORM-EVIDENCE-MANIFEST.json"
        assert len(names) == 13
        assert all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in bundle.infolist())
        assert all(info.compress_type == zipfile.ZIP_STORED for info in bundle.infolist())
        embedded = json.loads(bundle.read(names[0]))
        assert embedded == manifest
        for coordinate in report_builder.COORDINATE_IDS:
            environment_bytes = bundle.read(
                f"coordinates/{coordinate}/environment.json"
            )
            report = json.loads(bundle.read(f"coordinates/{coordinate}/report.json"))
            assert report["environment"]["source_document_sha256"] == (
                release_evidence._sha256(environment_bytes)
            )
    boundary = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_release_boundary.py"), str(first)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert boundary.returncode == 0, boundary.stderr
    assert "scanned 13 text members" in boundary.stdout


@pytest.mark.parametrize("suffix", ("xml", "XML"))
@pytest.mark.parametrize(
    ("payload", "reason"),
    (
        (
            ('<testsuite><testcase><skipped message="' + "C:" + "/Users/"
             + 'synthetic/workspace" /></testcase></testsuite>').encode("utf-8"),
            "local user or home path",
        ),
        (
            ("<testsuite><system-out>" + "ghp_" + "x" * 24
             + "</system-out></testsuite>").encode("utf-8"),
            "GitHub token shape",
        ),
        (
            b'<testsuite><testcase><skipped message="C&#58;&#92;Users&#92;'
            b'synthetic&#92;workspace" /></testcase></testsuite>',
            "local user or home path",
        ),
        (
            ("<testsuite><system-out>ghp&#95;" + "x" * 24
             + "</system-out></testsuite>").encode("utf-8"),
            "GitHub token shape",
        ),
        (b"<testsuite>", "malformed XML member"),
        (b'<!DOCTYPE testsuite [<!ENTITY sample "value">]><testsuite />',
         "XML declarations are not supported"),
        (b"<testsuite>\xff</testsuite>", "non-UTF-8 text member"),
    ),
    ids=("home-path", "secret-shaped", "encoded-path", "encoded-secret",
         "malformed", "declaration", "non-utf8"),
)
def test_release_boundary_rejects_unsafe_raw_test_evidence(
    tmp_path: Path, suffix: str, payload: bytes, reason: str
) -> None:
    artifact = tmp_path / "platform-evidence.zip"
    member = f"coordinates/windows-x64/junit.{suffix}"
    with zipfile.ZipFile(artifact, "w") as bundle:
        bundle.writestr(member, payload)
    original = artifact.read_bytes()

    boundary = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_release_boundary.py"), str(artifact)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert boundary.returncode == 1, boundary.stdout
    assert reason in boundary.stderr
    assert member in boundary.stderr
    assert "ghp_" + "x" * 24 not in boundary.stderr
    assert "C:" + "/Users/" not in boundary.stderr
    assert "C:" + chr(92) + "Users" + chr(92) not in boundary.stderr
    assert artifact.read_bytes() == original


def test_release_boundary_does_not_echo_an_unsafe_member_name(tmp_path: Path) -> None:
    marker = "ghp_" + "x" * 24
    artifact = tmp_path / "platform-evidence.zip"
    with zipfile.ZipFile(artifact, "w") as bundle:
        bundle.writestr(f"coordinates/{marker}/junit.xml", b"<testsuite />")
    boundary = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_release_boundary.py"), str(artifact)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert boundary.returncode == 1
    assert "GitHub token shape in <redacted archive member>" in boundary.stderr
    assert marker not in boundary.stderr


@pytest.mark.parametrize("archive", (True, False), ids=("archive", "standalone"))
def test_release_boundary_accepts_safe_xml_character_references(
    tmp_path: Path, archive: bool
) -> None:
    payload = (
        b'<testsuite><testcase name="check&#95;one"><skipped '
        b'message="safe&#10;diagnostic" /></testcase></testsuite>'
    )
    artifact = tmp_path / ("platform-evidence.zip" if archive else "junit.xml")
    if archive:
        with zipfile.ZipFile(artifact, "w") as bundle:
            bundle.writestr("coordinates/windows-x64/junit.xml", payload)
    else:
        artifact.write_bytes(payload)
    boundary = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_release_boundary.py"), str(artifact)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert boundary.returncode == 0, boundary.stderr
    assert "scanned 1 text members" in boundary.stdout


def test_raw_report_boundary_rejects_an_encoded_secret_before_upload(tmp_path: Path) -> None:
    artifact = tmp_path / "platform-contracts.xml"
    artifact.write_bytes(
        ("<testsuite><system-out>ghp&#95;" + "x" * 24
         + "</system-out></testsuite>").encode("utf-8")
    )
    original = artifact.read_bytes()
    boundary = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_release_boundary.py"), str(artifact)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert boundary.returncode == 1
    assert "GitHub token shape" in boundary.stderr
    assert "ghp_" + "x" * 24 not in boundary.stderr
    assert artifact.read_bytes() == original


@pytest.mark.parametrize(
    "fault",
    (
        "missing_coordinate",
        "extra_artifact",
        "mixed_run",
        "mixed_attempt",
        "pull_request",
        "wrong_ref",
        "wrong_commit",
        "report_tamper",
        "junit_failure",
        "junit_summary_failure",
        "environment_bytes_tamper",
        "environment_extra_field",
        "environment_duplicate_key",
    ),
)
def test_bundle_rejects_incomplete_substituted_or_failed_evidence(
    tmp_path: Path, fault: str
) -> None:
    evidence_root = _evidence_tree(tmp_path)
    coordinate = report_builder.COORDINATE_IDS[0]
    raw = evidence_root / (
        f"platform-python-contracts-{RUN_ID}-{RUN_ATTEMPT}-{coordinate}"
    )
    report_directory = evidence_root / (
        f"platform-component-contract-{RUN_ID}-{RUN_ATTEMPT}-{coordinate}"
    )
    environment_path = raw / "platform-environment.json"
    environment = json.loads(environment_path.read_text(encoding="utf-8"))
    if fault == "missing_coordinate":
        (report_directory / "platform-component-contract.json").unlink()
    elif fault == "extra_artifact":
        (evidence_root / "unrelated-artifact").mkdir()
    elif fault == "mixed_run":
        environment["run_id"] = "40000000002"
    elif fault == "mixed_attempt":
        environment["run_attempt"] = "3"
    elif fault == "pull_request":
        environment.update(
            {
                "event_name": "pull_request",
                "git_ref": "refs/pull/31/merge",
                "pull_request_head_sha": "b" * 40,
                "pull_request_base_sha": "c" * 40,
            }
        )
    elif fault == "wrong_ref":
        environment["git_ref"] = "refs/heads/not-main"
    elif fault == "wrong_commit":
        environment["executed_git_sha"] = "d" * 40
    elif fault == "report_tamper":
        report_path = report_directory / "platform-component-contract.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["verification_effect"] = "PASS"
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    elif fault == "junit_failure":
        manifest = report_builder.load_manifest()
        modules = tuple(
            sorted(
                {
                    module
                    for component in manifest["components"]
                    for module in component["test_modules"]
                }
            )
        )
        (raw / "platform-contracts.xml").write_bytes(
            _junit_bytes(modules, failure=True)
        )
    elif fault == "junit_summary_failure":
        junit_path = raw / "platform-contracts.xml"
        junit_path.write_bytes(
            junit_path.read_bytes().replace(b'failures="0"', b'failures="1"')
        )
    elif fault == "environment_bytes_tamper":
        environment_path.write_text(
            json.dumps(environment, separators=(",", ":")),
            encoding="utf-8",
        )
    elif fault == "environment_extra_field":
        environment["unbound_extra_field"] = "not permitted"
        environment_path.write_text(json.dumps(environment), encoding="utf-8")
    elif fault == "environment_duplicate_key":
        environment_path.write_text(
            json.dumps(environment)[:-1] + f', "run_id": "{RUN_ID}"}}',
            encoding="utf-8",
        )
    if fault in {
        "mixed_run",
        "mixed_attempt",
        "pull_request",
        "wrong_ref",
        "wrong_commit",
    }:
        environment_path.write_text(
            json.dumps(environment, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    with pytest.raises(
        (
            release_evidence.PlatformReleaseEvidenceError,
            report_builder.PlatformComponentReportError,
        )
    ):
        _prepare(evidence_root, tmp_path / "invalid.zip")


@pytest.mark.parametrize("artifact_kind", ("environment", "junit"))
def test_bundle_validates_and_archives_one_captured_byte_document(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_kind: str,
) -> None:
    evidence_root = _evidence_tree(tmp_path)
    coordinate = report_builder.COORDINATE_IDS[0]
    raw = evidence_root / (
        f"platform-python-contracts-{RUN_ID}-{RUN_ATTEMPT}-{coordinate}"
    )
    if artifact_kind == "environment":
        target = raw / "platform-environment.json"
        member = f"coordinates/{coordinate}/environment.json"
        original = target.read_bytes()
        altered = json.dumps(json.loads(original), separators=(",", ":")).encode()
    else:
        target = raw / "platform-contracts.xml"
        member = f"coordinates/{coordinate}/junit.xml"
        original = target.read_bytes()
        altered = original + b"<!-- semantically equivalent second read -->"

    real_read_bytes = Path.read_bytes
    target_reads = 0

    def switched_read_bytes(path: Path) -> bytes:
        nonlocal target_reads
        if path == target:
            target_reads += 1
            return original if target_reads == 1 else altered
        return real_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", switched_read_bytes)
    output = tmp_path / f"single-capture-{artifact_kind}.zip"
    _prepare(evidence_root, output)

    assert target_reads == 1
    with zipfile.ZipFile(output) as bundle:
        assert bundle.read(member) == original


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("release_tag", "1.3.0"),
        ("repository", "not-a-repository"),
        ("source_commit", "ABC"),
        ("run_id", "0"),
        ("run_attempt", "not-a-number"),
    ),
)
def test_bundle_rejects_malformed_release_coordinates(
    tmp_path: Path, field: str, value: str
) -> None:
    evidence_root = _evidence_tree(tmp_path)
    arguments = {
        "evidence_root": evidence_root,
        "output": tmp_path / "invalid.zip",
        "release_tag": "v1.3.0",
        "repository": "TimeLordRaps/verifier",
        "source_commit": SOURCE_COMMIT,
        "run_id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
    }
    arguments[field] = value

    with pytest.raises(release_evidence.PlatformReleaseEvidenceError):
        release_evidence.prepare_release_evidence(**arguments)
