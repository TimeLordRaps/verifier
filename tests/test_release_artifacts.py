"""Terminology: Verifier Standard (VSTD); ZIP archive format (ZIP).

The public source archive must bind exact, publicly resolvable Git bytes."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path
import zipfile

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "release_artifacts.py"
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"
TIME_GATE = REPO_ROOT / "scripts" / "check_time_status.py"
RELEASE_METADATA_GATE = REPO_ROOT / "scripts" / "check_release_metadata.py"

SPEC = importlib.util.spec_from_file_location("vstd_release_artifacts", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release_artifacts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_artifacts)

METADATA_SPEC = importlib.util.spec_from_file_location(
    "vstd_release_metadata", RELEASE_METADATA_GATE
)
assert METADATA_SPEC is not None and METADATA_SPEC.loader is not None
release_metadata = importlib.util.module_from_spec(METADATA_SPEC)
METADATA_SPEC.loader.exec_module(release_metadata)


def test_source_release_manifest_binds_head_and_exact_archive_bytes(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(REPO_ROOT),
            "source",
            "--ref",
            "HEAD",
            "--release",
            "test",
            "--output-dir",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    manifest_path = tmp_path / "verifier-standard-test.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
    ).strip()
    assert manifest["source"]["commit"] == expected_commit
    assert manifest["source"]["ref"] == "HEAD"
    assert "RELEASE-MANIFEST.json" not in manifest["files"]
    assert manifest["source"]["repository"] == "https://github.com/TimeLordRaps/verifier"
    assert manifest["source"]["byte_semantics"] == (
        "exact Git blob member bytes in a platform-independent canonical ZIP"
    )
    assert manifest["distribution"] == {
        "name": "verifier-standard",
        "import_package": "verifier",
        "console_scripts": {
            "verifiable": "verifier.runtime.public_cli:main",
            "verifier": "verifier.runtime.public_cli:main",
            "vstd": "verifier.runtime.public_cli:main",
        },
    }

    verify = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--repo",
            str(REPO_ROOT),
            "verify",
            str(manifest_path),
        ],
        capture_output=True,
        text=True,
    )
    assert verify.returncode == 0, verify.stderr

    epoch = subprocess.check_output(
        ["git", "show", "-s", "--format=%ct", expected_commit],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    timestamp = datetime.fromtimestamp(int(epoch), timezone.utc)
    expected_zip_time = (
        timestamp.year,
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second - (timestamp.second % 2),
    )
    with zipfile.ZipFile(tmp_path / "verifier-standard-test.zip") as bundle:
        assert bundle.infolist()
        for info in bundle.infolist():
            assert info.date_time == expected_zip_time
            assert info.create_system == 3
            assert info.compress_type == zipfile.ZIP_STORED


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (
            "https://github.com/TimeLordRaps/verifier.git",
            "https://github.com/TimeLordRaps/verifier",
        ),
        (
            "https://github.com/TimeLordRaps/verifier/",
            "https://github.com/TimeLordRaps/verifier",
        ),
        (
            "git" + "@github.com:TimeLordRaps/verifier.git",
            "https://github.com/TimeLordRaps/verifier",
        ),
        (
            "ssh://git" + "@github.com/TimeLordRaps/verifier.git",
            "https://github.com/TimeLordRaps/verifier",
        ),
    ],
)
def test_repository_url_spellings_are_canonical(raw: str, expected: str) -> None:
    assert release_artifacts._canonical_repository_url(raw) == expected


def _write_raw_wheel(path: Path, *, newline: bytes, reverse: bool) -> None:
    dist_info = "verifier_standard-1.2.0.dist-info"
    members = [
        ("verifier/__init__.py", b'__version__ = "1.2.0"\n'),
        (
            f"{dist_info}/METADATA",
            newline.join(
                [
                    b"Metadata-Version: 2.4",
                    b"Name: verifier-standard",
                    b"Version: 1.2.0",
                    b"",
                    b"Canonical metadata.",
                    b"",
                ]
            ),
        ),
        (
            f"{dist_info}/WHEEL",
            newline.join(
                [
                    b"Wheel-Version: 1.0",
                    b"Generator: test",
                    b"Root-Is-Purelib: true",
                    b"Tag: py3-none-any",
                    b"",
                ]
            ),
        ),
        (
            f"{dist_info}/entry_points.txt",
            newline.join(
                [
                    b"[console_scripts]",
                    b"verifiable = verifier.runtime.public_cli:main",
                    b"verifier = verifier.runtime.public_cli:main",
                    b"vstd = verifier.runtime.public_cli:main",
                    b"",
                ]
            ),
        ),
        (f"{dist_info}/RECORD", b"host-generated-record"),
    ]
    if reverse:
        members.reverse()
    with zipfile.ZipFile(path, "w") as bundle:
        for name, data in members:
            info = zipfile.ZipInfo(name, (2024, 1, 2, 3, 4, 4))
            info.create_system = 0 if reverse else 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0 if reverse else (0o100755 << 16)
            bundle.writestr(info, data)


def test_wheel_normalization_removes_host_newlines_and_zip_metadata(tmp_path: Path) -> None:
    first_raw = tmp_path / "first.whl"
    second_raw = tmp_path / "second.whl"
    first = tmp_path / "first-normalized.whl"
    second = tmp_path / "second-normalized.whl"
    _write_raw_wheel(first_raw, newline=b"\r\n", reverse=False)
    _write_raw_wheel(second_raw, newline=b"\n", reverse=True)

    epoch = "1787446816"
    release_artifacts._normalize_wheel(first_raw, first, epoch)
    release_artifacts._normalize_wheel(second_raw, second, epoch)
    assert first.read_bytes() == second.read_bytes()

    with zipfile.ZipFile(first) as bundle:
        infos = bundle.infolist()
        assert all(info.create_system == 3 for info in infos)
        assert all(info.compress_type == zipfile.ZIP_STORED for info in infos)
        metadata_name = "verifier_standard-1.2.0.dist-info/METADATA"
        assert b"\r" not in bundle.read(metadata_name)
        record_name = "verifier_standard-1.2.0.dist-info/RECORD"
        rows = list(csv.reader(io.StringIO(bundle.read(record_name).decode("utf-8"))))
        records = {row[0]: row[1:] for row in rows}
        for info in infos:
            if info.is_dir() or info.filename == record_name:
                continue
            data = bundle.read(info)
            assert records[info.filename] == [
                release_artifacts._record_digest(data),
                str(len(data)),
            ]
        assert records[record_name] == ["", ""]


def _write_raw_sdist(path: Path, *, newline: bytes, reverse: bool) -> None:
    root = "verifier_standard-1.2.0"
    members = [
        (
            f"{root}/PKG-INFO",
            newline.join(
                [
                    b"Metadata-Version: 2.4",
                    b"Name: verifier-standard",
                    b"Version: 1.2.0",
                    b"",
                ]
            ),
        ),
        (f"{root}/setup.cfg", newline.join([b"[egg_info]", b"tag_build =", b""])),
        (
            f"{root}/src/verifier_standard.egg-info/PKG-INFO",
            newline.join(
                [
                    b"Metadata-Version: 2.4",
                    b"Name: verifier-standard",
                    b"Version: 1.2.0",
                    b"",
                ]
            ),
        ),
        (f"{root}/README.md", b"Source bytes stay unchanged.\n"),
    ]
    if reverse:
        members.reverse()
    with tarfile.open(path, "w:gz") as bundle:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.mtime = 1 if reverse else 2
            info.uid = 1000
            info.gid = 1000
            info.mode = 0o600 if reverse else 0o664
            info.size = len(data)
            bundle.addfile(info, io.BytesIO(data))


def test_sdist_normalization_removes_host_newlines_and_tar_metadata(tmp_path: Path) -> None:
    first_raw = tmp_path / "first.tar.gz"
    second_raw = tmp_path / "second.tar.gz"
    first = tmp_path / "first-normalized.tar.gz"
    second = tmp_path / "second-normalized.tar.gz"
    _write_raw_sdist(first_raw, newline=b"\r\n", reverse=False)
    _write_raw_sdist(second_raw, newline=b"\n", reverse=True)

    epoch = "1787446816"
    release_artifacts._normalize_sdist(first_raw, first, epoch)
    release_artifacts._normalize_sdist(second_raw, second, epoch)
    assert first.read_bytes() == second.read_bytes()

    with tarfile.open(first, "r:gz") as bundle:
        files = {member.name: member for member in bundle.getmembers()}
        root = "verifier_standard-1.2.0"
        metadata = bundle.extractfile(files[f"{root}/PKG-INFO"])
        assert metadata is not None and b"\r" not in metadata.read()
        readme = bundle.extractfile(files[f"{root}/README.md"])
        assert readme is not None and readme.read() == b"Source bytes stay unchanged.\n"
        assert all(member.mtime == int(epoch) for member in files.values())
        assert all(member.uid == 0 and member.gid == 0 for member in files.values())


def test_artifact_directory_comparison_fails_closed(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "artifact.bin").write_bytes(b"same")
    (second / "artifact.bin").write_bytes(b"same")
    assert release_artifacts.compare_artifact_directories(first, second) == 1

    (second / "artifact.bin").write_bytes(b"different")
    with pytest.raises(release_artifacts.ReleaseError, match="artifact bytes differ"):
        release_artifacts.compare_artifact_directories(first, second)


def test_cyclonedx_sbom_is_deterministic_bound_and_non_self_referential(
    tmp_path: Path,
) -> None:
    artifacts = {
        "verifier-standard-1.2.0.zip": {
            "byte_size": 3,
            "sha256": release_artifacts._sha256(b"zip"),
        },
        "verifier_standard-1.2.0-py3-none-any.whl": {
            "byte_size": 5,
            "sha256": release_artifacts._sha256(b"wheel"),
        },
    }
    arguments = {
        "commit": "a" * 40,
        "epoch": "1787446816",
        "release": "1.2.0",
        "artifacts": artifacts,
    }
    first = tmp_path / "first.cdx.json"
    second = tmp_path / "second.cdx.json"
    release_artifacts._write_cyclonedx_sbom(first, **arguments)
    release_artifacts._write_cyclonedx_sbom(second, **arguments)

    assert first.read_bytes() == second.read_bytes()
    payload = json.loads(first.read_text(encoding="utf-8"))
    assert payload["bomFormat"] == "CycloneDX"
    assert payload["specVersion"] == "1.6"
    assert {component["name"] for component in payload["components"]} == set(artifacts)
    assert first.name not in {component["name"] for component in payload["components"]}
    release_artifacts._verify_cyclonedx_sbom(first, **arguments)

    payload["components"][0]["hashes"][0]["content"] = "0" * 64
    first.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(release_artifacts.ReleaseError, match="bound release subjects"):
        release_artifacts._verify_cyclonedx_sbom(first, **arguments)


def test_release_notes_use_the_github_tag_object_verification() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert 'git/tags/$TAG_OBJECT' in workflow
    assert ".verification.verified" in workflow
    assert ".verification.reason" in workflow
    assert "SIGNED_AND_GITHUB_VERIFIED" in workflow
    assert 'git verify-tag "$GITHUB_REF_NAME"' not in workflow


def test_release_is_drafted_with_attested_sbom_before_publication() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    create = workflow.index('gh release create "$GITHUB_REF_NAME"')
    publish = workflow.index('gh release edit "$GITHUB_REF_NAME"')

    assert "dist/*.cdx.json" in workflow
    assert "--draft" in workflow[create:publish]
    assert "--draft=false" in workflow[publish:]
    assert create < publish


@pytest.mark.parametrize(
    "status", ["OPEN", "CONFLICTED", "", "CLEAR\nStatus: CLEAR", "CLEAR\nStatus: open"]
)
def test_release_time_gate_rejects_every_non_exact_clear_state(
    tmp_path: Path, status: str
) -> None:
    time_file = tmp_path / "TIME.md"
    time_file.write_text(f"# TIME\n\nStatus: {status}\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(TIME_GATE), str(time_file)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert "[TIME BLOCKED]" in result.stderr


def test_tag_release_requires_clear_time_from_the_exact_checkout(tmp_path: Path) -> None:
    time_file = tmp_path / "TIME.md"
    time_file.write_text("# TIME\n\nStatus: CLEAR\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(TIME_GATE), str(time_file)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "[TIME CLEAR]" in result.stdout

    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert "Require TIME CLEAR in the exact tagged checkout" in workflow
    assert "python scripts/check_time_status.py" in workflow
    assert workflow.index("python scripts/check_time_status.py") < workflow.index(
        "python -m pytest -q"
    )


def _write_final_release_metadata(root: Path) -> None:
    (root / "pyproject.toml").write_text(
        '[project]\nname = "verifier-standard"\nversion = "1.2.0"\n',
        encoding="utf-8",
    )
    (root / "CHANGELOG.md").write_text(
        "# Changelog\n\n## 1.2.0 - 2026-08-26\n", encoding="utf-8"
    )
    (root / "CITATION.cff").write_text(
        'cff-version: 1.2.0\nmessage: "Cite this published release."\n'
        "version: 1.2.0\ndate-released: 2026-08-26\n",
        encoding="utf-8",
    )
    (root / ".zenodo.json").write_text(
        json.dumps(
            {
                "version": "1.2.0",
                "publication_date": "2026-08-26",
                "description": "Final publication metadata.",
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "fault",
    (
        "unreleased_changelog",
        "missing_citation_date",
        "mismatched_citation_date",
        "candidate_citation",
        "candidate_zenodo",
        "mismatched_zenodo_date",
        "package_version",
    ),
)
def test_release_metadata_gate_rejects_unfinalized_or_inconsistent_state(
    tmp_path: Path, fault: str
) -> None:
    _write_final_release_metadata(tmp_path)
    if fault == "unreleased_changelog":
        path = tmp_path / "CHANGELOG.md"
        path.write_text(path.read_text().replace("2026-08-26", "UNRELEASED"))
    elif fault == "missing_citation_date":
        path = tmp_path / "CITATION.cff"
        path.write_text(path.read_text().replace("date-released: 2026-08-26\n", ""))
    elif fault == "mismatched_citation_date":
        path = tmp_path / "CITATION.cff"
        path.write_text(path.read_text().replace("2026-08-26", "2026-08-25"))
    elif fault == "candidate_citation":
        path = tmp_path / "CITATION.cff"
        path.write_text(path.read_text().replace("published release", "release candidate"))
    elif fault == "candidate_zenodo":
        path = tmp_path / ".zenodo.json"
        path.write_text(
            json.dumps(
                {
                    "version": "1.2.0",
                    "publication_date": "2026-08-26",
                    "description": "Release-candidate metadata.",
                }
            )
        )
    elif fault == "mismatched_zenodo_date":
        path = tmp_path / ".zenodo.json"
        path.write_text(path.read_text().replace("2026-08-26", "2026-08-25"))
    else:
        path = tmp_path / "pyproject.toml"
        path.write_text(path.read_text().replace("1.2.0", "1.1.3"))

    with pytest.raises(ValueError):
        release_metadata.require_finalized(tmp_path, "1.2.0")


def test_release_metadata_gate_accepts_one_final_consistent_coordinate(tmp_path: Path) -> None:
    _write_final_release_metadata(tmp_path)
    release_metadata.require_finalized(tmp_path, "1.2.0")


def test_tag_release_contract_binds_main_version_gate_and_final_metadata() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    required = (
        'git merge-base --is-ancestor "$GITHUB_SHA" origin/main',
        'git rev-parse "${GITHUB_REF}^{commit}"',
        'test "$VERSION" = "$PACKAGE_VERSION"',
        'commits/$GITHUB_SHA/check-runs',
        'select(.name == "conformance-gate" and .conclusion == "success")',
        'repos/$GITHUB_REPOSITORY/immutable-releases',
        "--jq '.enabled')\" = true",
        'python scripts/check_release_metadata.py --version "${GITHUB_REF_NAME#v}"',
    )
    for fragment in required:
        assert fragment in workflow
    assert workflow.index('repos/$GITHUB_REPOSITORY/immutable-releases') < workflow.index(
        'gh release create "$GITHUB_REF_NAME"'
    )
