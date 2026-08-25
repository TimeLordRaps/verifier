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

SPEC = importlib.util.spec_from_file_location("vstd_release_artifacts", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release_artifacts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_artifacts)


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


def test_release_notes_use_the_github_tag_object_verification() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert 'git/tags/$TAG_OBJECT' in workflow
    assert ".verification.verified" in workflow
    assert ".verification.reason" in workflow
    assert "SIGNED_AND_GITHUB_VERIFIED" in workflow
    assert 'git verify-tag "$GITHUB_REF_NAME"' not in workflow
